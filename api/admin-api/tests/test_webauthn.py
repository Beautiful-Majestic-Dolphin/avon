"""WebAuthn ceremonies, with the regression that matters: an assertion from one user's authenticator must never complete another user's MFA."""

import base64
import time

import pytest
from httpx import AsyncClient

try:
    from soft_webauthn import SoftWebauthnDevice

    HAS_SOFT = True
except ImportError:
    HAS_SOFT = False
    SoftWebauthnDevice = None  # type: ignore

pytestmark = pytest.mark.asyncio

ORIGIN = "https://localhost"
RP_ID = "localhost"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


async def register_key(client: AsyncClient, token: str):
    device = SoftWebauthnDevice()
    begin = await client.post(
        "/api/v1/webauthn/register/begin", headers={"Authorization": f"Bearer {token}"}
    )
    assert begin.status_code == 200, begin.text
    options = begin.json()
    assert options["authenticatorSelection"]["userVerification"] == "preferred"
    attestation = device.create({"publicKey": options}, ORIGIN)
    complete = await client.post(
        "/api/v1/webauthn/register/complete",
        headers={"Authorization": f"Bearer {token}"},
        json={"credential": attestation, "name": "test key"},
    )
    assert complete.status_code == 200, complete.text
    return device


async def test_registration_then_login_requires_the_second_factor(
    client: AsyncClient, owner
):
    if not HAS_SOFT:
        pytest.skip("soft_webauthn not installed")
    login = await client.post(
        "/api/v1/users/login", json={"email": owner.email, "password": owner.password}
    )
    token = login.json()["access_token"]
    device = await register_key(client, token)

    # With a credential registered, a password alone yields only an MFA token.
    again = await client.post(
        "/api/v1/users/login", json={"email": owner.email, "password": owner.password}
    )
    body = again.json()
    assert "access_token" not in body and "mfa_token" in body

    begin = await client.post(
        "/api/v1/webauthn/authenticate/begin", json={"mfa_token": body["mfa_token"]}
    )
    assert begin.status_code == 200
    assertion = device.get({"publicKey": begin.json()}, ORIGIN)
    done = await client.post(
        "/api/v1/webauthn/authenticate/complete",
        json={"mfa_token": body["mfa_token"], "credential": assertion},
    )
    assert done.status_code == 200
    assert "access_token" in done.json()


async def test_another_users_authenticator_cannot_complete_this_users_mfa(
    client: AsyncClient, owner, second_user
):
    """Regression for the credential/user mismatch."""
    if not HAS_SOFT:
        pytest.skip("soft_webauthn not installed")
    owner_login = await client.post(
        "/api/v1/users/login", json={"email": owner.email, "password": owner.password}
    )
    owner_device = await register_key(client, owner_login.json()["access_token"])

    victim_login = await client.post(
        "/api/v1/users/login",
        json={"email": second_user.email, "password": second_user.password},
    )
    victim_device = await register_key(client, victim_login.json()["access_token"])

    step_one = await client.post(
        "/api/v1/users/login",
        json={"email": second_user.email, "password": second_user.password},
    )
    mfa_token = step_one.json()["mfa_token"]
    begin = await client.post(
        "/api/v1/webauthn/authenticate/begin", json={"mfa_token": mfa_token}
    )
    options = begin.json()
    allowed = {c["id"] for c in options.get("allowCredentials", [])}
    assert (
        b64(owner_device.credential_id) not in allowed
    ), "the owner's credential must not be offered for the victim"

    assertion = owner_device.get({"publicKey": options}, ORIGIN)
    hijack = await client.post(
        "/api/v1/webauthn/authenticate/complete",
        json={"mfa_token": mfa_token, "credential": assertion},
    )
    assert hijack.status_code == 401, hijack.text
    assert "access_token" not in hijack.json()

    assertion = victim_device.get({"publicKey": options}, ORIGIN)
    ok = await client.post(
        "/api/v1/webauthn/authenticate/complete",
        json={"mfa_token": mfa_token, "credential": assertion},
    )
    assert ok.status_code == 200


async def test_a_challenge_cannot_be_replayed(client: AsyncClient, owner):
    if not HAS_SOFT:
        pytest.skip("soft_webauthn not installed")
    login = await client.post(
        "/api/v1/users/login", json={"email": owner.email, "password": owner.password}
    )
    device = await register_key(client, login.json()["access_token"])
    step_one = await client.post(
        "/api/v1/users/login", json={"email": owner.email, "password": owner.password}
    )
    mfa_token = step_one.json()["mfa_token"]
    options = (
        await client.post(
            "/api/v1/webauthn/authenticate/begin", json={"mfa_token": mfa_token}
        )
    ).json()
    assertion = device.get({"publicKey": options}, ORIGIN)

    first = await client.post(
        "/api/v1/webauthn/authenticate/complete",
        json={"mfa_token": mfa_token, "credential": assertion},
    )
    assert first.status_code == 200
    replay = await client.post(
        "/api/v1/webauthn/authenticate/complete",
        json={"mfa_token": mfa_token, "credential": assertion},
    )
    assert replay.status_code == 401, "a challenge must be usable exactly once"


async def test_mfa_required_user_cannot_log_in_with_a_password_alone(
    client: AsyncClient, owner, db
):
    await db.execute(
        "UPDATE users SET mfa_required = true WHERE email = $1", owner.email
    )
    r = await client.post(
        "/api/v1/users/login", json={"email": owner.email, "password": owner.password}
    )
    body = r.json()
    assert "access_token" not in body
    assert body.get("detail") == "mfa_enrollment_required" or "mfa_token" in body


async def test_removing_the_last_key_of_an_mfa_required_user_is_refused(
    client: AsyncClient, owner, db
):
    if not HAS_SOFT:
        pytest.skip("soft_webauthn not installed")
    login = await client.post(
        "/api/v1/users/login", json={"email": owner.email, "password": owner.password}
    )
    token = login.json()["access_token"]
    await register_key(client, token)
    await db.execute(
        "UPDATE users SET mfa_required = true WHERE email = $1", owner.email
    )

    listed = await client.get(
        "/api/v1/webauthn/credentials", headers={"Authorization": f"Bearer {token}"}
    )
    cred_id = listed.json()[0]["id"]
    delete = await client.delete(
        f"/api/v1/webauthn/credentials/{cred_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert delete.status_code == 409, delete.text


async def test_key_management_requires_a_fresh_login(
    client: AsyncClient, owner, freeze_time=None
):
    if not HAS_SOFT:
        pytest.skip("soft_webauthn not installed")
    login = await client.post(
        "/api/v1/users/login", json={"email": owner.email, "password": owner.password}
    )
    token = login.json()["access_token"]
    # Simulate time passing
    if freeze_time:
        freeze_time(offset_seconds=600)
    else:
        # Monkeypatch time.time to simulate 10 min later
        original = time.time
        time.time = lambda: original() + 600  # type: ignore
        try:
            begin = await client.post(
                "/api/v1/webauthn/register/begin",
                headers={"Authorization": f"Bearer {token}"},
            )
        finally:
            time.time = original  # type: ignore
        assert begin.status_code == 403
        assert "reauth" in begin.text.lower()
        return
    begin = await client.post(
        "/api/v1/webauthn/register/begin", headers={"Authorization": f"Bearer {token}"}
    )
    assert begin.status_code == 403
    assert "reauth" in begin.text.lower()
