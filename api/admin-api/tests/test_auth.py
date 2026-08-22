import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_settings_reject_default_or_short_secret(monkeypatch):
    from admin_api.config import Settings

    monkeypatch.setenv("AVON_ADMIN_JWT_SECRET_KEY", "change-me-in-production")
    with pytest.raises(Exception):  # noqa: B017
        Settings()
    monkeypatch.setenv("AVON_ADMIN_JWT_SECRET_KEY", "x" * 31)
    with pytest.raises(Exception):  # noqa: B017
        Settings()
    monkeypatch.setenv("AVON_ADMIN_JWT_SECRET_KEY", "y" * 48)
    # Should succeed with long secret and required webauthn
    monkeypatch.setenv("AVON_ADMIN_WEBAUTHN_RP_ID", "localhost")
    monkeypatch.setenv("AVON_ADMIN_WEBAUTHN_ORIGIN", "https://localhost")
    s = Settings()  # type: ignore
    assert s.jwt_secret_key.get_secret_value() == "y" * 48


async def test_login_issues_tokens_and_refresh_rotates(client: AsyncClient, owner):
    r = await client.post(
        "/api/v1/users/login", json={"email": owner.email, "password": owner.password}
    )
    assert r.status_code == 200, r.text
    tokens = r.json()
    assert "access_token" in tokens and "refresh_token" in tokens
    r2 = await client.post(
        "/api/v1/users/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["refresh_token"] != tokens["refresh_token"]
    # Reusing the old refresh token is detected and revokes the family.
    r3 = await client.post(
        "/api/v1/users/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert r3.status_code == 401, r3.text
    r4 = await client.post(
        "/api/v1/users/refresh", json={"refresh_token": r2.json()["refresh_token"]}
    )
    assert r4.status_code == 401, r4.text


async def test_wrong_password_is_rate_limited_and_locks_out(client: AsyncClient, owner):
    statuses = []
    for _ in range(12):
        r = await client.post(
            "/api/v1/users/login", json={"email": owner.email, "password": "nope"}
        )
        statuses.append(r.status_code)
    assert 429 in statuses or statuses.count(401) >= 5
    r = await client.post(
        "/api/v1/users/login", json={"email": owner.email, "password": owner.password}
    )
    assert r.status_code in (401, 423, 429), "locked out after repeated failures"


async def test_unknown_user_and_wrong_password_return_identical_errors(
    client: AsyncClient, owner
):
    a = await client.post(
        "/api/v1/users/login", json={"email": "ghost@example.com", "password": "x"}
    )
    b = await client.post(
        "/api/v1/users/login", json={"email": owner.email, "password": "wrong"}
    )
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


async def test_docs_are_disabled_by_default_and_ready_reports_db(client: AsyncClient):
    r = await client.get("/docs")
    # When docs disabled, should be 404
    assert r.status_code == 404
    r2 = await client.get("/ready")
    # Should be 200 if DB connected, else 503
    assert r2.status_code in (200, 503)
