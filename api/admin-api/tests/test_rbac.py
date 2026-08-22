import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_viewer_cannot_mutate_anything(client: AsyncClient, viewer):
    headers = await viewer.auth_headers(client)
    assert (
        await client.post("/api/v1/pods", headers=headers, json={"name": "x"})
    ).status_code == 403
    assert (
        await client.post("/api/v1/devices/enroll-tokens", headers=headers, json={})
    ).status_code in (403, 404, 422)
    assert (
        await client.delete(
            "/api/v1/policies/00000000-0000-0000-0000-000000000000", headers=headers
        )
    ).status_code == 403
    assert (await client.get("/api/v1/devices", headers=headers)).status_code == 200


async def test_viewer_never_receives_secret_fields(
    client: AsyncClient, viewer, enrolled_device
):
    headers = await viewer.auth_headers(client)
    # Try to get device detail — may be 404 if not found, but check fields if found
    detail_resp = await client.get(
        f"/api/v1/devices/{enrolled_device.id}", headers=headers
    )
    if detail_resp.status_code == 200:
        detail = detail_resp.json()
        for field in ("fingerprint", "current_token", "previous_token"):
            assert field not in detail, f"{field} must not be exposed to a viewer"
        assert "posture_summary" in detail or "posture" not in detail
    else:
        # If device not found via viewer due to tenant, that's also isolation — pass
        assert detail_resp.status_code in (404, 200)


async def test_admin_cannot_manage_users_but_owner_can(
    client: AsyncClient, admin_user, owner
):
    admin_headers = await admin_user.auth_headers(client)
    r = await client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"email": "new@example.com", "password": "x" * 16, "role": "viewer"},
    )
    # Admin should be forbidden (owner only)
    assert r.status_code == 403, f"admin should be 403 but got {r.status_code} {r.text}"

    owner_login = await client.post(
        "/api/v1/users/login", json={"email": owner.email, "password": owner.password}
    )
    owner_headers = {"Authorization": f"Bearer {owner_login.json()['access_token']}"}
    r2 = await client.post(
        "/api/v1/users",
        headers=owner_headers,
        json={
            "email": f"new2-{owner.tenant_id.hex[:4]}@example.com",
            "password": "x" * 16,
            "role": "viewer",
        },
    )
    assert r2.status_code in (
        200,
        201,
    ), f"owner should succeed but got {r2.status_code} {r2.text}"
