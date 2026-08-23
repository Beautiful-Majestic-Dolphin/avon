import hashlib

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_enroll_token_is_returned_once_and_stored_hashed(
    client: AsyncClient, admin_user, db
):
    headers = await admin_user.auth_headers(client)
    r = await client.post(
        "/api/v1/devices/enroll-tokens",
        headers=headers,
        json={
            "device_name": "laptop-1",
            "max_uses": 1,
            "expires_in_hours": 24,
            "require_approval": True,
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    token = body["token"]
    assert len(token) >= 32

    rows = await db.fetch(
        "SELECT token_hash, device_name, require_approval FROM enrollment_tokens"
    )
    assert len(rows) == 1
    assert bytes(rows[0]["token_hash"]) == hashlib.sha256(token.encode()).digest()
    assert rows[0]["require_approval"] is True

    # The plaintext is never persisted anywhere, including the audit trail.
    audit = await db.fetch("SELECT details::text FROM activity_logs")
    assert all(token not in (row["details"] or "") for row in audit)

    # And it is not retrievable a second time.
    listed = await client.get("/api/v1/devices/enroll-tokens", headers=headers)
    assert listed.status_code == 200
    assert all("token" not in item for item in listed.json()["items"])


async def test_pending_device_can_be_approved_and_the_call_reaches_control(
    client: AsyncClient, admin_user, pending_device, fake_control
):
    headers = await admin_user.auth_headers(client)
    listed = await client.get("/api/v1/devices?status=pending", headers=headers)
    assert listed.status_code == 200
    assert [d["id"] for d in listed.json()["items"]] == [str(pending_device.id)]

    r = await client.post(
        f"/api/v1/devices/{pending_device.id}/approve", headers=headers
    )
    assert r.status_code == 200
    assert fake_control.approved == [pending_device.id]
    assert await pending_device.status() == "active"


async def test_revoking_a_device_calls_control_and_records_the_reason(
    client: AsyncClient, admin_user, enrolled_device, fake_control, db
):
    headers = await admin_user.auth_headers(client)
    r = await client.post(
        f"/api/v1/devices/{enrolled_device.id}/revoke",
        headers=headers,
        json={"reason": "lost laptop"},
    )
    assert r.status_code == 200
    assert fake_control.revoked == [(enrolled_device.id, "lost laptop")]
    row = await db.fetchrow(
        "SELECT event_type, details FROM activity_logs ORDER BY id DESC LIMIT 1"
    )
    assert row["event_type"] == "device.revoke"
    assert "lost laptop" in str(row["details"])


async def test_a_control_outage_surfaces_as_503_and_does_not_half_apply(
    client: AsyncClient, admin_user, enrolled_device, fake_control
):
    fake_control.fail_next = True
    headers = await admin_user.auth_headers(client)
    r = await client.post(
        f"/api/v1/devices/{enrolled_device.id}/revoke",
        headers=headers,
        json={"reason": "x"},
    )
    assert r.status_code == 503
    assert (
        await enrolled_device.status() == "active"
    ), "the local row must not change if control refused"
