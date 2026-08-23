import pytest
from httpx import AsyncClient

from admin_api.audit import verify_chain

pytestmark = pytest.mark.asyncio


async def test_audit_rows_are_hash_chained_and_carry_actor_ip_and_request_id(
    client: AsyncClient, admin_user, db
):
    headers = await admin_user.auth_headers(client)
    for name in ("a", "b", "c"):
        r = await client.post(
            "/api/v1/pods",
            headers=headers,
            json={"name": name},
        )
        assert r.status_code in (200, 201), r.text

    rows = await db.fetch(
        "SELECT actor_id, ip_address, request_id, prev_hash, hash FROM activity_logs ORDER BY id"
    )
    assert len(rows) >= 3
    assert all(row["actor_id"] is not None for row in rows)
    assert all(row["ip_address"] is not None for row in rows)
    assert all(row["request_id"] for row in rows)
    for previous, current in zip(rows, rows[1:], strict=False):  # noqa: RUF007
        assert bytes(current["prev_hash"]) == bytes(previous["hash"])

    intact, checked = await verify_chain(db, admin_user.tenant_id)
    assert intact and checked >= 3


async def test_tampering_with_a_row_breaks_the_chain(
    client: AsyncClient, admin_user, db
):
    headers = await admin_user.auth_headers(client)
    await client.post("/api/v1/pods", headers=headers, json={"name": "x"})
    await client.post("/api/v1/pods", headers=headers, json={"name": "y"})
    await db.execute(
        "UPDATE activity_logs SET details = '{\"tampered\": true}' WHERE id = (SELECT min(id) FROM activity_logs)"
    )
    intact, _ = await verify_chain(db, admin_user.tenant_id)
    assert intact is False
