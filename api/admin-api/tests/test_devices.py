"""Device detail endpoint."""

import json

from httpx import AsyncClient


async def test_device_detail_reports_the_enrolled_key_provider_not_the_pulsed_one(
    client: AsyncClient, admin_user, enrolled_device, db_pool
):
    """`devices.key_provider` is written at enrollment from the hardware binding
    the control plane verified. The copy inside `posture` is whatever the agent
    chose to send on its last pulse, so it must not be the one operators see."""
    async with db_pool.acquire() as db:
        await db.execute(
            "UPDATE devices SET key_provider = 'software', posture = $2::jsonb "
            "WHERE id = $1",
            enrolled_device.id,
            json.dumps({"key_provider": "tpm2"}),
        )
    headers = await admin_user.auth_headers(client)
    r = await client.get(f"/api/v1/devices/{enrolled_device.id}", headers=headers)
    assert r.status_code == 200
    assert r.json()["key_provider"] == "software"
