import pytest
from httpx import AsyncClient

from admin_api.analytics.detector import FLOORS, detect, open_anomaly

pytestmark = pytest.mark.asyncio


def test_a_spike_from_a_zero_baseline_is_detected():
    """The old detector skipped every metric whose baseline mean was zero, which
    silenced exactly the security metrics that are normally zero."""
    assert (
        "avon_control_authentications_total" in FLOORS or "auth_failure_rate" in FLOORS
    )
    anomaly = detect("auth_failure_rate", current=25.0, history=[0.0] * 48)
    assert anomaly is not None
    assert anomaly.severity == "critical"


def test_a_normal_value_against_a_zero_baseline_is_not_an_anomaly():
    assert detect("auth_failure_rate", current=0.0, history=[0.0] * 48) is None


def test_z_score_still_applies_when_a_baseline_exists():
    history = [10.0] * 40 + [11.0] * 8
    assert detect("gateway_drop_rate", current=10.5, history=history) is None
    assert detect("gateway_drop_rate", current=100.0, history=history) is not None


async def test_an_open_anomaly_is_not_duplicated(db, tenant_id):
    anomaly = detect("auth_failure_rate", current=25.0, history=[0.0] * 48)
    assert await open_anomaly(db, tenant_id, anomaly) is True
    assert (
        await open_anomaly(db, tenant_id, anomaly) is False
    ), "an unacknowledged anomaly must not be re-raised"
    rows = await db.fetch(
        "SELECT count(*) AS n FROM anomaly_events WHERE acknowledged_at IS NULL"
    )
    assert rows[0]["n"] == 1


async def test_acknowledging_allows_a_later_recurrence(
    client: AsyncClient, admin_user, db, tenant_id
):
    anomaly = detect("auth_failure_rate", current=25.0, history=[0.0] * 48)
    await open_anomaly(db, tenant_id, anomaly)
    row = await db.fetchrow("SELECT id FROM anomaly_events ORDER BY id DESC LIMIT 1")
    headers = await admin_user.auth_headers(client)
    r = await client.post(
        f"/api/v1/analytics/anomalies/{row['id']}/ack", headers=headers
    )
    assert r.status_code == 200
    assert await open_anomaly(db, tenant_id, anomaly) is True


async def test_an_invalid_period_is_a_422_not_a_500(client: AsyncClient, admin_user):
    headers = await admin_user.auth_headers(client)
    r = await client.get("/api/v1/analytics/metrics?period=abc", headers=headers)
    assert r.status_code == 422
