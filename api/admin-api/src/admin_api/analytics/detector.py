"""Anomaly detection.

Two properties the previous version lacked: a metric whose baseline is zero can
still raise an alert (it used to skip them, which silenced auth failures and
packet drops — the metrics most worth alerting on), and an unacknowledged
anomaly is not raised again every collection interval.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from uuid import UUID

import asyncpg

# Absolute floors for metrics that are normally zero. Crossing one is an alert
# regardless of variance, because "three standard deviations above zero" is zero.
FLOORS: dict[str, float] = {
    "auth_failure_rate": 5.0,
    "gateway_drop_rate": 10.0,
    "avon_gateway_flows_denied_total": 100.0,
    "avon_tunnel_replays_dropped_total": 1.0,  # any replay at all is worth a look
    "avon_control_authentications_total": 0.0,  # informational; never alerts on its own
}

WARNING_SIGMA = 2.0
CRITICAL_SIGMA = 3.0


@dataclass
class Anomaly:
    metric: str
    severity: str
    current: float
    expected: float
    deviation: float
    message: str


def detect(metric: str, current: float, history: list[float]) -> Anomaly | None:
    if not history:
        return None
    mean = statistics.fmean(history)
    stdev = statistics.pstdev(history) if len(history) > 1 else 0.0

    if mean == 0.0 and stdev == 0.0:
        floor = FLOORS.get(metric)
        if floor is None or current <= floor or floor == 0.0:
            return None
        return Anomaly(
            metric=metric,
            severity="critical",
            current=current,
            expected=0.0,
            deviation=current,
            message=f"{metric} rose to {current:g} from a zero baseline (floor {floor:g})",
        )

    if stdev == 0.0:
        # A perfectly flat non-zero baseline: use a proportional test instead.
        if current <= mean * 3:
            return None
        return Anomaly(
            metric,
            "critical",
            current,
            mean,
            current - mean,
            f"{metric} tripled against a flat baseline",
        )

    z = (current - mean) / stdev
    if z < WARNING_SIGMA:
        return None
    severity = "critical" if z >= CRITICAL_SIGMA else "warning"
    return Anomaly(
        metric,
        severity,
        current,
        mean,
        z,
        f"{metric} is {z:.1f} sigma above its {len(history)}-sample baseline",
    )


async def open_anomaly(
    conn: asyncpg.Connection, tenant_id: UUID, anomaly: Anomaly | None
) -> bool:
    """Insert unless an unacknowledged anomaly for this metric already exists."""
    if anomaly is None:
        return False
    existing = await conn.fetchval(
        "SELECT 1 FROM anomaly_events WHERE tenant_id = $1 AND metric_name = $2 AND acknowledged_at IS NULL LIMIT 1",
        tenant_id,
        anomaly.metric,
    )
    if existing:
        return False
    await conn.execute(
        """INSERT INTO anomaly_events (tenant_id, metric_name, severity, current_value, expected_value, deviation, message)
           VALUES ($1, $2, $3, $4, $5, $6, $7)""",
        tenant_id,
        anomaly.metric,
        anomaly.severity,
        anomaly.current,
        anomaly.expected,
        anomaly.deviation,
        anomaly.message,
    )
    return True


# Backward-compat wrappers for old collector API
async def detect_anomalies(
    conn: asyncpg.Connection, metric_name: str, current_value: float
) -> None:
    """Old API — kept for collector compatibility; delegates to detect/open_anomaly."""
    # Try to get history from analytics_hourly; if not available, use single point
    try:
        rows = await conn.fetch(
            "SELECT avg_value FROM analytics_hourly WHERE metric_name = $1 ORDER BY hour DESC LIMIT 48",
            metric_name,
        )
        history = [float(r["avg_value"] or 0.0) for r in rows]
        if len(history) < 5:
            history = [0.0] * 48
    except Exception:
        history = [0.0] * 48
    anomaly = detect(metric_name, current_value, history)
    if anomaly is not None:
        # tenant_id fallback
        try:
            tenant_id = await conn.fetchval("SELECT id FROM tenants LIMIT 1")
            if tenant_id:
                await open_anomaly(conn, tenant_id, anomaly)
        except Exception:
            pass


async def run_anomaly_detection(conn: asyncpg.Connection) -> None:
    """Run anomaly detection on all monitored metrics using latest snapshot values."""
    for metric in FLOORS:
        row = await conn.fetchrow(
            """SELECT metric_value FROM analytics_snapshots
               WHERE metric_name = $1
               ORDER BY collected_at DESC LIMIT 1""",
            metric,
        )
        if row:
            await detect_anomalies(conn, metric, float(row["metric_value"]))
