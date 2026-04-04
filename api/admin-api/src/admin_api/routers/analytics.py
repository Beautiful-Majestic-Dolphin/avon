"""Analytics endpoints for AVON Admin API.

Provides trend analysis, security posture, anomaly detection,
capacity planning, enrollment velocity, and crypto health metrics.
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query
import asyncpg
import structlog

from admin_api.auth.dependencies import get_current_user, CurrentUser
from admin_api.analytics.models import (
    AnomalyEvent,
    CapacityResponse,
    CryptoHealthResponse,
    EnrollmentVelocityResponse,
    SecurityPostureResponse,
    TrendPoint,
    TrendResponse,
)
from admin_api.analytics.queries import AnalyticsQueries
from admin_api.db.connection import get_db

logger = structlog.get_logger()

router = APIRouter()


@router.get("/trends", response_model=TrendResponse)
async def get_trends(
    metric: str = Query(..., description="Metric name (e.g., connected_agents, auth_request_rate)"),
    period: str = Query("24h", description="Time period (e.g., 6h, 24h, 7d, 30d)"),
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> TrendResponse:
    """Get time-series trend data for a metric."""
    hours = _parse_period(period)

    hourly_data = await AnalyticsQueries.get_hourly_trends(db, metric, hours)

    data = [
        TrendPoint(
            timestamp=h.hour.isoformat(),
            value=h.avg_value or 0.0,
        )
        for h in hourly_data
    ]

    granularity = "hourly" if hours <= 168 else "daily"

    return TrendResponse(
        metric=metric,
        period=period,
        granularity=granularity,
        data=data,
    )


@router.get("/security-posture", response_model=SecurityPostureResponse)
async def get_security_posture(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> SecurityPostureResponse:
    """Get aggregate device security posture metrics."""
    # Device counts by status
    total = await db.fetchrow("SELECT COUNT(*) AS c FROM devices")
    active = await db.fetchrow("SELECT COUNT(*) AS c FROM devices WHERE status = 'active'")
    suspended = await db.fetchrow("SELECT COUNT(*) AS c FROM devices WHERE status = 'suspended'")
    revoked = await db.fetchrow("SELECT COUNT(*) AS c FROM devices WHERE status = 'revoked'")

    total_count = total["c"] if total else 0
    active_count = active["c"] if active else 0
    suspended_count = suspended["c"] if suspended else 0
    revoked_count = revoked["c"] if revoked else 0

    health_pct = (active_count / total_count * 100) if total_count > 0 else 100.0

    # FIDO2 enrolled devices
    fido2 = await db.fetchrow(
        "SELECT COUNT(*) AS c FROM devices WHERE fido2_credential_id IS NOT NULL"
    )
    fido2_count = fido2["c"] if fido2 else 0

    # Recent activity
    recent_enrollments = await db.fetchrow(
        "SELECT COUNT(*) AS c FROM devices WHERE enrolled_at >= NOW() - INTERVAL '24 hours'"
    )
    recent_suspensions = await db.fetchrow(
        """SELECT COUNT(*) AS c FROM activity_logs
           WHERE event_type LIKE '%suspend%' AND created_at >= NOW() - INTERVAL '24 hours'"""
    )

    return SecurityPostureResponse(
        total_devices=total_count,
        active_devices=active_count,
        suspended_devices=suspended_count,
        revoked_devices=revoked_count,
        health_percentage=round(health_pct, 1),
        fido2_enrolled=fido2_count,
        recent_enrollments_24h=recent_enrollments["c"] if recent_enrollments else 0,
        recent_suspensions_24h=recent_suspensions["c"] if recent_suspensions else 0,
    )


@router.get("/anomalies", response_model=list[AnomalyEvent])
async def get_anomalies(
    severity: Optional[str] = Query(None, description="Filter by severity (warning, critical)"),
    days: int = Query(30, ge=1, le=365, description="Look back period in days"),
    limit: int = Query(100, ge=1, le=1000),
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> list[AnomalyEvent]:
    """Get detected anomaly events."""
    return await AnalyticsQueries.get_anomalies(db, severity=severity, days=days, limit=limit)


@router.get("/capacity", response_model=CapacityResponse)
async def get_capacity(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> CapacityResponse:
    """Get capacity and utilization metrics."""
    active_tunnels = await db.fetchrow(
        "SELECT COUNT(*) AS c FROM tunnels WHERE status = 'active'"
    )
    total_tunnels = await db.fetchrow("SELECT COUNT(*) AS c FROM tunnels")
    bytes_transferred = await db.fetchrow(
        "SELECT COALESCE(SUM(bytes_sent + bytes_received), 0) AS total FROM tunnels"
    )
    active_devices = await db.fetchrow(
        "SELECT COUNT(*) AS c FROM devices WHERE status = 'active'"
    )
    total_devices = await db.fetchrow("SELECT COUNT(*) AS c FROM devices")

    active_t = active_tunnels["c"] if active_tunnels else 0
    total_t = total_tunnels["c"] if total_tunnels else 0
    active_d = active_devices["c"] if active_devices else 0
    total_d = total_devices["c"] if total_devices else 0

    return CapacityResponse(
        active_tunnels=active_t,
        total_tunnels=total_t,
        tunnel_utilization_percent=round(active_t / max(total_t, 1) * 100, 1),
        total_bytes_transferred=bytes_transferred["total"] if bytes_transferred else 0,
        active_devices=active_d,
        total_devices=total_d,
        device_utilization_percent=round(active_d / max(total_d, 1) * 100, 1),
    )


@router.get("/enrollment-velocity", response_model=EnrollmentVelocityResponse)
async def get_enrollment_velocity(
    period: str = Query("7d", description="Time period (e.g., 7d, 30d, 90d)"),
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EnrollmentVelocityResponse:
    """Get enrollment rate over time."""
    hours = _parse_period(period)
    days = max(hours // 24, 1)

    rows = await db.fetch(
        """SELECT date_trunc('day', enrolled_at) AS day, COUNT(*) AS count
           FROM devices
           WHERE enrolled_at >= NOW() - INTERVAL '1 hour' * $1
           GROUP BY date_trunc('day', enrolled_at)
           ORDER BY day""",
        hours,
    )

    data = [
        TrendPoint(timestamp=row["day"].isoformat(), value=float(row["count"]))
        for row in rows
    ]

    total = sum(int(row["count"]) for row in rows)
    avg_per_day = total / days if days > 0 else 0

    return EnrollmentVelocityResponse(
        period=period,
        data=data,
        total_enrollments=total,
        avg_per_day=round(avg_per_day, 1),
    )


@router.get("/crypto-health", response_model=CryptoHealthResponse)
async def get_crypto_health(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> CryptoHealthResponse:
    """Get certificate and cryptographic health metrics."""
    total_certs = await db.fetchrow("SELECT COUNT(*) AS c FROM certificates")
    active_certs = await db.fetchrow(
        "SELECT COUNT(*) AS c FROM certificates WHERE status = 'active'"
    )
    revoked_certs = await db.fetchrow(
        "SELECT COUNT(*) AS c FROM certificates WHERE status = 'revoked'"
    )
    expired_certs = await db.fetchrow(
        "SELECT COUNT(*) AS c FROM certificates WHERE status = 'expired' OR not_after < NOW()"
    )

    total_rotations = await db.fetchrow(
        "SELECT COALESCE(SUM(token_sequence), 0) AS total FROM devices"
    )
    recent_rotations = await db.fetchrow(
        """SELECT COUNT(*) AS c FROM activity_logs
           WHERE event_type LIKE '%rotation%' AND created_at >= NOW() - INTERVAL '24 hours'"""
    )

    return CryptoHealthResponse(
        total_certificates=total_certs["c"] if total_certs else 0,
        active_certificates=active_certs["c"] if active_certs else 0,
        revoked_certificates=revoked_certs["c"] if revoked_certs else 0,
        expired_certificates=expired_certs["c"] if expired_certs else 0,
        total_rotations=total_rotations["total"] if total_rotations else 0,
        recent_rotations_24h=recent_rotations["c"] if recent_rotations else 0,
    )


def _parse_period(period: str) -> int:
    """Parse a period string (e.g., '6h', '7d', '30d') to hours."""
    period = period.strip().lower()
    if period.endswith("h"):
        return int(period[:-1])
    elif period.endswith("d"):
        return int(period[:-1]) * 24
    return 24  # default
