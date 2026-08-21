"""Dashboard endpoints for AVON Admin API."""

from datetime import UTC, datetime

import asyncpg
import structlog
from fastapi import APIRouter, Depends, Query

from admin_api.auth.dependencies import CurrentUser, get_current_user
from admin_api.db.connection import get_db
from admin_api.db.queries import (
    ActivityQueries,
    DeviceQueries,
    PodQueries,
    PolicyQueries,
    TunnelQueries,
)

logger = structlog.get_logger()

router = APIRouter()


@router.get("/overview")
async def get_dashboard_overview(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Get dashboard overview statistics."""
    device_stats = await DeviceQueries.get_devices_by_status(db)
    total_devices = await DeviceQueries.count_devices(db)
    active_devices = device_stats.get("active", 0)
    suspended_devices = device_stats.get("suspended", 0)

    total_pods = await PodQueries.count_pods(db)

    total_policies = await PolicyQueries.count_policies(db)
    enabled_policies = await PolicyQueries.count_policies(db, enabled=True)

    tunnel_stats = await TunnelQueries.get_tunnel_stats(db)
    total_tunnels = await TunnelQueries.count_tunnels(db)
    active_tunnels = await TunnelQueries.count_tunnels(db, status="active")

    return {
        "devices": {
            "total": total_devices,
            "active": active_devices,
            "suspended": suspended_devices,
            "by_status": device_stats,
        },
        "pods": {
            "total": total_pods,
        },
        "policies": {
            "total": total_policies,
            "enabled": enabled_policies,
            "disabled": total_policies - enabled_policies,
        },
        "tunnels": {
            "total": total_tunnels,
            "active": active_tunnels,
            "by_status": tunnel_stats.get("by_status", {}),
            "total_bytes_sent": tunnel_stats.get("total_bytes_sent", 0),
            "total_bytes_received": tunnel_stats.get("total_bytes_received", 0),
        },
        "timestamp": datetime.now(UTC).isoformat(),
    }


@router.get("/activity")
async def get_recent_activity(
    hours: int = Query(24, ge=1, le=168, description="Hours of activity to retrieve"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Get recent activity feed."""
    activities = await ActivityQueries.get_recent_activity(db, hours=hours, limit=limit)

    items = [
        {
            "id": str(activity.id),
            "event_type": activity.event_type,
            "actor_id": str(activity.actor_id) if activity.actor_id else None,
            "actor_type": activity.actor_type,
            "target_id": str(activity.target_id) if activity.target_id else None,
            "target_type": activity.target_type,
            "details": activity.details,
            "ip_address": activity.ip_address,
            "created_at": activity.created_at.isoformat(),
        }
        for activity in activities
    ]

    return {
        "items": items,
        "hours": hours,
        "count": len(items),
    }


@router.get("/device-health")
async def get_device_health(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Get device health summary."""
    device_stats = await DeviceQueries.get_devices_by_status(db)
    total = await DeviceQueries.count_devices(db)

    healthy = device_stats.get("active", 0)
    warning = device_stats.get("pending", 0)
    critical = device_stats.get("suspended", 0) + device_stats.get("revoked", 0)

    health_percentage = (healthy / total * 100) if total > 0 else 100

    return {
        "total_devices": total,
        "healthy": healthy,
        "warning": warning,
        "critical": critical,
        "health_percentage": round(health_percentage, 1),
        "by_status": device_stats,
    }


@router.get("/policy-summary")
async def get_policy_summary(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Get policy summary."""
    total = await PolicyQueries.count_policies(db)
    enabled = await PolicyQueries.count_policies(db, enabled=True)
    disabled = total - enabled

    policies = await PolicyQueries.list_policies(db, limit=10)

    recent_policies = [
        {
            "id": str(policy.id),
            "name": policy.name,
            "action": policy.action,
            "enabled": policy.enabled,
            "priority": policy.priority,
            "created_at": policy.created_at.isoformat(),
        }
        for policy in policies
    ]

    return {
        "total": total,
        "enabled": enabled,
        "disabled": disabled,
        "recent_policies": recent_policies,
    }


@router.get("/tunnel-metrics")
async def get_tunnel_metrics(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Get tunnel metrics."""
    stats = await TunnelQueries.get_tunnel_stats(db)
    total = await TunnelQueries.count_tunnels(db)
    active = await TunnelQueries.count_tunnels(db, status="active")

    bytes_sent = stats.get("total_bytes_sent", 0)
    bytes_received = stats.get("total_bytes_received", 0)

    def format_bytes(b: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if b < 1024:
                return f"{b:.2f} {unit}"
            b /= 1024
        return f"{b:.2f} PB"

    return {
        "total_tunnels": total,
        "active_tunnels": active,
        "by_status": stats.get("by_status", {}),
        "data_transfer": {
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "bytes_sent_formatted": format_bytes(bytes_sent),
            "bytes_received_formatted": format_bytes(bytes_received),
            "total_bytes": bytes_sent + bytes_received,
            "total_formatted": format_bytes(bytes_sent + bytes_received),
        },
    }
