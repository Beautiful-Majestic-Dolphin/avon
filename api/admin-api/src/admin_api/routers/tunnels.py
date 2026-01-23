"""Tunnel management endpoints for AVON Admin API."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
import asyncpg
import structlog

from admin_api.auth.dependencies import get_current_user, CurrentUser
from admin_api.db.connection import get_db
from admin_api.db.queries import TunnelQueries
from admin_api.db.models import DbTunnel

logger = structlog.get_logger()

router = APIRouter()


class TunnelResponse:
    """Tunnel response model."""

    def __init__(self, tunnel: DbTunnel):
        self.id = tunnel.id
        self.session_id = tunnel.session_id.hex()
        self.source_device_id = tunnel.source_device_id
        self.destination_device_id = tunnel.destination_device_id
        self.status = tunnel.status
        self.established_at = tunnel.established_at
        self.closed_at = tunnel.closed_at
        self.bytes_sent = tunnel.bytes_sent
        self.bytes_received = tunnel.bytes_received
        self.created_at = tunnel.created_at


class TunnelListResponse:
    """Tunnel list response."""

    def __init__(self, items: list, total: int, skip: int, limit: int):
        self.items = items
        self.total = total
        self.skip = skip
        self.limit = limit
        self.has_more = (skip + len(items)) < total


@router.get("/")
async def list_tunnels(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by tunnel status"),
    device_id: Optional[UUID] = Query(None, description="Filter by device (source or destination)"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """List all tunnels with optional filtering."""
    tunnels = await TunnelQueries.list_tunnels(
        db,
        status=status_filter,
        device_id=device_id,
        skip=skip,
        limit=limit,
    )
    total = await TunnelQueries.count_tunnels(db, status=status_filter)

    items = [
        {
            "id": str(tunnel.id),
            "session_id": tunnel.session_id.hex(),
            "source_device_id": str(tunnel.source_device_id),
            "destination_device_id": str(tunnel.destination_device_id),
            "status": tunnel.status,
            "established_at": tunnel.established_at.isoformat() if tunnel.established_at else None,
            "closed_at": tunnel.closed_at.isoformat() if tunnel.closed_at else None,
            "bytes_sent": tunnel.bytes_sent,
            "bytes_received": tunnel.bytes_received,
            "created_at": tunnel.created_at.isoformat(),
        }
        for tunnel in tunnels
    ]

    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
        "has_more": (skip + len(items)) < total,
    }


@router.get("/stats")
async def get_tunnel_stats(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Get tunnel statistics."""
    stats = await TunnelQueries.get_tunnel_stats(db)
    total = await TunnelQueries.count_tunnels(db)
    active = await TunnelQueries.count_tunnels(db, status="active")

    return {
        "total_tunnels": total,
        "active_tunnels": active,
        "by_status": stats.get("by_status", {}),
        "total_bytes_sent": stats.get("total_bytes_sent", 0),
        "total_bytes_received": stats.get("total_bytes_received", 0),
    }


@router.get("/{tunnel_id}")
async def get_tunnel(
    tunnel_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Get detailed information about a specific tunnel."""
    tunnel = await TunnelQueries.get_tunnel(db, tunnel_id)
    if tunnel is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tunnel not found",
        )

    return {
        "id": str(tunnel.id),
        "session_id": tunnel.session_id.hex(),
        "source_device_id": str(tunnel.source_device_id),
        "destination_device_id": str(tunnel.destination_device_id),
        "status": tunnel.status,
        "established_at": tunnel.established_at.isoformat() if tunnel.established_at else None,
        "closed_at": tunnel.closed_at.isoformat() if tunnel.closed_at else None,
        "bytes_sent": tunnel.bytes_sent,
        "bytes_received": tunnel.bytes_received,
        "created_at": tunnel.created_at.isoformat(),
        "updated_at": tunnel.updated_at.isoformat(),
    }
