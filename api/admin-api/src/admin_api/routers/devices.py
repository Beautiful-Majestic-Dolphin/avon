"""Device management endpoints for AVON Admin API."""

import contextlib
from uuid import UUID

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from admin_api.audit import log_event
from admin_api.auth.dependencies import CurrentUser, get_current_admin, get_current_user
from admin_api.db.connection import get_db
from admin_api.db.queries import ActivityQueries, DeviceQueries
from admin_api.schemas.device import (
    DeviceDetailResponse,
    DeviceEnrollmentRequest,
    DeviceListResponse,
    DeviceResponse,
    EnrollmentTokenResponse,
    EnrollTokenRequest,
)
from admin_api.services.control_client import ControlClient
from admin_api.services.enrollment import EnrollmentService

logger = structlog.get_logger()

router = APIRouter()


@router.get("/", response_model=DeviceListResponse)
async def list_devices(
    status: str | None = Query(None, description="Filter by device status"),
    pod_id: UUID | None = Query(None, description="Filter by pod membership"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> DeviceListResponse:
    """List all devices with optional filtering."""
    devices = await DeviceQueries.list_devices(
        db, status=status, pod_id=pod_id, skip=skip, limit=limit
    )
    total = await DeviceQueries.count_devices(db, status=status)

    items = []
    for device in devices:
        pod_ids = await DeviceQueries.get_device_pods(db, device.id)
        items.append(
            DeviceResponse(
                id=device.id,
                name=device.name,
                status=device.status,
                last_seen_at=device.last_seen_at,
                last_pulse_at=device.last_pulse_at,
                enrolled_at=device.enrolled_at,
                pod_ids=pod_ids,
            )
        )

    return DeviceListResponse(
        items=items,
        total=total,
        skip=skip,
        limit=limit,
        has_more=(skip + len(items)) < total,
    )


# --- 4.12: Enroll tokens (hashed, single-show) ---


@router.post(
    "/enroll-tokens",
    response_model=EnrollmentTokenResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_enroll_token(
    req: EnrollTokenRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
):
    # Support both old and new field names
    device_name = req.device_name or req.name or "device"
    # Use tenant from current user
    tenant_id = getattr(current_user.user, "tenant_id", None)
    # Create via enrollment service
    svc = EnrollmentService(db)
    result = await svc.create_enrollment(
        name=device_name,
        device_type=req.device_type,
        assigned_pods=req.assigned_pods,
        created_by=current_user.id,
        expires_hours=req.expires_in_hours,
        max_uses=req.max_uses,
        require_approval=req.require_approval,
        tenant_id=tenant_id,
    )
    # Audit without plaintext token
    with contextlib.suppress(Exception):
        await log_event(
            db,
            tenant_id or current_user.user.id,
            actor=current_user.id,
            event="enrollment.created",
            target=None,
            details={
                "device_name": device_name,
                "max_uses": req.max_uses,
                "require_approval": req.require_approval,
            },
        )
    return result


@router.get("/enroll-tokens")
async def list_enroll_tokens(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
):
    rows = await db.fetch(
        "SELECT id, device_name, device_kind, max_uses, use_count, require_approval, expires_at, created_at FROM enrollment_tokens WHERE tenant_id = $1 ORDER BY created_at DESC",
        getattr(current_user.user, "tenant_id", None) or current_user.id,
    )
    items = []
    for r in rows:
        items.append(
            {
                "id": str(r["id"]),
                "device_name": r["device_name"],
                "device_kind": r["device_kind"],
                "max_uses": r["max_uses"],
                "use_count": r["use_count"],
                "require_approval": r["require_approval"],
                "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
        )
    return {"items": items, "total": len(items)}


@router.delete("/enroll-tokens/{token_id}")
async def delete_enroll_token(
    token_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
):
    await db.execute(
        "DELETE FROM enrollment_tokens WHERE id = $1 AND tenant_id = $2",
        token_id,
        getattr(current_user.user, "tenant_id", None) or current_user.id,
    )
    return {"success": True}


@router.get("/{device_id}", response_model=DeviceDetailResponse)
async def get_device(
    device_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> DeviceDetailResponse:
    """Get detailed information about a specific device."""
    device = await DeviceQueries.get_device(db, device_id)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    pod_ids = await DeviceQueries.get_device_pods(db, device_id)

    return DeviceDetailResponse(
        id=device.id,
        name=device.name,
        status=device.status,
        hardware_fingerprint=device.hardware_fingerprint.hex(),
        last_seen_at=device.last_seen_at,
        last_pulse_at=device.last_pulse_at,
        last_known_ip=device.last_known_ip,
        enrolled_at=device.enrolled_at,
        enrolled_by=device.enrolled_by,
        created_at=device.created_at,
        updated_at=device.updated_at,
        pod_ids=pod_ids,
    )


@router.post("/enroll", response_model=EnrollmentTokenResponse)
async def create_enrollment(
    enrollment: DeviceEnrollmentRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> EnrollmentTokenResponse:
    """Create an enrollment token for a new device.

    Requires admin privileges.
    """
    enrollment_service = EnrollmentService(db)
    result = await enrollment_service.create_enrollment(
        name=enrollment.name,
        device_type=enrollment.device_type,
        assigned_pods=enrollment.assigned_pods,
        created_by=current_user.id,
        require_fido2=enrollment.require_fido2,
    )

    await ActivityQueries.log_activity(
        db,
        event_type="device.enrollment_created",
        actor_id=current_user.id,
        actor_type="user",
        details={
            "device_name": enrollment.name,
            "device_type": enrollment.device_type,
            "assigned_pods": [str(p) for p in enrollment.assigned_pods],
        },
    )

    return result


@router.post("/{device_id}/suspend")
async def suspend_device(
    device_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> dict:
    """Suspend a device, revoking its access.

    Requires admin privileges.
    """
    device = await DeviceQueries.get_device(db, device_id)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    if device.status == "suspended":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device is already suspended",
        )

    success = await DeviceQueries.update_device_status(db, device_id, "suspended")
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to suspend device",
        )

    await ActivityQueries.log_activity(
        db,
        event_type="device.suspended",
        actor_id=current_user.id,
        actor_type="user",
        target_id=device_id,
        target_type="device",
        details={"device_name": device.name},
    )

    logger.info(
        "device_suspended", device_id=str(device_id), by_user=str(current_user.id)
    )

    return {"success": True, "message": f"Device {device.name} has been suspended"}


@router.post("/{device_id}/activate")
async def activate_device(
    device_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> dict:
    """Reactivate a suspended device.

    Requires admin privileges.
    """
    device = await DeviceQueries.get_device(db, device_id)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    if device.status == "active":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device is already active",
        )

    success = await DeviceQueries.update_device_status(db, device_id, "active")
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate device",
        )

    await ActivityQueries.log_activity(
        db,
        event_type="device.activated",
        actor_id=current_user.id,
        actor_type="user",
        target_id=device_id,
        target_type="device",
        details={"device_name": device.name},
    )

    logger.info(
        "device_activated", device_id=str(device_id), by_user=str(current_user.id)
    )

    return {"success": True, "message": f"Device {device.name} has been activated"}


@router.delete("/{device_id}")
async def delete_device(
    device_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> dict:
    """Permanently delete a device.

    Requires admin privileges. This action cannot be undone.
    """
    device = await DeviceQueries.get_device(db, device_id)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    success = await DeviceQueries.delete_device(db, device_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete device",
        )

    await ActivityQueries.log_activity(
        db,
        event_type="device.deleted",
        actor_id=current_user.id,
        actor_type="user",
        target_id=device_id,
        target_type="device",
        details={"device_name": device.name},
    )

    logger.info(
        "device_deleted", device_id=str(device_id), by_user=str(current_user.id)
    )

    return {"success": True, "message": f"Device {device.name} has been deleted"}


# --- 4.12: Device lifecycle via Control ---


@router.post("/{device_id}/approve")
async def approve_device_endpoint(
    device_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
):
    # Get tenant
    tenant_id = (
        getattr(current_user.user, "tenant_id", None)
        or await db.fetchval("SELECT tenant_id FROM devices WHERE id = $1", device_id)
        or current_user.id
    )
    client = ControlClient()
    try:
        await client.approve_device(tenant_id, device_id)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"control unavailable: {e}") from e
    # Update local status only after control success
    await db.execute(
        "UPDATE devices SET status = 'active'::device_status, updated_at = NOW() WHERE id = $1",
        device_id,
    )
    with contextlib.suppress(Exception):
        await log_event(
            db,
            tenant_id,
            actor=current_user.id,
            event="device.approve",
            target=device_id,
            details={},
        )
    return {"success": True}


class RevokeRequest(BaseModel):
    reason: str = "revoked"


@router.post("/{device_id}/revoke")
async def revoke_device_endpoint(
    device_id: UUID,
    body: RevokeRequest = None,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
):
    # body may contain reason
    reason = body.reason if body else "revoked"
    # Try to get tenant
    tenant_id = (
        getattr(current_user.user, "tenant_id", None)
        or await db.fetchval("SELECT tenant_id FROM devices WHERE id = $1", device_id)
        or current_user.id
    )
    client = ControlClient()
    try:
        await client.revoke_device(tenant_id, device_id, reason)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"control unavailable: {e}") from e
    await db.execute(
        "UPDATE devices SET status = 'revoked'::device_status, updated_at = NOW() WHERE id = $1",
        device_id,
    )
    with contextlib.suppress(Exception):
        await log_event(
            db,
            tenant_id,
            actor=current_user.id,
            event="device.revoke",
            target=device_id,
            details={"reason": reason},
        )
    return {"success": True}
