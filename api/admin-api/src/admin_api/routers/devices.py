"""Device management endpoints for AVON Admin API."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
import asyncpg
import structlog

from admin_api.auth.dependencies import get_current_user, get_current_admin, CurrentUser
from admin_api.db.connection import get_db
from admin_api.db.queries import DeviceQueries, ActivityQueries
from admin_api.schemas.device import (
    DeviceResponse,
    DeviceDetailResponse,
    DeviceEnrollmentRequest,
    EnrollmentTokenResponse,
    DeviceUpdateRequest,
    DeviceListResponse,
)
from admin_api.services.enrollment import EnrollmentService

logger = structlog.get_logger()

router = APIRouter()


@router.get("/", response_model=DeviceListResponse)
async def list_devices(
    status: Optional[str] = Query(None, description="Filter by device status"),
    pod_id: Optional[UUID] = Query(None, description="Filter by pod membership"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> DeviceListResponse:
    """List all devices with optional filtering."""
    devices = await DeviceQueries.list_devices(db, status=status, pod_id=pod_id, skip=skip, limit=limit)
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

    logger.info("device_suspended", device_id=str(device_id), by_user=str(current_user.id))

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

    logger.info("device_activated", device_id=str(device_id), by_user=str(current_user.id))

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

    logger.info("device_deleted", device_id=str(device_id), by_user=str(current_user.id))

    return {"success": True, "message": f"Device {device.name} has been deleted"}
