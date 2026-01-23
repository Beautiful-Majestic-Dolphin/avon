"""Pod management endpoints for AVON Admin API."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
import asyncpg
import structlog

from admin_api.auth.dependencies import get_current_user, get_current_admin, CurrentUser
from admin_api.db.connection import get_db
from admin_api.db.queries import PodQueries, ActivityQueries
from admin_api.schemas.pod import (
    PodResponse,
    PodDetailResponse,
    PodCreateRequest,
    PodUpdateRequest,
    PodListResponse,
    PodDeviceRequest,
)

logger = structlog.get_logger()

router = APIRouter()


@router.get("/", response_model=PodListResponse)
async def list_pods(
    parent_id: Optional[UUID] = Query(None, description="Filter by parent pod"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> PodListResponse:
    """List all pods with optional filtering."""
    pods = await PodQueries.list_pods(db, parent_id=parent_id, skip=skip, limit=limit)
    total = await PodQueries.count_pods(db)

    items = []
    for pod in pods:
        device_ids = await PodQueries.get_pod_devices(db, pod.id)
        items.append(
            PodResponse(
                id=pod.id,
                name=pod.name,
                parent_id=pod.parent_id,
                description=pod.description,
                device_count=len(device_ids),
                created_at=pod.created_at,
            )
        )

    return PodListResponse(
        items=items,
        total=total,
        skip=skip,
        limit=limit,
        has_more=(skip + len(items)) < total,
    )


@router.get("/{pod_id}", response_model=PodDetailResponse)
async def get_pod(
    pod_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> PodDetailResponse:
    """Get detailed information about a specific pod."""
    pod = await PodQueries.get_pod(db, pod_id)
    if pod is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pod not found",
        )

    device_ids = await PodQueries.get_pod_devices(db, pod_id)
    child_pods = await PodQueries.list_pods(db, parent_id=pod_id)

    child_pod_responses = []
    for child in child_pods:
        child_device_ids = await PodQueries.get_pod_devices(db, child.id)
        child_pod_responses.append(
            PodResponse(
                id=child.id,
                name=child.name,
                parent_id=child.parent_id,
                description=child.description,
                device_count=len(child_device_ids),
                created_at=child.created_at,
            )
        )

    return PodDetailResponse(
        id=pod.id,
        name=pod.name,
        parent_id=pod.parent_id,
        description=pod.description,
        created_at=pod.created_at,
        updated_at=pod.updated_at,
        device_count=len(device_ids),
        child_pods=child_pod_responses,
        devices=device_ids,
    )


@router.post("/", response_model=PodResponse, status_code=status.HTTP_201_CREATED)
async def create_pod(
    pod_request: PodCreateRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> PodResponse:
    """Create a new pod.
    
    Requires admin privileges.
    """
    if pod_request.parent_id:
        parent = await PodQueries.get_pod(db, pod_request.parent_id)
        if parent is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Parent pod not found",
            )

    pod = await PodQueries.create_pod(
        db,
        name=pod_request.name,
        parent_id=pod_request.parent_id,
        description=pod_request.description,
    )

    await ActivityQueries.log_activity(
        db,
        event_type="pod.created",
        actor_id=current_user.id,
        actor_type="user",
        target_id=pod.id,
        target_type="pod",
        details={"pod_name": pod.name, "parent_id": str(pod.parent_id) if pod.parent_id else None},
    )

    logger.info("pod_created", pod_id=str(pod.id), name=pod.name, by_user=str(current_user.id))

    return PodResponse(
        id=pod.id,
        name=pod.name,
        parent_id=pod.parent_id,
        description=pod.description,
        device_count=0,
        created_at=pod.created_at,
    )


@router.patch("/{pod_id}", response_model=PodResponse)
async def update_pod(
    pod_id: UUID,
    pod_request: PodUpdateRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> PodResponse:
    """Update a pod.
    
    Requires admin privileges.
    """
    existing = await PodQueries.get_pod(db, pod_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pod not found",
        )

    pod = await PodQueries.update_pod(
        db,
        pod_id=pod_id,
        name=pod_request.name,
        description=pod_request.description,
    )

    if pod is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update pod",
        )

    await ActivityQueries.log_activity(
        db,
        event_type="pod.updated",
        actor_id=current_user.id,
        actor_type="user",
        target_id=pod_id,
        target_type="pod",
        details={"changes": pod_request.model_dump(exclude_unset=True)},
    )

    device_ids = await PodQueries.get_pod_devices(db, pod_id)

    return PodResponse(
        id=pod.id,
        name=pod.name,
        parent_id=pod.parent_id,
        description=pod.description,
        device_count=len(device_ids),
        created_at=pod.created_at,
    )


@router.delete("/{pod_id}")
async def delete_pod(
    pod_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> dict:
    """Delete a pod.
    
    Requires admin privileges. Cannot delete pods with child pods or devices.
    """
    pod = await PodQueries.get_pod(db, pod_id)
    if pod is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pod not found",
        )

    child_pods = await PodQueries.list_pods(db, parent_id=pod_id, limit=1)
    if child_pods:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete pod with child pods",
        )

    device_ids = await PodQueries.get_pod_devices(db, pod_id)
    if device_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete pod with devices",
        )

    success = await PodQueries.delete_pod(db, pod_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete pod",
        )

    await ActivityQueries.log_activity(
        db,
        event_type="pod.deleted",
        actor_id=current_user.id,
        actor_type="user",
        target_id=pod_id,
        target_type="pod",
        details={"pod_name": pod.name},
    )

    logger.info("pod_deleted", pod_id=str(pod_id), by_user=str(current_user.id))

    return {"success": True, "message": f"Pod {pod.name} has been deleted"}


@router.post("/{pod_id}/devices")
async def add_device_to_pod(
    pod_id: UUID,
    request: PodDeviceRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> dict:
    """Add a device to a pod.
    
    Requires admin privileges.
    """
    pod = await PodQueries.get_pod(db, pod_id)
    if pod is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pod not found",
        )

    success = await PodQueries.add_device_to_pod(db, request.device_id, pod_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add device to pod",
        )

    await ActivityQueries.log_activity(
        db,
        event_type="pod.device_added",
        actor_id=current_user.id,
        actor_type="user",
        target_id=pod_id,
        target_type="pod",
        details={"device_id": str(request.device_id)},
    )

    return {"success": True, "message": "Device added to pod"}


@router.delete("/{pod_id}/devices/{device_id}")
async def remove_device_from_pod(
    pod_id: UUID,
    device_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> dict:
    """Remove a device from a pod.
    
    Requires admin privileges.
    """
    pod = await PodQueries.get_pod(db, pod_id)
    if pod is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pod not found",
        )

    success = await PodQueries.remove_device_from_pod(db, device_id, pod_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not in pod",
        )

    await ActivityQueries.log_activity(
        db,
        event_type="pod.device_removed",
        actor_id=current_user.id,
        actor_type="user",
        target_id=pod_id,
        target_type="pod",
        details={"device_id": str(device_id)},
    )

    return {"success": True, "message": "Device removed from pod"}
