"""Policy management endpoints for AVON Admin API."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
import asyncpg
import structlog

from admin_api.auth.dependencies import get_current_user, get_current_admin, CurrentUser
from admin_api.db.connection import get_db
from admin_api.db.queries import PolicyQueries, PodQueries, ActivityQueries
from admin_api.schemas.policy import (
    PolicyResponse,
    PolicyDetailResponse,
    PolicyCreateRequest,
    PolicyUpdateRequest,
    PolicyListResponse,
    PolicyConditionsSchema,
)

logger = structlog.get_logger()

router = APIRouter()


@router.get("/", response_model=PolicyListResponse)
async def list_policies(
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> PolicyListResponse:
    """List all policies with optional filtering."""
    policies = await PolicyQueries.list_policies(db, enabled=enabled, skip=skip, limit=limit)
    total = await PolicyQueries.count_policies(db, enabled=enabled)

    items = [
        PolicyResponse(
            id=policy.id,
            name=policy.name,
            description=policy.description,
            source_pod_id=policy.source_pod_id,
            destination_pod_id=policy.destination_pod_id,
            action=policy.action,
            priority=policy.priority,
            enabled=policy.enabled,
            created_at=policy.created_at,
        )
        for policy in policies
    ]

    return PolicyListResponse(
        items=items,
        total=total,
        skip=skip,
        limit=limit,
        has_more=(skip + len(items)) < total,
    )


@router.get("/{policy_id}", response_model=PolicyDetailResponse)
async def get_policy(
    policy_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> PolicyDetailResponse:
    """Get detailed information about a specific policy."""
    policy = await PolicyQueries.get_policy(db, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )

    source_pod = await PodQueries.get_pod(db, policy.source_pod_id)
    dest_pod = await PodQueries.get_pod(db, policy.destination_pod_id)

    conditions = None
    if policy.conditions:
        conditions = PolicyConditionsSchema(**policy.conditions)

    return PolicyDetailResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        source_pod_id=policy.source_pod_id,
        source_pod_name=source_pod.name if source_pod else None,
        destination_pod_id=policy.destination_pod_id,
        destination_pod_name=dest_pod.name if dest_pod else None,
        action=policy.action,
        priority=policy.priority,
        enabled=policy.enabled,
        conditions=conditions,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
        created_by=policy.created_by,
    )


@router.post("/", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    policy_request: PolicyCreateRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> PolicyResponse:
    """Create a new policy.
    
    Requires admin privileges.
    """
    source_pod = await PodQueries.get_pod(db, policy_request.source_pod_id)
    if source_pod is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source pod not found",
        )

    dest_pod = await PodQueries.get_pod(db, policy_request.destination_pod_id)
    if dest_pod is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Destination pod not found",
        )

    conditions_dict = None
    if policy_request.conditions:
        conditions_dict = policy_request.conditions.model_dump()

    policy = await PolicyQueries.create_policy(
        db,
        name=policy_request.name,
        source_pod_id=policy_request.source_pod_id,
        destination_pod_id=policy_request.destination_pod_id,
        action=policy_request.action,
        priority=policy_request.priority,
        description=policy_request.description,
        conditions=conditions_dict,
        created_by=current_user.id,
    )

    await ActivityQueries.log_activity(
        db,
        event_type="policy.created",
        actor_id=current_user.id,
        actor_type="user",
        target_id=policy.id,
        target_type="policy",
        details={
            "policy_name": policy.name,
            "action": policy.action,
            "source_pod": str(policy.source_pod_id),
            "destination_pod": str(policy.destination_pod_id),
        },
    )

    logger.info(
        "policy_created",
        policy_id=str(policy.id),
        name=policy.name,
        by_user=str(current_user.id),
    )

    return PolicyResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        source_pod_id=policy.source_pod_id,
        destination_pod_id=policy.destination_pod_id,
        action=policy.action,
        priority=policy.priority,
        enabled=policy.enabled,
        created_at=policy.created_at,
    )


@router.patch("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: UUID,
    policy_request: PolicyUpdateRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> PolicyResponse:
    """Update a policy.
    
    Requires admin privileges.
    """
    existing = await PolicyQueries.get_policy(db, policy_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )

    conditions_dict = None
    if policy_request.conditions:
        conditions_dict = policy_request.conditions.model_dump()

    policy = await PolicyQueries.update_policy(
        db,
        policy_id=policy_id,
        name=policy_request.name,
        description=policy_request.description,
        action=policy_request.action,
        priority=policy_request.priority,
        enabled=policy_request.enabled,
        conditions=conditions_dict,
    )

    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update policy",
        )

    await ActivityQueries.log_activity(
        db,
        event_type="policy.updated",
        actor_id=current_user.id,
        actor_type="user",
        target_id=policy_id,
        target_type="policy",
        details={"changes": policy_request.model_dump(exclude_unset=True)},
    )

    return PolicyResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        source_pod_id=policy.source_pod_id,
        destination_pod_id=policy.destination_pod_id,
        action=policy.action,
        priority=policy.priority,
        enabled=policy.enabled,
        created_at=policy.created_at,
    )


@router.delete("/{policy_id}")
async def delete_policy(
    policy_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> dict:
    """Delete a policy.
    
    Requires admin privileges.
    """
    policy = await PolicyQueries.get_policy(db, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )

    success = await PolicyQueries.delete_policy(db, policy_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete policy",
        )

    await ActivityQueries.log_activity(
        db,
        event_type="policy.deleted",
        actor_id=current_user.id,
        actor_type="user",
        target_id=policy_id,
        target_type="policy",
        details={"policy_name": policy.name},
    )

    logger.info("policy_deleted", policy_id=str(policy_id), by_user=str(current_user.id))

    return {"success": True, "message": f"Policy {policy.name} has been deleted"}


@router.post("/{policy_id}/enable")
async def enable_policy(
    policy_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> dict:
    """Enable a policy.
    
    Requires admin privileges.
    """
    policy = await PolicyQueries.get_policy(db, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )

    if policy.enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy is already enabled",
        )

    await PolicyQueries.update_policy(db, policy_id, enabled=True)

    await ActivityQueries.log_activity(
        db,
        event_type="policy.enabled",
        actor_id=current_user.id,
        actor_type="user",
        target_id=policy_id,
        target_type="policy",
    )

    return {"success": True, "message": f"Policy {policy.name} has been enabled"}


@router.post("/{policy_id}/disable")
async def disable_policy(
    policy_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> dict:
    """Disable a policy.
    
    Requires admin privileges.
    """
    policy = await PolicyQueries.get_policy(db, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )

    if not policy.enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy is already disabled",
        )

    await PolicyQueries.update_policy(db, policy_id, enabled=False)

    await ActivityQueries.log_activity(
        db,
        event_type="policy.disabled",
        actor_id=current_user.id,
        actor_type="user",
        target_id=policy_id,
        target_type="policy",
    )

    return {"success": True, "message": f"Policy {policy.name} has been disabled"}
