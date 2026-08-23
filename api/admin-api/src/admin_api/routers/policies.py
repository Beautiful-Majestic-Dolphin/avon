"""Policy management endpoints for AVON Admin API — v2 spec with JSON Schema contract."""

from __future__ import annotations

import json
import pathlib
from uuid import UUID

import asyncpg
import jsonschema
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status

from admin_api.auth.dependencies import CurrentUser, get_current_admin, get_current_user
from admin_api.db.connection import get_db
from admin_api.db.queries import ActivityQueries, PolicyQueries
from admin_api.schemas.policy import (
    CedarResponse,
    ExplainRequest,
    ExplainResponse,
    PolicyCreateRequest,
    PolicyDetailResponse,
    PolicyListResponse,
    PolicyResponse,
    PolicyUpdateRequest,
)
from admin_api.services.control_client import ControlClient

logger = structlog.get_logger()
router = APIRouter()

_SCHEMA_PATH = (
    pathlib.Path(__file__).parents[3].parent.parent.parent
    / "docs"
    / "policy-schema.json"
)
# Fallback for installed layout
if not _SCHEMA_PATH.exists():
    _SCHEMA_PATH = pathlib.Path(__file__).parents[4] / "docs" / "policy-schema.json"
try:
    _SCHEMA = json.loads(_SCHEMA_PATH.read_text()) if _SCHEMA_PATH.exists() else None
except Exception:
    _SCHEMA = None


def _validate_spec(spec: dict) -> None:
    if _SCHEMA is None:
        return
    try:
        jsonschema.validate(instance=spec, schema=_SCHEMA)
    except jsonschema.ValidationError as e:
        # Include schema path for debuggability — matches expected 422 shape
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "msg": e.message,
                "path": list(e.path),
                "schema_path": list(e.schema_path),
            },
        ) from e


def _row_to_response(row) -> PolicyResponse:
    return PolicyResponse(
        id=row.id,
        name=row.name,
        description=row.description,
        enabled=row.enabled,
        priority=row.priority,
        spec=row.spec,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("/", response_model=PolicyListResponse)
async def list_policies(
    enabled: bool | None = Query(None, description="Filter by enabled status"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> PolicyListResponse:
    policies = await PolicyQueries.list_policies(
        db, enabled=enabled, skip=skip, limit=limit
    )
    total = await PolicyQueries.count_policies(db, enabled=enabled)
    items = [_row_to_response(p) for p in policies]
    return PolicyListResponse(
        items=items,
        total=total,
        skip=skip,
        limit=limit,
        has_more=(skip + len(items)) < total,
    )


@router.post("/explain", response_model=ExplainResponse)
async def explain_policy(
    req: ExplainRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> ExplainResponse:
    tenant_id = getattr(current_user.user, "tenant_id", None) or current_user.id
    client = ControlClient()
    try:
        result = await client.explain(
            tenant_id, req.device_id, req.destination, req.protocol, req.port
        )
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"control unavailable: {e}") from e
    # result may be dict or object with allow/reason/matched_policies/cedar
    if isinstance(result, dict):
        return ExplainResponse(
            allow=bool(result.get("allow", False)),
            reason=str(result.get("reason", "")),
            matched_policies=list(
                result.get("matched_policies", []) or result.get("matched", [])
            ),
            cedar=str(result.get("cedar", "")),
        )
    return ExplainResponse(
        allow=bool(getattr(result, "allow", False)),
        reason=str(getattr(result, "reason", "")),
        matched_policies=list(
            getattr(result, "matched_policies", []) or getattr(result, "matched", [])
        ),
        cedar=str(getattr(result, "cedar", "")),
    )


@router.get("/{policy_id}/cedar", response_model=CedarResponse)
async def get_policy_cedar(
    policy_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> CedarResponse:
    policy = await PolicyQueries.get_policy(db, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found"
        )
    tenant_id = getattr(current_user.user, "tenant_id", None) or current_user.id
    client = ControlClient()
    try:
        result = await client.explain(tenant_id, policy_id, "0.0.0.0", "tcp", 80)
        cedar = ""
        if isinstance(result, dict):
            cedar = str(result.get("cedar", ""))
        else:
            cedar = str(getattr(result, "cedar", ""))
        if not cedar:
            # Fallback: render spec as pseudo-cedar for debug
            cedar = json.dumps(policy.spec, indent=2)
    except Exception:
        cedar = json.dumps(policy.spec, indent=2)
    return CedarResponse(cedar=cedar, policy_id=policy_id)


@router.get("/{policy_id}", response_model=PolicyDetailResponse)
async def get_policy(
    policy_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> PolicyDetailResponse:
    policy = await PolicyQueries.get_policy(db, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found"
        )
    return PolicyDetailResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        enabled=policy.enabled,
        priority=policy.priority,
        spec=policy.spec,
        version=policy.version,
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
    _validate_spec(policy_request.spec)
    tenant_id = getattr(current_user.user, "tenant_id", None)
    policy = await PolicyQueries.create_policy(
        db,
        name=policy_request.name,
        spec=policy_request.spec,
        tenant_id=tenant_id,
        description=policy_request.description,
        enabled=policy_request.enabled,
        created_by=current_user.id,
    )
    await ActivityQueries.log_activity(
        db,
        event_type="policy.created",
        actor_id=current_user.id,
        actor_type="user",
        target_id=policy.id,
        target_type="policy",
        details={"policy_name": policy.name, "spec": policy.spec},
    )
    logger.info(
        "policy_created",
        policy_id=str(policy.id),
        name=policy.name,
        by_user=str(current_user.id),
    )
    return _row_to_response(policy)


@router.patch("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: UUID,
    policy_request: PolicyUpdateRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> PolicyResponse:
    existing = await PolicyQueries.get_policy(db, policy_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found"
        )
    if policy_request.spec is not None:
        _validate_spec(policy_request.spec)
    policy = await PolicyQueries.update_policy(
        db,
        policy_id=policy_id,
        name=policy_request.name,
        description=policy_request.description,
        enabled=policy_request.enabled,
        spec=policy_request.spec,
        priority=policy_request.priority,
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
    return _row_to_response(policy)


@router.delete("/{policy_id}")
async def delete_policy(
    policy_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> dict:
    policy = await PolicyQueries.get_policy(db, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found"
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
    logger.info(
        "policy_deleted", policy_id=str(policy_id), by_user=str(current_user.id)
    )
    return {"success": True, "message": f"Policy {policy.name} has been deleted"}


@router.post("/{policy_id}/enable")
async def enable_policy(
    policy_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> dict:
    policy = await PolicyQueries.get_policy(db, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found"
        )
    if policy.enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Policy is already enabled"
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
    policy = await PolicyQueries.get_policy(db, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found"
        )
    if not policy.enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Policy is already disabled"
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
