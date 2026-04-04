"""SCIM 2.0 API endpoints for AVON Admin API.

Implements RFC 7643/7644 for user and group provisioning from identity
providers (Okta, Azure AD, Google Workspace, etc.).
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
import asyncpg
import structlog

from admin_api.db.connection import get_db
from admin_api.scim.auth import get_scim_auth
from admin_api.scim.filters import (
    SCIM_GROUP_ATTRIBUTES,
    SCIM_USER_ATTRIBUTES,
    parse_filter,
)
from admin_api.scim.schemas import (
    SCIM_GROUP_SCHEMA,
    SCIM_USER_SCHEMA,
    ScimErrorResponse,
    ScimGroupRequest,
    ScimGroupResponse,
    ScimListResponse,
    ScimPatchRequest,
    ScimUserRequest,
    ScimUserResponse,
)
from admin_api.scim.service import ScimService

logger = structlog.get_logger()

router = APIRouter(dependencies=[Depends(get_scim_auth)])


def _scim_error(status_code: int, detail: str, scim_type: str = None):
    """Raise an HTTPException with SCIM error format."""
    raise HTTPException(
        status_code=status_code,
        detail=ScimErrorResponse(
            detail=detail,
            status=str(status_code),
            scimType=scim_type,
        ).model_dump(),
    )


# --- Discovery Endpoints ---


@router.get("/ServiceProviderConfig")
async def get_service_provider_config() -> dict:
    """Return SCIM service provider configuration."""
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 1000},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "SCIM bearer token authentication",
            }
        ],
    }


@router.get("/Schemas")
async def get_schemas() -> dict:
    """Return supported SCIM schemas."""
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "Resources": [
            {
                "id": SCIM_USER_SCHEMA,
                "name": "User",
                "description": "AVON User Account",
                "attributes": [
                    {"name": "userName", "type": "string", "required": True, "uniqueness": "server"},
                    {"name": "name", "type": "complex", "required": False},
                    {"name": "displayName", "type": "string", "required": False},
                    {"name": "active", "type": "boolean", "required": False},
                    {"name": "externalId", "type": "string", "required": False, "uniqueness": "global"},
                ],
            },
            {
                "id": SCIM_GROUP_SCHEMA,
                "name": "Group",
                "description": "AVON Pod / Group",
                "attributes": [
                    {"name": "displayName", "type": "string", "required": True},
                    {"name": "members", "type": "complex", "required": False, "multiValued": True},
                    {"name": "externalId", "type": "string", "required": False, "uniqueness": "global"},
                ],
            },
        ],
    }


@router.get("/ResourceTypes")
async def get_resource_types() -> dict:
    """Return supported SCIM resource types."""
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "Resources": [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/scim/v2/Users",
                "schema": SCIM_USER_SCHEMA,
            },
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "Group",
                "name": "Group",
                "endpoint": "/scim/v2/Groups",
                "schema": SCIM_GROUP_SCHEMA,
            },
        ],
    }


# --- User Endpoints ---


@router.get("/Users")
async def list_users(
    filter: Optional[str] = Query(None),
    startIndex: int = Query(1, ge=1),
    count: int = Query(100, ge=1, le=1000),
    db: asyncpg.Connection = Depends(get_db),
) -> dict:
    """List or search SCIM users."""
    service = ScimService(db)
    offset = startIndex - 1  # SCIM uses 1-based indexing

    parsed = None
    if filter:
        try:
            parsed = parse_filter(filter, SCIM_USER_ATTRIBUTES)
        except ValueError as e:
            _scim_error(400, str(e), "invalidFilter")

    users, total = await service.list_users(
        offset=offset,
        limit=count,
        filter_column=parsed.column if parsed else None,
        filter_op=parsed.operator if parsed else None,
        filter_value=parsed.value if parsed else None,
    )

    return ScimListResponse(
        totalResults=total,
        startIndex=startIndex,
        itemsPerPage=len(users),
        Resources=[u.model_dump(by_alias=True) for u in users],
    ).model_dump(by_alias=True)


@router.post("/Users", status_code=status.HTTP_201_CREATED)
async def create_user(
    request: ScimUserRequest,
    db: asyncpg.Connection = Depends(get_db),
) -> dict:
    """Create a SCIM user."""
    service = ScimService(db)

    full_name = None
    if request.name:
        full_name = request.name.formatted or (
            f"{request.name.givenName or ''} {request.name.familyName or ''}".strip()
            if request.name.givenName or request.name.familyName
            else None
        )
    if not full_name and request.displayName:
        full_name = request.displayName

    try:
        user = await service.create_user(
            user_name=request.userName,
            full_name=full_name,
            active=request.active,
            external_id=request.externalId,
        )
    except ValueError as e:
        _scim_error(409, str(e), "uniqueness")

    return user.model_dump(by_alias=True)


@router.get("/Users/{user_id}")
async def get_user(
    user_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
) -> dict:
    """Get a SCIM user by ID."""
    service = ScimService(db)
    user = await service.get_user(user_id)
    if user is None:
        _scim_error(404, "User not found")
    return user.model_dump(by_alias=True)


@router.put("/Users/{user_id}")
async def replace_user(
    user_id: UUID,
    request: ScimUserRequest,
    db: asyncpg.Connection = Depends(get_db),
) -> dict:
    """Replace a SCIM user (full update)."""
    service = ScimService(db)

    full_name = None
    if request.name:
        full_name = request.name.formatted or (
            f"{request.name.givenName or ''} {request.name.familyName or ''}".strip()
            if request.name.givenName or request.name.familyName
            else None
        )
    if not full_name and request.displayName:
        full_name = request.displayName

    user = await service.update_user(
        user_id=user_id,
        user_name=request.userName,
        full_name=full_name,
        active=request.active,
        external_id=request.externalId,
    )
    if user is None:
        _scim_error(404, "User not found")
    return user.model_dump(by_alias=True)


@router.patch("/Users/{user_id}")
async def patch_user(
    user_id: UUID,
    request: ScimPatchRequest,
    db: asyncpg.Connection = Depends(get_db),
) -> dict:
    """Patch a SCIM user (partial update).

    Handles both Okta and Azure AD PATCH formats.
    """
    service = ScimService(db)

    for op in request.Operations:
        op_type = op.op.lower()

        if op_type == "replace":
            # Okta: {"op": "replace", "value": {"active": false}}
            # Azure AD: {"op": "Replace", "path": "active", "value": "false"}
            if op.path:
                value = op.value
                if isinstance(value, str) and value.lower() in ("true", "false"):
                    value = value.lower() == "true"
                await service.update_user(user_id, **{_scim_to_field(op.path): value})
            elif isinstance(op.value, dict):
                kwargs = {}
                for k, v in op.value.items():
                    field = _scim_to_field(k)
                    if field:
                        kwargs[field] = v
                if kwargs:
                    await service.update_user(user_id, **kwargs)

    user = await service.get_user(user_id)
    if user is None:
        _scim_error(404, "User not found")
    return user.model_dump(by_alias=True)


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
) -> None:
    """Delete (deactivate) a SCIM user and suspend their devices."""
    service = ScimService(db)
    deleted = await service.delete_user(user_id)
    if not deleted:
        _scim_error(404, "User not found")


# --- Group Endpoints ---


@router.get("/Groups")
async def list_groups(
    filter: Optional[str] = Query(None),
    startIndex: int = Query(1, ge=1),
    count: int = Query(100, ge=1, le=1000),
    db: asyncpg.Connection = Depends(get_db),
) -> dict:
    """List or search SCIM groups."""
    service = ScimService(db)
    offset = startIndex - 1

    parsed = None
    if filter:
        try:
            parsed = parse_filter(filter, SCIM_GROUP_ATTRIBUTES)
        except ValueError as e:
            _scim_error(400, str(e), "invalidFilter")

    groups, total = await service.list_groups(
        offset=offset,
        limit=count,
        filter_column=parsed.column if parsed else None,
        filter_op=parsed.operator if parsed else None,
        filter_value=parsed.value if parsed else None,
    )

    return ScimListResponse(
        totalResults=total,
        startIndex=startIndex,
        itemsPerPage=len(groups),
        Resources=[g.model_dump(by_alias=True) for g in groups],
    ).model_dump(by_alias=True)


@router.post("/Groups", status_code=status.HTTP_201_CREATED)
async def create_group(
    request: ScimGroupRequest,
    db: asyncpg.Connection = Depends(get_db),
) -> dict:
    """Create a SCIM group (Avon pod)."""
    service = ScimService(db)

    member_ids = [UUID(m.value) for m in request.members]

    group = await service.create_group(
        display_name=request.displayName,
        external_id=request.externalId,
        member_ids=member_ids,
    )
    return group.model_dump(by_alias=True)


@router.get("/Groups/{group_id}")
async def get_group(
    group_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
) -> dict:
    """Get a SCIM group by ID."""
    service = ScimService(db)
    group = await service.get_group(group_id)
    if group is None:
        _scim_error(404, "Group not found")
    return group.model_dump(by_alias=True)


@router.put("/Groups/{group_id}")
async def replace_group(
    group_id: UUID,
    request: ScimGroupRequest,
    db: asyncpg.Connection = Depends(get_db),
) -> dict:
    """Replace a SCIM group (full update)."""
    service = ScimService(db)

    member_ids = [UUID(m.value) for m in request.members]

    group = await service.update_group(
        pod_id=group_id,
        display_name=request.displayName,
        external_id=request.externalId,
        member_ids=member_ids,
    )
    if group is None:
        _scim_error(404, "Group not found")
    return group.model_dump(by_alias=True)


@router.patch("/Groups/{group_id}")
async def patch_group(
    group_id: UUID,
    request: ScimPatchRequest,
    db: asyncpg.Connection = Depends(get_db),
) -> dict:
    """Patch a SCIM group (add/remove members, update name)."""
    service = ScimService(db)

    for op in request.Operations:
        op_type = op.op.lower()
        path = (op.path or "").lower()

        if op_type == "replace":
            if path == "displayname" or (not op.path and isinstance(op.value, dict)):
                name = op.value if isinstance(op.value, str) else op.value.get("displayName")
                if name:
                    await service.update_group(group_id, display_name=name)

        elif op_type == "add" and "members" in path:
            member_ids = _extract_member_ids(op.value)
            await service.add_group_members(group_id, member_ids)

        elif op_type == "remove" and "members" in path:
            member_ids = _extract_member_ids(op.value)
            await service.remove_group_members(group_id, member_ids)

    group = await service.get_group(group_id)
    if group is None:
        _scim_error(404, "Group not found")
    return group.model_dump(by_alias=True)


@router.delete("/Groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
) -> None:
    """Delete a SCIM group (Avon pod)."""
    service = ScimService(db)
    deleted = await service.delete_group(group_id)
    if not deleted:
        _scim_error(404, "Group not found")


# --- Helpers ---


def _scim_to_field(scim_attr: str) -> Optional[str]:
    """Map a SCIM attribute name to an update_user keyword argument."""
    mapping = {
        "userName": "user_name",
        "active": "active",
        "name.formatted": "full_name",
        "displayName": "full_name",
        "externalId": "external_id",
    }
    return mapping.get(scim_attr)


def _extract_member_ids(value) -> list[UUID]:
    """Extract member UUIDs from a SCIM PATCH value."""
    if isinstance(value, list):
        return [UUID(m["value"]) if isinstance(m, dict) else UUID(m) for m in value]
    return []
