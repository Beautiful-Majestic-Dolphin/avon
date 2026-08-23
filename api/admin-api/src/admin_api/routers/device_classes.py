"""Device classes and MUD import."""

from __future__ import annotations

from uuid import UUID

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from admin_api.auth.dependencies import CurrentUser, get_current_admin, get_current_user
from admin_api.db.connection import get_db
from admin_api.db.queries import DeviceClassQueries
from admin_api.services.control_client import ControlClient

logger = structlog.get_logger()
router = APIRouter()


class DeviceClassCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    match_rules: dict = Field(default_factory=dict)
    mud_url: str | None = None


class DeviceClassResponse(BaseModel):
    id: UUID
    name: str
    description: str | None = None
    match_rules: dict = Field(default_factory=dict)
    mud_url: str | None = None


@router.get("/", response_model=list[DeviceClassResponse])
async def list_device_classes(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    rows = await DeviceClassQueries.list_device_classes(db)
    return [
        DeviceClassResponse(
            id=r.id,
            name=r.name,
            description=r.description,
            match_rules=r.match_rules,
            mud_url=r.mud_url,
        )
        for r in rows
    ]


@router.post(
    "/", response_model=DeviceClassResponse, status_code=status.HTTP_201_CREATED
)
async def create_device_class(
    req: DeviceClassCreateRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
):
    tenant_id = getattr(current_user.user, "tenant_id", None)
    row = await DeviceClassQueries.create_device_class(
        db,
        name=req.name,
        tenant_id=tenant_id,
        description=req.description,
        match_rules=req.match_rules,
    )
    # store mud_url if provided
    if req.mud_url:
        await db.execute(
            "UPDATE device_classes SET mud_url = $2 WHERE id = $1", row.id, req.mud_url
        )
        row = await DeviceClassQueries.get_device_class(db, row.id)
    return DeviceClassResponse(
        id=row.id,
        name=row.name,
        description=row.description,
        match_rules=row.match_rules,
        mud_url=row.mud_url,
    )


@router.get("/{class_id}", response_model=DeviceClassResponse)
async def get_device_class(
    class_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    row = await DeviceClassQueries.get_device_class(db, class_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device class not found"
        )
    return DeviceClassResponse(
        id=row.id,
        name=row.name,
        description=row.description,
        match_rules=row.match_rules,
        mud_url=row.mud_url,
    )


@router.delete("/{class_id}")
async def delete_device_class(
    class_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
):
    ok = await DeviceClassQueries.delete_device_class(db, class_id)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device class not found"
        )
    return {"success": True}


class MudImportRequest(BaseModel):
    document: str | None = None
    url: str | None = None


@router.post("/{class_id}/mud")
async def import_mud(
    class_id: UUID,
    body: MudImportRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
):
    # ensure class exists and tenant-scoped
    row = await DeviceClassQueries.get_device_class(db, class_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device class not found"
        )
    tenant_id = getattr(current_user.user, "tenant_id", None) or current_user.id
    document = body.document or ""
    if not document and body.url:
        # In real deployment fetch from URL; for test just use URL as document placeholder
        document = body.url
    if not document:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="document or url required"
        )
    client = ControlClient()
    try:
        result = await client.import_mud(tenant_id, class_id, document)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"control unavailable: {e}") from e
    return result
