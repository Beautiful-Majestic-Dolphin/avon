"""Pod schemas for AVON Admin API."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class PodResponse(BaseModel):
    """Pod summary response."""

    id: UUID
    name: str
    parent_id: UUID | None = None
    description: str | None = None
    device_count: int = 0
    created_at: datetime


class PodDetailResponse(BaseModel):
    """Detailed pod response."""

    id: UUID
    name: str
    parent_id: UUID | None = None
    description: str | None = None
    created_at: datetime
    updated_at: datetime
    device_count: int = 0
    child_pods: list["PodResponse"] = Field(default_factory=list)
    devices: list[UUID] = Field(default_factory=list)


class PodCreateRequest(BaseModel):
    """Pod creation request."""

    name: str = Field(..., min_length=1, max_length=255)
    parent_id: UUID | None = None
    description: str | None = Field(None, max_length=1000)


class PodUpdateRequest(BaseModel):
    """Pod update request."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=1000)


class PodDeviceRequest(BaseModel):
    """Request to add/remove device from pod."""

    device_id: UUID


class PodListResponse(BaseModel):
    """Pod list response with pagination."""

    items: list[PodResponse]
    total: int
    skip: int
    limit: int
    has_more: bool


class PodHierarchyResponse(BaseModel):
    """Pod hierarchy response."""

    id: UUID
    name: str
    description: str | None = None
    children: list["PodHierarchyResponse"] = Field(default_factory=list)
    device_count: int = 0


PodDetailResponse.model_rebuild()
PodHierarchyResponse.model_rebuild()
