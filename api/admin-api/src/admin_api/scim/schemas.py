"""SCIM 2.0 request and response schemas (RFC 7643)."""

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field


# --- SCIM Core Schemas ---

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


class ScimName(BaseModel):
    """SCIM User name component."""

    formatted: Optional[str] = None
    familyName: Optional[str] = None
    givenName: Optional[str] = None


class ScimMeta(BaseModel):
    """SCIM resource metadata."""

    resourceType: str
    created: Optional[str] = None
    lastModified: Optional[str] = None
    location: Optional[str] = None


class ScimGroupRef(BaseModel):
    """Group reference in a SCIM User resource."""

    value: str
    display: Optional[str] = None
    ref: Optional[str] = Field(None, alias="$ref")


class ScimMemberRef(BaseModel):
    """Member reference in a SCIM Group resource."""

    value: str
    display: Optional[str] = None
    ref: Optional[str] = Field(None, alias="$ref")


# --- SCIM User ---

class ScimUserRequest(BaseModel):
    """SCIM User creation/replacement request."""

    schemas: list[str] = [SCIM_USER_SCHEMA]
    userName: str
    name: Optional[ScimName] = None
    displayName: Optional[str] = None
    active: bool = True
    externalId: Optional[str] = None
    password: Optional[str] = None


class ScimUserResponse(BaseModel):
    """SCIM User resource response."""

    schemas: list[str] = [SCIM_USER_SCHEMA]
    id: str
    userName: str
    name: Optional[ScimName] = None
    displayName: Optional[str] = None
    active: bool = True
    externalId: Optional[str] = None
    groups: list[ScimGroupRef] = []
    meta: ScimMeta


# --- SCIM Group ---

class ScimGroupRequest(BaseModel):
    """SCIM Group creation/replacement request."""

    schemas: list[str] = [SCIM_GROUP_SCHEMA]
    displayName: str
    externalId: Optional[str] = None
    members: list[ScimMemberRef] = []


class ScimGroupResponse(BaseModel):
    """SCIM Group resource response."""

    schemas: list[str] = [SCIM_GROUP_SCHEMA]
    id: str
    displayName: str
    externalId: Optional[str] = None
    members: list[ScimMemberRef] = []
    meta: ScimMeta


# --- SCIM List Response ---

class ScimListResponse(BaseModel):
    """SCIM paginated list response."""

    schemas: list[str] = [SCIM_LIST_SCHEMA]
    totalResults: int
    startIndex: int = 1
    itemsPerPage: int = 100
    Resources: list[dict] = Field(default_factory=list)


# --- SCIM PATCH ---

class ScimPatchOperation(BaseModel):
    """Single SCIM PATCH operation."""

    op: str
    path: Optional[str] = None
    value: Any = None


class ScimPatchRequest(BaseModel):
    """SCIM PATCH request body."""

    schemas: list[str] = [SCIM_PATCH_SCHEMA]
    Operations: list[ScimPatchOperation]


# --- SCIM Error ---

class ScimErrorResponse(BaseModel):
    """SCIM error response."""

    schemas: list[str] = [SCIM_ERROR_SCHEMA]
    detail: str
    status: str
    scimType: Optional[str] = None
