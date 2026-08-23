"""Policy schemas for AVON Admin API — v2 spec with JSON Schema contract."""

from datetime import datetime, time
from uuid import UUID

from pydantic import BaseModel, Field


# Legacy schemas retained for backward compatibility with existing tests.
class TimeWindowSchema(BaseModel):
    """Time window for policy conditions (legacy)."""

    start_time: time
    end_time: time
    days_of_week: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4, 5, 6])
    timezone: str = "UTC"


class PostureRequirementSchema(BaseModel):
    """Device posture requirements (legacy)."""

    min_os_version: str | None = None
    min_agent_version: str | None = None
    require_firewall: bool = False
    require_disk_encryption: bool = False
    max_days_since_update: int | None = None
    require_antivirus: bool = False
    require_screen_lock: bool = False


class PolicyConditionsSchema(BaseModel):
    """Policy conditions (legacy)."""

    time_window: TimeWindowSchema | None = None
    posture_requirements: PostureRequirementSchema | None = None


class PolicyResponse(BaseModel):
    """Policy summary response."""

    id: UUID
    name: str
    description: str | None = None
    enabled: bool
    priority: int
    spec: dict
    version: int
    created_at: datetime
    updated_at: datetime


class PolicyDetailResponse(BaseModel):
    """Detailed policy response."""

    id: UUID
    name: str
    description: str | None = None
    enabled: bool
    priority: int
    spec: dict
    version: int
    created_at: datetime
    updated_at: datetime
    created_by: UUID | None = None


class PolicyCreateRequest(BaseModel):
    """Policy creation request — spec is validated against docs/policy-schema.json.
    Supports both v2 (spec dict) and legacy pod-based fields for backward compat.
    """

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=1000)
    enabled: bool = True
    spec: dict | None = Field(None, description="PolicySpec v2 JSON")
    # legacy fields
    source_pod_id: UUID | None = None
    destination_pod_id: UUID | None = None
    action: str | None = Field(None, pattern="^(allow|deny)$")
    priority: int | None = Field(None, ge=0, le=10000)
    conditions: PolicyConditionsSchema | None = None

    model_config = {"extra": "ignore"}


class PolicyUpdateRequest(BaseModel):
    """Policy update request."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=1000)
    enabled: bool | None = None
    spec: dict | None = None
    priority: int | None = Field(None, ge=0, le=10000)


class PolicyListResponse(BaseModel):
    """Policy list response with pagination."""

    items: list[PolicyResponse]
    total: int
    skip: int
    limit: int
    has_more: bool


class ExplainRequest(BaseModel):
    """Explain a flow decision."""

    device_id: UUID
    destination: str
    protocol: str = Field(..., pattern="^(tcp|udp|icmp|any)$")
    port: int = Field(..., ge=1, le=65535)


class ExplainResponse(BaseModel):
    """Explain response from AdminService."""

    allow: bool
    reason: str
    matched_policies: list[str] = Field(default_factory=list)
    cedar: str = ""


class CedarResponse(BaseModel):
    """Cedar debug response."""

    cedar: str
    policy_id: UUID
