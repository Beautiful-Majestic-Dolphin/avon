"""Policy schemas for AVON Admin API."""

from datetime import datetime, time
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class TimeWindowSchema(BaseModel):
    """Time window for policy conditions."""

    start_time: time
    end_time: time
    days_of_week: list[int] = Field(
        default_factory=lambda: [0, 1, 2, 3, 4, 5, 6],
        description="Days of week (0=Monday, 6=Sunday)",
    )
    timezone: str = "UTC"


class PostureRequirementSchema(BaseModel):
    """Device posture requirements for policy conditions."""

    min_os_version: Optional[str] = None
    min_agent_version: Optional[str] = None
    require_firewall: bool = False
    require_disk_encryption: bool = False
    max_days_since_update: Optional[int] = None
    require_antivirus: bool = False
    require_screen_lock: bool = False


class PolicyConditionsSchema(BaseModel):
    """Policy conditions."""

    time_window: Optional[TimeWindowSchema] = None
    posture_requirements: Optional[PostureRequirementSchema] = None


class PolicyResponse(BaseModel):
    """Policy summary response."""

    id: UUID
    name: str
    description: Optional[str] = None
    source_pod_id: UUID
    destination_pod_id: UUID
    action: str
    priority: int
    enabled: bool
    created_at: datetime


class PolicyDetailResponse(BaseModel):
    """Detailed policy response."""

    id: UUID
    name: str
    description: Optional[str] = None
    source_pod_id: UUID
    source_pod_name: Optional[str] = None
    destination_pod_id: UUID
    destination_pod_name: Optional[str] = None
    action: str
    priority: int
    enabled: bool
    conditions: Optional[PolicyConditionsSchema] = None
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None


class PolicyCreateRequest(BaseModel):
    """Policy creation request."""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    source_pod_id: UUID
    destination_pod_id: UUID
    action: str = Field(..., pattern="^(allow|deny)$")
    priority: int = Field(default=100, ge=1, le=10000)
    conditions: Optional[PolicyConditionsSchema] = None


class PolicyUpdateRequest(BaseModel):
    """Policy update request."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    action: Optional[str] = Field(None, pattern="^(allow|deny)$")
    priority: Optional[int] = Field(None, ge=1, le=10000)
    enabled: Optional[bool] = None
    conditions: Optional[PolicyConditionsSchema] = None


class PolicyListResponse(BaseModel):
    """Policy list response with pagination."""

    items: list[PolicyResponse]
    total: int
    skip: int
    limit: int
    has_more: bool


class PolicyEvaluationRequest(BaseModel):
    """Request to evaluate a policy."""

    source_device_id: UUID
    destination_device_id: UUID


class PolicyEvaluationResponse(BaseModel):
    """Policy evaluation result."""

    action: str
    policy_id: Optional[UUID] = None
    policy_name: Optional[str] = None
    reason: str
    evaluation_time_ms: float
