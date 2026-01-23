"""Device schemas for AVON Admin API."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class DevicePostureResponse(BaseModel):
    """Device posture information."""

    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    firewall_enabled: Optional[bool] = None
    disk_encrypted: Optional[bool] = None
    last_update_check: Optional[datetime] = None
    antivirus_enabled: Optional[bool] = None
    screen_lock_enabled: Optional[bool] = None


class DeviceResponse(BaseModel):
    """Device summary response."""

    id: UUID
    name: str
    status: str
    last_seen_at: Optional[datetime] = None
    last_pulse_at: Optional[datetime] = None
    enrolled_at: datetime
    pod_ids: list[UUID] = Field(default_factory=list)


class DeviceDetailResponse(BaseModel):
    """Detailed device response."""

    id: UUID
    name: str
    status: str
    hardware_fingerprint: str
    last_seen_at: Optional[datetime] = None
    last_pulse_at: Optional[datetime] = None
    last_known_ip: Optional[str] = None
    enrolled_at: datetime
    enrolled_by: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime
    pod_ids: list[UUID] = Field(default_factory=list)
    posture: Optional[DevicePostureResponse] = None
    active_tunnels: int = 0


class DeviceEnrollmentRequest(BaseModel):
    """Device enrollment request."""

    name: str = Field(..., min_length=1, max_length=255)
    device_type: str = Field(..., pattern="^(linux|windows|macos|ios|android)$")
    assigned_pods: list[UUID] = Field(default_factory=list)
    description: Optional[str] = None


class EnrollmentTokenResponse(BaseModel):
    """Enrollment token response."""

    token: str
    device_name: str
    device_type: str
    expires_at: datetime
    installation_url: str
    installation_instructions: str


class DeviceUpdateRequest(BaseModel):
    """Device update request."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    pod_ids: Optional[list[UUID]] = None


class DeviceSuspendRequest(BaseModel):
    """Device suspend request."""

    reason: Optional[str] = None


class DeviceListResponse(BaseModel):
    """Device list response with pagination."""

    items: list[DeviceResponse]
    total: int
    skip: int
    limit: int
    has_more: bool
