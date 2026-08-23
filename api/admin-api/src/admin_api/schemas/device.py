"""Device schemas for AVON Admin API."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class DevicePostureResponse(BaseModel):
    """Device posture information."""

    os_version: str | None = None
    agent_version: str | None = None
    firewall_enabled: bool | None = None
    disk_encrypted: bool | None = None
    last_update_check: datetime | None = None
    antivirus_enabled: bool | None = None
    screen_lock_enabled: bool | None = None


class DeviceResponse(BaseModel):
    """Device summary response."""

    id: UUID
    name: str
    status: str
    last_seen_at: datetime | None = None
    last_pulse_at: datetime | None = None
    enrolled_at: datetime
    pod_ids: list[UUID] = Field(default_factory=list)


class DeviceDetailResponse(BaseModel):
    """Detailed device response."""

    id: UUID
    name: str
    status: str
    hardware_fingerprint: str
    last_seen_at: datetime | None = None
    last_pulse_at: datetime | None = None
    last_known_ip: str | None = None
    enrolled_at: datetime
    enrolled_by: UUID | None = None
    created_at: datetime
    updated_at: datetime
    pod_ids: list[UUID] = Field(default_factory=list)
    posture: DevicePostureResponse | None = None
    active_tunnels: int = 0


class DeviceEnrollmentRequest(BaseModel):
    """Device enrollment request."""

    name: str = Field(..., min_length=1, max_length=255)
    device_type: str = Field(..., pattern="^(linux|windows|macos|ios|android)$")
    assigned_pods: list[UUID] = Field(default_factory=list)
    description: str | None = None
    require_fido2: bool = False


class EnrollTokenRequest(BaseModel):
    """Enroll token request for 4.12 — handles device_name, max_uses, etc."""

    device_name: str = Field(..., min_length=1, max_length=255, alias="device_name")
    device_type: str = Field(
        default="linux",
        pattern="^(linux|windows|macos|ios|android|agent|gateway|router|ikev2|agentless)$",
    )
    max_uses: int = Field(default=1, ge=1)
    expires_in_hours: int = Field(default=24, ge=1, alias="expires_in_hours")
    require_approval: bool = False
    assigned_pods: list[UUID] = Field(default_factory=list)
    # Compat with old name fields
    name: str | None = Field(default=None, min_length=1, max_length=255)
    require_fido2: bool = False

    model_config = {"populate_by_name": True}


class EnrollmentTokenResponse(BaseModel):
    """Enrollment token response."""

    token: str
    device_name: str
    device_type: str
    require_fido2: bool = False
    expires_at: datetime
    installation_url: str
    installation_instructions: str


class DeviceUpdateRequest(BaseModel):
    """Device update request."""

    name: str | None = Field(None, min_length=1, max_length=255)
    pod_ids: list[UUID] | None = None


class DeviceSuspendRequest(BaseModel):
    """Device suspend request."""

    reason: str | None = None


class DeviceListResponse(BaseModel):
    """Device list response with pagination."""

    items: list[DeviceResponse]
    total: int
    skip: int
    limit: int
    has_more: bool
