"""Database models for AVON Admin API."""

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


def _as_dict(value: Any) -> Any:
    """asyncpg hands JSONB back as text unless a codec is registered, and the
    codec would change how every existing insert is encoded. Decoding on the way
    into the model keeps that blast radius at zero."""
    if isinstance(value, (str, bytes)):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return None
    return value


class DbDevice(BaseModel):
    """Device database model."""

    id: UUID
    name: str
    hardware_fingerprint: bytes
    current_token: bytes
    previous_token: bytes | None = None
    token_sequence: int = 0
    last_seen_at: datetime | None = None
    last_pulse_at: datetime | None = None
    last_known_ip: str | None = None
    enrolled_at: datetime
    enrolled_by: UUID | None = None
    status: str = "active"
    # Device trust: what the control plane made of this device's last quote,
    # and the evidence it recorded.
    attestation_state: str = "none"
    attestation: dict | None = None
    posture: dict | None = None
    risk_score: int | None = None
    created_at: datetime
    updated_at: datetime

    @field_validator("attestation", "posture", mode="before")
    @classmethod
    def _decode_json(cls, value: Any) -> Any:
        return _as_dict(value)


class DbPod(BaseModel):
    """Pod database model."""

    id: UUID
    name: str
    parent_id: UUID | None = None
    description: str | None = None
    external_id: str | None = None
    managed_by: str = "local"
    created_at: datetime
    updated_at: datetime


class DbPolicy(BaseModel):
    """Policy database model — v2 stores spec JSONB."""

    id: UUID
    tenant_id: UUID | None = None
    name: str
    description: str | None = None
    enabled: bool = True
    priority: int = 100
    spec: dict = Field(default_factory=dict)
    version: int = 1
    created_at: datetime
    updated_at: datetime
    created_by: UUID | None = None
    # legacy columns for backward compat
    source_pod_id: UUID | None = None
    destination_pod_id: UUID | None = None
    action: str | None = None
    conditions: dict | None = None

    model_config = {"extra": "ignore"}


class DbDeviceClass(BaseModel):
    """Device class database model."""

    id: UUID
    tenant_id: UUID
    name: str
    description: str | None = None
    match_rules: dict = Field(default_factory=dict)
    mud_url: str | None = None
    created_at: datetime
    updated_at: datetime


class DbUser(BaseModel):
    """User database model."""

    id: UUID
    email: str
    hashed_password: str = Field(validation_alias="password_hash")
    full_name: str | None = None
    is_active: bool = True
    is_admin: bool = False
    tenant_id: UUID | None = None
    role: str = "viewer"
    external_id: str | None = None
    managed_by: str = "local"
    mfa_required: bool = False
    failed_logins: int = 0
    locked_until: datetime | None = None
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = None

    model_config = {"populate_by_name": True, "extra": "ignore"}


class DbWebAuthnCredential(BaseModel):
    """WebAuthn credential database model."""

    id: UUID
    user_id: UUID
    credential_id: bytes
    public_key: bytes
    sign_count: int = 0
    transports: list[str] = []
    aaguid: bytes | None = None
    name: str = "Security Key"
    created_at: datetime
    last_used_at: datetime | None = None


class DbEnrollmentToken(BaseModel):
    """Enrollment token database model."""

    id: UUID
    tenant_id: UUID
    token_hash: bytes
    device_name: str | None = None
    device_type: str | None = None
    device_kind: str | None = None
    assigned_pods: list[UUID] | None = None
    pod_ids: list[UUID] | None = None
    require_fido2: bool = False
    require_approval: bool = False
    max_uses: int = 1
    use_count: int = 0
    expires_at: datetime
    created_by: UUID | None = None
    consumed_at: datetime | None = None
    created_at: datetime
    last_used_at: datetime | None = None


class DbTunnel(BaseModel):
    """Tunnel database model."""

    id: UUID
    session_id: bytes
    source_device_id: UUID
    destination_device_id: UUID
    status: str  # "establishing", "active", "closing", "closed"
    established_at: datetime | None = None
    closed_at: datetime | None = None
    bytes_sent: int = 0
    bytes_received: int = 0
    created_at: datetime
    updated_at: datetime


class DbScimToken(BaseModel):
    """SCIM Bearer token database model."""

    id: UUID
    token_hash: str
    description: str
    created_by: UUID
    created_at: datetime
    last_used_at: datetime | None = None
    is_active: bool = True


class DbActivityLog(BaseModel):
    """Activity log database model."""

    id: int  # activity_logs.id is BIGSERIAL, not a UUID
    event_type: str
    actor_id: UUID | None = None
    actor_type: str  # "user", "device", "system"
    target_id: UUID | None = None
    target_type: str | None = None
    details: dict | None = None
    ip_address: str | None = None
    created_at: datetime
