"""Database models for AVON Admin API."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


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
    created_at: datetime
    updated_at: datetime


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
    """Policy database model."""

    id: UUID
    name: str
    description: str | None = None
    source_pod_id: UUID
    destination_pod_id: UUID
    action: str  # "allow" or "deny"
    priority: int = 100
    enabled: bool = True
    conditions: dict | None = None
    created_at: datetime
    updated_at: datetime
    created_by: UUID | None = None


class DbUser(BaseModel):
    """User database model."""

    id: UUID
    email: str
    hashed_password: str
    full_name: str | None = None
    is_active: bool = True
    is_admin: bool = False
    external_id: str | None = None
    managed_by: str = "local"
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = None


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

    token: str
    device_id: UUID | None = None
    device_name: str
    device_type: str
    assigned_pods: list[UUID]
    require_fido2: bool = False
    expires_at: datetime
    created_by: UUID
    consumed_at: datetime | None = None
    created_at: datetime


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
    """SCIM bearer token database model."""

    id: UUID
    token_hash: str
    description: str
    created_by: UUID
    created_at: datetime
    last_used_at: datetime | None = None
    is_active: bool = True


class DbActivityLog(BaseModel):
    """Activity log database model."""

    id: UUID
    event_type: str
    actor_id: UUID | None = None
    actor_type: str  # "user", "device", "system"
    target_id: UUID | None = None
    target_type: str | None = None
    details: dict | None = None
    ip_address: str | None = None
    created_at: datetime
