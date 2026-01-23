"""Database models for AVON Admin API."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class DbDevice(BaseModel):
    """Device database model."""

    id: UUID
    name: str
    hardware_fingerprint: bytes
    current_token: bytes
    previous_token: Optional[bytes] = None
    token_sequence: int = 0
    last_seen_at: Optional[datetime] = None
    last_pulse_at: Optional[datetime] = None
    last_known_ip: Optional[str] = None
    enrolled_at: datetime
    enrolled_by: Optional[UUID] = None
    status: str = "active"
    created_at: datetime
    updated_at: datetime


class DbPod(BaseModel):
    """Pod database model."""

    id: UUID
    name: str
    parent_id: Optional[UUID] = None
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class DbPolicy(BaseModel):
    """Policy database model."""

    id: UUID
    name: str
    description: Optional[str] = None
    source_pod_id: UUID
    destination_pod_id: UUID
    action: str  # "allow" or "deny"
    priority: int = 100
    enabled: bool = True
    conditions: Optional[dict] = None
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None


class DbUser(BaseModel):
    """User database model."""

    id: UUID
    email: str
    hashed_password: str
    full_name: Optional[str] = None
    is_active: bool = True
    is_admin: bool = False
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime] = None


class DbEnrollmentToken(BaseModel):
    """Enrollment token database model."""

    token: str
    device_id: Optional[UUID] = None
    device_name: str
    device_type: str
    assigned_pods: list[UUID]
    expires_at: datetime
    created_by: UUID
    consumed_at: Optional[datetime] = None
    created_at: datetime


class DbTunnel(BaseModel):
    """Tunnel database model."""

    id: UUID
    session_id: bytes
    source_device_id: UUID
    destination_device_id: UUID
    status: str  # "establishing", "active", "closing", "closed"
    established_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    created_at: datetime
    updated_at: datetime


class DbActivityLog(BaseModel):
    """Activity log database model."""

    id: UUID
    event_type: str
    actor_id: Optional[UUID] = None
    actor_type: str  # "user", "device", "system"
    target_id: Optional[UUID] = None
    target_type: Optional[str] = None
    details: Optional[dict] = None
    ip_address: Optional[str] = None
    created_at: datetime
