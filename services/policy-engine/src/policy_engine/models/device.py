"""Device models for the AVON Policy Engine."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class DevicePosture(BaseModel):
    """Device security posture information."""

    os_version: str = ""
    agent_version: str = ""
    firewall_enabled: bool = False
    disk_encrypted: bool = False
    last_update_check: Optional[datetime] = None
    antivirus_enabled: bool = False
    screen_lock_enabled: bool = False


class Device(BaseModel):
    """Device information."""

    id: str = Field(..., description="Device UUID")
    name: str = ""
    status: str = "active"
    pod_ids: list[str] = Field(default_factory=list)
    posture: Optional[DevicePosture] = None
    last_seen: Optional[datetime] = None
