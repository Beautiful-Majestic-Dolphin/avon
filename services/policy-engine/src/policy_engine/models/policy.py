"""Policy models for the AVON Policy Engine."""

from datetime import time
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class PolicyAction(str, Enum):
    """Policy action types."""

    ALLOW = "ALLOW"
    DENY = "DENY"


class TimeWindow(BaseModel):
    """Time-based access window."""

    start_time: time = Field(..., description="Start time (HH:MM)")
    end_time: time = Field(..., description="End time (HH:MM)")
    days_of_week: list[int] = Field(
        default_factory=lambda: [0, 1, 2, 3, 4, 5, 6],
        description="Days of week (0=Monday, 6=Sunday)",
    )
    timezone: str = "UTC"


class RequiredPosture(BaseModel):
    """Required device posture for policy evaluation."""

    firewall_enabled: Optional[bool] = None
    disk_encrypted: Optional[bool] = None
    antivirus_enabled: Optional[bool] = None
    screen_lock_enabled: Optional[bool] = None
    min_os_version: Optional[str] = None
    min_agent_version: Optional[str] = None
    max_hours_since_update_check: Optional[int] = None


class PolicyConditions(BaseModel):
    """Conditions that must be met for a policy to apply."""

    time_window: Optional[TimeWindow] = None
    required_posture: Optional[RequiredPosture] = None


class Policy(BaseModel):
    """Policy definition."""

    id: str = Field(..., description="Policy UUID")
    name: str = ""
    source_pod_id: str = Field(..., description="Source pod UUID")
    destination_pod_id: str = Field(..., description="Destination pod UUID")
    action: PolicyAction = PolicyAction.DENY
    priority: int = Field(default=100, description="Lower number = higher priority")
    enabled: bool = True
    conditions: Optional[PolicyConditions] = None
    description: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class PolicyDecision(BaseModel):
    """Result of policy evaluation."""

    action: PolicyAction
    policy_id: Optional[str] = None
    reason: str = ""
    evaluation_time_ms: float = 0.0
    matched_policies_count: int = 0
    source_pods: list[str] = Field(default_factory=list)
    destination_pods: list[str] = Field(default_factory=list)
