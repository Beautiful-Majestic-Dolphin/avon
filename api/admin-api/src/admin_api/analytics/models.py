"""Analytics data models."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class AnalyticsSnapshot(BaseModel):
    """Raw metric snapshot from Prometheus."""

    id: UUID
    metric_name: str
    metric_value: float
    labels: Optional[dict] = None
    collected_at: datetime


class AnalyticsHourly(BaseModel):
    """Hourly metric rollup."""

    id: UUID
    metric_name: str
    hour: datetime
    avg_value: Optional[float] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    sample_count: Optional[int] = None


class AnomalyEvent(BaseModel):
    """Detected anomaly event."""

    id: UUID
    metric_name: str
    severity: str
    current_value: float
    expected_value: float
    deviation: float
    message: Optional[str] = None
    detected_at: datetime
    acknowledged_at: Optional[datetime] = None


class TrendPoint(BaseModel):
    """A single point in a time-series trend."""

    timestamp: str
    value: float


class TrendResponse(BaseModel):
    """Time-series trend response."""

    metric: str
    period: str
    granularity: str
    data: list[TrendPoint]


class SecurityPostureResponse(BaseModel):
    """Aggregate security posture metrics."""

    total_devices: int
    active_devices: int
    suspended_devices: int
    revoked_devices: int
    health_percentage: float
    fido2_enrolled: int
    recent_enrollments_24h: int
    recent_suspensions_24h: int


class CapacityResponse(BaseModel):
    """Capacity and utilization metrics."""

    active_tunnels: int
    total_tunnels: int
    tunnel_utilization_percent: float
    total_bytes_transferred: int
    active_devices: int
    total_devices: int
    device_utilization_percent: float


class EnrollmentVelocityResponse(BaseModel):
    """Enrollment rate over time."""

    period: str
    data: list[TrendPoint]
    total_enrollments: int
    avg_per_day: float


class CryptoHealthResponse(BaseModel):
    """Certificate and cryptographic health metrics."""

    total_certificates: int
    active_certificates: int
    revoked_certificates: int
    expired_certificates: int
    total_rotations: int
    recent_rotations_24h: int
