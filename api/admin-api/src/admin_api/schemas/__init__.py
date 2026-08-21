"""Pydantic schemas for AVON Admin API."""

from admin_api.schemas.common import (
    ErrorResponse,
    PaginatedResponse,
    SuccessResponse,
)
from admin_api.schemas.device import (
    DeviceDetailResponse,
    DeviceEnrollmentRequest,
    DeviceResponse,
    DeviceUpdateRequest,
    EnrollmentTokenResponse,
)
from admin_api.schemas.pod import (
    PodCreateRequest,
    PodDetailResponse,
    PodResponse,
    PodUpdateRequest,
)
from admin_api.schemas.policy import (
    PolicyConditionsSchema,
    PolicyCreateRequest,
    PolicyDetailResponse,
    PolicyResponse,
    PolicyUpdateRequest,
    PostureRequirementSchema,
    TimeWindowSchema,
)

__all__ = [
    "DeviceDetailResponse",
    "DeviceEnrollmentRequest",
    "DeviceResponse",
    "DeviceUpdateRequest",
    "EnrollmentTokenResponse",
    "ErrorResponse",
    "PaginatedResponse",
    "PodCreateRequest",
    "PodDetailResponse",
    "PodResponse",
    "PodUpdateRequest",
    "PolicyConditionsSchema",
    "PolicyCreateRequest",
    "PolicyDetailResponse",
    "PolicyResponse",
    "PolicyUpdateRequest",
    "PostureRequirementSchema",
    "SuccessResponse",
    "TimeWindowSchema",
]
