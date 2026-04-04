"""Common schemas for AVON Admin API."""

from datetime import datetime
from typing import Generic, TypeVar, Optional
from uuid import UUID

from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper."""

    items: list[T]
    total: int
    skip: int
    limit: int
    has_more: bool


class ErrorResponse(BaseModel):
    """Error response."""

    detail: str
    error_code: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SuccessResponse(BaseModel):
    """Generic success response."""

    success: bool = True
    message: str


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class TokenResponse(BaseModel):
    """Authentication token response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class MfaRequiredResponse(BaseModel):
    """Response when MFA is required to complete login."""

    mfa_required: bool = True
    mfa_token: str
    mfa_methods: list[str] = ["webauthn"]


class WebAuthnCredentialResponse(BaseModel):
    """Response for a registered WebAuthn credential."""

    id: UUID
    name: str
    created_at: datetime
    last_used_at: Optional[datetime] = None
    transports: list[str] = []


class LoginRequest(BaseModel):
    """Login request."""

    email: str
    password: str


class RefreshTokenRequest(BaseModel):
    """Refresh token request."""

    refresh_token: str


class UserResponse(BaseModel):
    """User response."""

    id: UUID
    email: str
    full_name: Optional[str] = None
    is_admin: bool
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None


class UserCreateRequest(BaseModel):
    """User creation request."""

    email: str
    password: str
    full_name: Optional[str] = None
    is_admin: bool = False


class UserUpdateRequest(BaseModel):
    """User update request."""

    email: Optional[str] = None
    full_name: Optional[str] = None
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None


class ChangePasswordRequest(BaseModel):
    """Change password request."""

    current_password: str
    new_password: str
