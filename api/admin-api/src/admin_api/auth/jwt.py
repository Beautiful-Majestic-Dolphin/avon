"""JWT token handling for AVON Admin API."""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from jose import JWTError, jwt
from pydantic import BaseModel
import structlog

from admin_api.config import settings

logger = structlog.get_logger()


class TokenData(BaseModel):
    """Token payload data."""

    user_id: UUID
    email: str
    is_admin: bool = False
    exp: datetime
    token_type: str = "access"


class TokenPair(BaseModel):
    """Access and refresh token pair."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


def create_access_token(
    user_id: UUID,
    email: str,
    is_admin: bool = False,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT access token."""
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.jwt_access_token_expire_minutes)

    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {
        "sub": str(user_id),
        "email": email,
        "is_admin": is_admin,
        "exp": expire,
        "type": "access",
    }

    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return encoded_jwt


def create_refresh_token(
    user_id: UUID,
    email: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT refresh token."""
    if expires_delta is None:
        expires_delta = timedelta(days=settings.jwt_refresh_token_expire_days)

    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {
        "sub": str(user_id),
        "email": email,
        "exp": expire,
        "type": "refresh",
    }

    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return encoded_jwt


def create_token_pair(
    user_id: UUID,
    email: str,
    is_admin: bool = False,
) -> TokenPair:
    """Create both access and refresh tokens."""
    access_token = create_access_token(user_id, email, is_admin)
    refresh_token = create_refresh_token(user_id, email)

    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


def verify_token(token: str, expected_type: str = "access") -> Optional[TokenData]:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )

        token_type = payload.get("type", "access")
        if token_type != expected_type:
            logger.warning("token_type_mismatch", expected=expected_type, actual=token_type)
            return None

        user_id = payload.get("sub")
        email = payload.get("email")
        is_admin = payload.get("is_admin", False)
        exp = payload.get("exp")

        if user_id is None or email is None:
            logger.warning("token_missing_claims")
            return None

        return TokenData(
            user_id=UUID(user_id),
            email=email,
            is_admin=is_admin,
            exp=datetime.fromtimestamp(exp, tz=timezone.utc),
            token_type=token_type,
        )

    except JWTError as e:
        logger.warning("token_verification_failed", error=str(e))
        return None


def refresh_access_token(refresh_token: str) -> Optional[str]:
    """Create a new access token from a refresh token."""
    token_data = verify_token(refresh_token, expected_type="refresh")
    if token_data is None:
        return None

    return create_access_token(
        user_id=token_data.user_id,
        email=token_data.email,
        is_admin=token_data.is_admin,
    )


def create_mfa_token(
    user_id: UUID,
    email: str,
    is_admin: bool = False,
) -> str:
    """Create a short-lived MFA challenge token.

    Issued after password verification when the user has FIDO2 keys registered.
    This token proves password auth passed but FIDO2 key tap is still required.
    It cannot be used as an access token (type is 'mfa_challenge').
    """
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.mfa_token_expire_minutes
    )
    to_encode = {
        "sub": str(user_id),
        "email": email,
        "is_admin": is_admin,
        "exp": expire,
        "type": "mfa_challenge",
    }
    return jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def verify_mfa_token(token: str) -> Optional[TokenData]:
    """Verify an MFA challenge token. Returns None if invalid/expired."""
    return verify_token(token, expected_type="mfa_challenge")
