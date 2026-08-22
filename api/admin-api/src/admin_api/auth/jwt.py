"""JWT token handling for AVON Admin API — PyJWT, HS256, strict issuer."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt as pyjwt
import structlog
from pydantic import BaseModel

from admin_api.config import settings

logger = structlog.get_logger()

# Dummy Argon2 hash for constant-time path when user is unknown
_DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy"


class TokenData(BaseModel):
    """Token payload data — superset for compat."""

    user_id: UUID
    tenant_id: UUID | None = None
    role: str | None = None
    email: str | None = None
    is_admin: bool = False
    exp: datetime
    token_type: str = "access"
    jti: UUID | None = None
    typ: str | None = None


class TokenPair(BaseModel):
    """Access and refresh token pair."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


def _secret() -> str:
    return (
        settings.jwt_secret_key.get_secret_value()
        if hasattr(settings.jwt_secret_key, "get_secret_value")
        else str(settings.jwt_secret_key)
    )


def _issuer() -> str:
    return getattr(settings, "jwt_issuer", "avon-admin")


def _now() -> datetime:
    return datetime.now(UTC)


def create_access_token(
    user_id: UUID,
    tenant_id: UUID | None = None,
    role: str | None = None,
    email: str | None = None,
    is_admin: bool = False,
    expires_delta: timedelta | None = None,
    jti: UUID | None = None,
    tenant: UUID | None = None,
    **kwargs,
) -> str:
    """Create a JWT access token. Supports both new (tenant_id/role) and legacy (email/is_admin) signatures."""
    # Legacy: create_access_token(user_id, email, is_admin) or (user_id, email)
    if isinstance(tenant_id, str):
        # If second arg looks like email, treat as legacy
        is_email_like = "@" in tenant_id or "." in tenant_id
        # role could be bool in legacy position 3
        if isinstance(role, bool):
            is_admin = role
            email = tenant_id  # type: ignore
            tenant_id = None
            role = None
        elif is_email_like:
            email = tenant_id  # type: ignore
            tenant_id = None
            # role may be None, keep is_admin as is
        # else: tenant_id is str uuid? but we expect UUID, so treat as tid string
        if isinstance(tenant_id, str):
            import contextlib

            with contextlib.suppress(Exception):
                tenant_id = UUID(tenant_id)  # type: ignore
    if isinstance(role, bool):
        is_admin = role
        role = None
    if isinstance(email, bool):
        is_admin = email  # type: ignore
        email = None
    # Handle kwargs: email=, is_admin=, tenant_id=
    if "email" in kwargs:
        email = kwargs.pop("email")
    if "is_admin" in kwargs:
        is_admin = kwargs.pop("is_admin")
    if "tenant_id" in kwargs and tenant_id is None:
        tenant_id = kwargs.pop("tenant_id")
    if tenant is not None and tenant_id is None:
        tenant_id = tenant
    if tenant_id is None:
        tenant_id = UUID("00000000-0000-0000-0000-000000000000")
    if isinstance(tenant_id, str):
        import contextlib

        with contextlib.suppress(Exception):
            tenant_id = UUID(tenant_id)
        if isinstance(tenant_id, str):
            tenant_id = UUID("00000000-0000-0000-0000-000000000000")

    if role is None:
        role = "owner" if is_admin else "viewer"
    if expires_delta is None:
        minutes = getattr(
            settings,
            "jwt_access_token_expire_minutes",
            getattr(settings, "access_token_minutes", 15),
        )
        expires_delta = timedelta(minutes=minutes)

    now = _now()
    exp = now + expires_delta
    jti_val = jti or uuid.uuid4()
    payload = {
        "sub": str(user_id),
        "tid": str(tenant_id),
        "role": role,
        "iss": _issuer(),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(jti_val),
        "typ": "access",
        "type": "access",
    }
    if email:
        payload["email"] = email
        payload["is_admin"] = is_admin
    return pyjwt.encode(payload, _secret(), algorithm="HS256")


def create_refresh_token(
    user_id: UUID,
    tenant_id: UUID | None = None,
    jti: UUID | None = None,
    email: str | None = None,
    expires_delta: timedelta | None = None,
    **kwargs,
) -> str:
    """Create a JWT refresh token."""
    if isinstance(tenant_id, str) and email is None:
        email = tenant_id  # type: ignore
        tenant_id = None
    if "email" in kwargs:
        email = kwargs.pop("email")
    if tenant_id is None and "tenant_id" in kwargs:
        tenant_id = kwargs.pop("tenant_id")
    if tenant_id is None:
        tenant_id = UUID("00000000-0000-0000-0000-000000000000")
    if expires_delta is None:
        days = getattr(
            settings,
            "jwt_refresh_token_expire_days",
            getattr(settings, "refresh_token_days", 7),
        )
        expires_delta = timedelta(days=days)
    now = _now()
    exp = now + expires_delta
    jti_val = jti or uuid.uuid4()
    payload = {
        "sub": str(user_id),
        "tid": str(tenant_id),
        "iss": _issuer(),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(jti_val),
        "typ": "refresh",
        "type": "refresh",
    }
    if email:
        payload["email"] = email
    return pyjwt.encode(payload, _secret(), algorithm="HS256")


def create_token_pair(
    user_id: UUID,
    email: str | None = None,
    is_admin: bool = False,
    tenant_id: UUID | None = None,
    role: str | None = None,
) -> TokenPair:
    """Create both access and refresh tokens."""
    if tenant_id is None:
        tenant_id = UUID("00000000-0000-0000-0000-000000000000")
    if role is None:
        role = "owner" if is_admin else "viewer"
    # Support legacy where first param is user_id, second is email
    # Already handled
    access_token = create_access_token(
        user_id, tenant_id, role, email=email, is_admin=is_admin
    )
    refresh_token = create_refresh_token(user_id, tenant_id, email=email)
    minutes = getattr(
        settings,
        "jwt_access_token_expire_minutes",
        getattr(settings, "access_token_minutes", 15),
    )
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=minutes * 60,
    )


def decode(token: str, expected_typ: str = "access") -> TokenData | None:
    """Decode and verify a JWT. Checks HS256, issuer, exp with 10s leeway, typ."""
    try:
        payload = pyjwt.decode(
            token,
            _secret(),
            algorithms=["HS256"],
            issuer=_issuer(),
            leeway=10,
            options={"require": ["exp", "iss", "iat", "jti", "typ"]},
        )
    except pyjwt.InvalidTokenError as e:
        logger.warning("token_verification_failed", error=str(e))
        return None
    typ = payload.get("typ") or payload.get("type")
    if typ != expected_typ:
        logger.warning("token_type_mismatch", expected=expected_typ, actual=typ)
        return None
    try:
        sub = payload.get("sub")
        tid = payload.get("tid")
        exp = payload.get("exp")
        jti = payload.get("jti")
        if sub is None or exp is None:
            return None
        return TokenData(
            user_id=UUID(str(sub)),
            tenant_id=UUID(str(tid)) if tid else None,
            role=payload.get("role"),
            email=payload.get("email"),
            is_admin=payload.get("is_admin", False) or payload.get("role") == "owner",
            exp=datetime.fromtimestamp(int(exp), tz=UTC),
            token_type=typ,
            jti=UUID(str(jti)) if jti else None,
            typ=typ,
        )
    except Exception as e:
        logger.warning("token_missing_claims", error=str(e))
        return None


# Legacy aliases
def verify_token(token: str, expected_type: str = "access") -> TokenData | None:
    return decode(token, expected_typ=expected_type)


def refresh_access_token(refresh_token: str) -> str | None:
    token_data = decode(refresh_token, expected_typ="refresh")
    if token_data is None:
        return None
    # For legacy callers that expect email/is_admin preserved
    return create_access_token(
        token_data.user_id,
        tenant_id=token_data.tenant_id,
        role=token_data.role,
        email=token_data.email,
        is_admin=token_data.is_admin,
    )


def create_mfa_token(
    user_id: UUID,
    email: str | None = None,
    is_admin: bool = False,
    tenant_id: UUID | None = None,
    role: str | None = None,
) -> str:
    """Short-lived MFA challenge token typ=mfa."""
    if tenant_id is None:
        tenant_id = UUID("00000000-0000-0000-0000-000000000000")
    if role is None:
        role = "owner" if is_admin else "viewer"
    now = _now()
    exp = now + timedelta(minutes=getattr(settings, "mfa_token_expire_minutes", 5))
    payload = {
        "sub": str(user_id),
        "tid": str(tenant_id),
        "role": role,
        "iss": _issuer(),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(uuid.uuid4()),
        "typ": "mfa",
        "type": "mfa_challenge",
    }
    if email:
        payload["email"] = email
        payload["is_admin"] = is_admin
    return pyjwt.encode(payload, _secret(), algorithm="HS256")


def verify_mfa_token(token: str) -> TokenData | None:
    # Accept both typ=mfa and type=mfa_challenge for compat
    data = decode(token, expected_typ="mfa")
    if data is not None:
        return data
    return decode(token, expected_typ="mfa_challenge")
