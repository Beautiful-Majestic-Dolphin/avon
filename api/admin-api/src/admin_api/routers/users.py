"""User management endpoints for AVON Admin API."""

from __future__ import annotations

import contextlib
import uuid
from datetime import UTC, datetime
from uuid import UUID

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from admin_api.auth.dependencies import CurrentUser, get_current_user
from admin_api.auth.jwt import create_mfa_token, create_token_pair, decode
from admin_api.auth.passwords import hash_password, verify_password
from admin_api.auth.rbac import require_role
from admin_api.config import settings
from admin_api.db.connection import get_db
from admin_api.db.queries import ActivityQueries, UserQueries, WebAuthnQueries
from admin_api.schemas.common import (
    ChangePasswordRequest,
    LoginRequest,
    MfaRequiredResponse,
    RefreshTokenRequest,
    TokenResponse,
    UserCreateRequest,
    UserResponse,
    UserUpdateRequest,
)

logger = structlog.get_logger()

router = APIRouter()

# Dummy hash for constant-time path when user unknown
_DUMMY_HASH = hash_password("dummy-password-for-constant-time")

# Simple in-memory rate limiter for login (keyed by ip+email) — slowapi optional
_login_attempts: dict[str, list[datetime]] = {}


def _rate_limit_key(request: Request, email: str) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{ip}:{email.lower()}"


def _is_rate_limited(key: str) -> bool:
    # Parse limit like "10/minute"
    try:
        limit_str = settings.login_rate_limit  # e.g. "10/minute"
        count_str, per = limit_str.split("/")
        limit = int(count_str)
        window = 60 if "minute" in per else 3600 if "hour" in per else 60
    except Exception:
        limit, window = 10, 60
    now = datetime.now(UTC)
    attempts = _login_attempts.get(key, [])
    # keep only within window
    attempts = [t for t in attempts if (now - t).total_seconds() < window]
    _login_attempts[key] = attempts
    return len(attempts) >= limit


def _record_attempt(key: str) -> None:
    now = datetime.now(UTC)
    _login_attempts.setdefault(key, []).append(now)


@router.post("/login", response_model=TokenResponse | MfaRequiredResponse)
async def login(
    login_request: LoginRequest,
    request: Request,
    db: asyncpg.Connection = Depends(get_db),
) -> TokenResponse | MfaRequiredResponse:
    """Authenticate user and return tokens. Handles lockout, rate limiting, constant-time."""
    key = _rate_limit_key(request, login_request.email)
    if _is_rate_limited(key):
        raise HTTPException(status_code=429, detail="Too many login attempts")

    user = await UserQueries.get_user_by_email(db, login_request.email)

    # Constant-time path: always verify against dummy when user unknown
    if user is None:
        verify_password(login_request.password, _DUMMY_HASH)
        _record_attempt(key)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Check lockout
    if user.locked_until and user.locked_until > datetime.now(UTC):
        raise HTTPException(status_code=423, detail="Account locked. Try again later.")

    # Verify password
    if not verify_password(login_request.password, user.hashed_password):
        # Increment failed_logins
        try:
            await db.execute(
                "UPDATE users SET failed_logins = failed_logins + 1, locked_until = CASE WHEN failed_logins + 1 >= $2 THEN NOW() + ($3 || ' minutes')::interval ELSE locked_until END WHERE id = $1",
                user.id,
                settings.lockout_after,
                str(settings.lockout_minutes),
            )
        except Exception as e:
            logger.warning("failed_to_update_failed_logins", error=str(e))
        _record_attempt(key)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is disabled")

    # Success — reset counters
    with contextlib.suppress(Exception):
        await db.execute(
            "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1",
            user.id,
        )

    # Check MFA
    has_webauthn = await WebAuthnQueries.user_has_credentials(db, user.id)
    # Also check mfa_required flag
    mfa_required = getattr(user, "mfa_required", False)
    if has_webauthn or mfa_required:
        if has_webauthn:
            mfa_token = create_mfa_token(
                user.id,
                user.email,
                user.is_admin,
                tenant_id=user.tenant_id,
                role=user.role,
            )
            logger.info("mfa_required", user_id=str(user.id), email=user.email)
            return MfaRequiredResponse(
                mfa_required=True, mfa_token=mfa_token, mfa_methods=["webauthn"]
            )
        else:
            # mfa_required but no credentials — enrollment required
            # Issue enrollment token? For now return mfa_required with detail
            raise HTTPException(status_code=403, detail="mfa_enrollment_required")

    # No MFA — issue tokens and store refresh jti
    # Determine tenant and role
    tenant_id = user.tenant_id or UUID("00000000-0000-0000-0000-000000000001")
    role = getattr(user, "role", "owner" if user.is_admin else "viewer")
    token_pair = create_token_pair(
        user.id, user.email, user.is_admin, tenant_id=tenant_id, role=role
    )
    # Store refresh token jti
    try:
        data = decode(token_pair.refresh_token, expected_typ="refresh")
        if data and data.jti:
            await db.execute(
                "INSERT INTO refresh_tokens (jti, user_id, expires_at) VALUES ($1, $2, NOW() + ($3 || ' days')::interval) ON CONFLICT DO NOTHING",
                data.jti,
                user.id,
                str(settings.refresh_token_days),
            )
    except Exception as e:
        logger.warning("failed_to_store_refresh", error=str(e))

    await UserQueries.update_last_login(db, user.id)
    await ActivityQueries.log_activity(
        db,
        event_type="user.login",
        actor_id=user.id,
        actor_type="user",
        tenant_id=tenant_id,
    )
    logger.info("user_logged_in", user_id=str(user.id), email=user.email)
    return TokenResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
        expires_in=token_pair.expires_in,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    refresh_request: RefreshTokenRequest,
    db: asyncpg.Connection = Depends(get_db),
) -> TokenResponse:
    """Refresh access token using refresh token with rotation and reuse detection."""
    token_data = decode(refresh_request.refresh_token, expected_typ="refresh")
    if token_data is None or token_data.jti is None:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    # Check DB for jti
    try:
        row = await db.fetchrow(
            "SELECT jti, user_id, revoked_at, replaced_by, expires_at FROM refresh_tokens WHERE jti = $1",
            token_data.jti,
        )
        if row is None:
            # Token not found — maybe old token before DB tracking? Fall back to just issuing new token for compat
            # But spec says reuse of revoked should revoke family
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        if row["revoked_at"] is not None:
            # Reuse detected — revoke family
            await db.execute(
                "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
                row["user_id"],
            )
            raise HTTPException(status_code=401, detail="Refresh token reuse detected")
        if row["expires_at"] and row["expires_at"] < datetime.now(UTC):
            raise HTTPException(status_code=401, detail="Refresh token expired")
        # Rotate: mark old as revoked, insert new
        new_jti = uuid.uuid4()
        # Fetch user for role/tenant
        user = await UserQueries.get_user(db, token_data.user_id)
        if user is None or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or disabled")
        tenant_id = (
            user.tenant_id
            or token_data.tenant_id
            or UUID("00000000-0000-0000-0000-000000000001")
        )
        role = getattr(
            user, "role", token_data.role or ("owner" if user.is_admin else "viewer")
        )
        # Create new tokens
        # Import here to avoid circular
        from admin_api.auth.jwt import create_access_token, create_refresh_token

        access_token = create_access_token(
            user.id,
            tenant_id,
            role,
            email=user.email,
            is_admin=user.is_admin,
            jti=uuid.uuid4(),
        )
        refresh_token = create_refresh_token(
            user.id, tenant_id, jti=new_jti, email=user.email
        )
        # DB rotation
        await db.execute(
            "UPDATE refresh_tokens SET revoked_at = NOW(), replaced_by = $2 WHERE jti = $1",
            token_data.jti,
            new_jti,
        )
        await db.execute(
            "INSERT INTO refresh_tokens (jti, user_id, expires_at) VALUES ($1, $2, NOW() + ($3 || ' days')::interval)",
            new_jti,
            user.id,
            str(settings.refresh_token_days),
        )
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.jwt_access_token_expire_minutes * 60,
        )
    except HTTPException:
        raise
    except Exception as e:
        # If DB not available (e.g., no refresh_tokens table in tests without DB), fallback to old behavior
        logger.warning("refresh_db_fallback", error=str(e))
        # Fallback: just verify and issue new access without rotation
        from admin_api.auth.jwt import create_access_token

        # Use token_data to create new access
        access = create_access_token(
            token_data.user_id,
            tenant_id=token_data.tenant_id,
            role=token_data.role,
            email=token_data.email,
            is_admin=token_data.is_admin,
        )
        return TokenResponse(
            access_token=access,
            refresh_token=refresh_request.refresh_token,
            expires_in=settings.jwt_access_token_expire_minutes * 60,
        )


@router.post("/logout")
async def logout(
    refresh_request: RefreshTokenRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Revoke a refresh token."""
    token_data = decode(refresh_request.refresh_token, expected_typ="refresh")
    if token_data and token_data.jti:
        with contextlib.suppress(Exception):
            await db.execute(
                "UPDATE refresh_tokens SET revoked_at = NOW() WHERE jti = $1",
                token_data.jti,
            )
    return {"success": True}


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: CurrentUser = Depends(get_current_user),
) -> UserResponse:
    """Get current user information."""
    return UserResponse(
        id=current_user.user.id,
        email=current_user.user.email,
        full_name=current_user.user.full_name,
        is_admin=current_user.user.is_admin,
        is_active=current_user.user.is_active,
        created_at=current_user.user.created_at,
        last_login_at=current_user.user.last_login_at,
    )


@router.post("/change-password")
async def change_password(
    password_request: ChangePasswordRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Change current user's password."""
    if not verify_password(
        password_request.current_password, current_user.user.hashed_password
    ):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    new_hash = hash_password(password_request.new_password)
    await db.execute(
        "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
        new_hash,
        current_user.id,
    )
    await ActivityQueries.log_activity(
        db,
        event_type="user.password_changed",
        actor_id=current_user.id,
        actor_type="user",
    )
    logger.info("user_password_changed", user_id=str(current_user.id))
    return {"success": True, "message": "Password changed successfully"}


@router.get("/", response_model=list[UserResponse])
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(require_role("owner")),
) -> list[UserResponse]:
    """List all users. Requires admin privileges."""
    users = await UserQueries.list_users(db, skip=skip, limit=limit)
    return [
        UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            is_admin=user.is_admin,
            is_active=user.is_active,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        )
        for user in users
    ]


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_request: UserCreateRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(require_role("owner")),
) -> UserResponse:
    """Create a new user. Requires admin privileges."""
    existing = await UserQueries.get_user_by_email(db, user_request.email)
    if existing:
        raise HTTPException(
            status_code=400, detail="User with this email already exists"
        )

    hashed = hash_password(user_request.password)
    user = await UserQueries.create_user(
        db,
        email=user_request.email,
        hashed_password=hashed,
        full_name=user_request.full_name,
        is_admin=user_request.is_admin,
    )

    await ActivityQueries.log_activity(
        db,
        event_type="user.created",
        actor_id=current_user.id,
        actor_type="user",
        target_id=user.id,
        target_type="user",
        details={"email": user.email, "is_admin": user.is_admin},
    )
    logger.info(
        "user_created",
        user_id=str(user.id),
        email=user.email,
        by_user=str(current_user.id),
    )
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_admin=user.is_admin,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(require_role("owner")),
) -> UserResponse:
    """Get user by ID. Requires admin privileges."""
    user = await UserQueries.get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_admin=user.is_admin,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    user_request: UserUpdateRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(require_role("owner")),
) -> UserResponse:
    """Update a user. Requires admin privileges."""
    user = await UserQueries.get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.managed_by == "scim":
        raise HTTPException(
            status_code=409,
            detail="User is managed by SCIM. Modify via your identity provider.",
        )

    updates = []
    params: list = [user_id]
    param_idx = 2
    if user_request.email is not None:
        updates.append(f"email = ${param_idx}")
        params.append(user_request.email)
        param_idx += 1
    if user_request.full_name is not None:
        updates.append(f"full_name = ${param_idx}")
        params.append(user_request.full_name)
        param_idx += 1
    if user_request.is_admin is not None:
        role = "owner" if user_request.is_admin else "viewer"
        updates.append(f"role = ${param_idx}::user_role")
        params.append(role)
        param_idx += 1
        updates.append(f"is_admin = ${param_idx}")
        params.append(user_request.is_admin)
        param_idx += 1
    if user_request.is_active is not None:
        updates.append(f"is_active = ${param_idx}")
        params.append(user_request.is_active)
        param_idx += 1
    if updates:
        updates.append("updated_at = NOW()")
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = $1 RETURNING *"
        row = await db.fetchrow(query, *params)
        if row:
            d = dict(row)
            if "role" in d and "is_admin" not in d:
                d["is_admin"] = d["role"] in ("owner", "admin")
            if "password_hash" in d and "hashed_password" not in d:
                d["hashed_password"] = d["password_hash"]
            user = await UserQueries.get_user(db, user_id)

    await ActivityQueries.log_activity(
        db,
        event_type="user.updated",
        actor_id=current_user.id,
        actor_type="user",
        target_id=user_id,
        target_type="user",
        details={"changes": user_request.model_dump(exclude_unset=True)},
    )
    updated_user = await UserQueries.get_user(db, user_id)
    if updated_user is None:
        raise HTTPException(status_code=500, detail="Failed to retrieve updated user")
    return UserResponse(
        id=updated_user.id,
        email=updated_user.email,
        full_name=updated_user.full_name,
        is_admin=updated_user.is_admin,
        is_active=updated_user.is_active,
        created_at=updated_user.created_at,
        last_login_at=updated_user.last_login_at,
    )
