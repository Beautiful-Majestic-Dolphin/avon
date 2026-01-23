"""User management endpoints for AVON Admin API."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from passlib.context import CryptContext
import asyncpg
import structlog

from admin_api.auth.dependencies import get_current_user, get_current_admin, CurrentUser
from admin_api.auth.jwt import create_token_pair, refresh_access_token
from admin_api.db.connection import get_db
from admin_api.db.queries import UserQueries, ActivityQueries
from admin_api.schemas.common import (
    TokenResponse,
    LoginRequest,
    RefreshTokenRequest,
    UserResponse,
    UserCreateRequest,
    UserUpdateRequest,
    ChangePasswordRequest,
)

logger = structlog.get_logger()

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


@router.post("/login", response_model=TokenResponse)
async def login(
    login_request: LoginRequest,
    db: asyncpg.Connection = Depends(get_db),
) -> TokenResponse:
    """Authenticate user and return tokens."""
    user = await UserQueries.get_user_by_email(db, login_request.email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not verify_password(login_request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    await UserQueries.update_last_login(db, user.id)

    token_pair = create_token_pair(user.id, user.email, user.is_admin)

    await ActivityQueries.log_activity(
        db,
        event_type="user.login",
        actor_id=user.id,
        actor_type="user",
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
    """Refresh access token using refresh token."""
    new_access_token = refresh_access_token(refresh_request.refresh_token)
    if new_access_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    from admin_api.auth.jwt import verify_token
    from admin_api.config import settings

    token_data = verify_token(refresh_request.refresh_token, expected_type="refresh")
    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=refresh_request.refresh_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


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
    if not verify_password(password_request.current_password, current_user.user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    new_hash = hash_password(password_request.new_password)
    await db.execute(
        "UPDATE users SET hashed_password = $1, updated_at = NOW() WHERE id = $2",
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
    current_user: CurrentUser = Depends(get_current_admin),
) -> list[UserResponse]:
    """List all users.
    
    Requires admin privileges.
    """
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
    current_user: CurrentUser = Depends(get_current_admin),
) -> UserResponse:
    """Create a new user.
    
    Requires admin privileges.
    """
    existing = await UserQueries.get_user_by_email(db, user_request.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists",
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

    logger.info("user_created", user_id=str(user.id), email=user.email, by_user=str(current_user.id))

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
    current_user: CurrentUser = Depends(get_current_admin),
) -> UserResponse:
    """Get user by ID.
    
    Requires admin privileges.
    """
    user = await UserQueries.get_user(db, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
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


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    user_request: UserUpdateRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> UserResponse:
    """Update a user.
    
    Requires admin privileges.
    """
    user = await UserQueries.get_user(db, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
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
        updates.append(f"is_admin = ${param_idx}")
        params.append(user_request.is_admin)
        param_idx += 1

    if user_request.is_active is not None:
        updates.append(f"is_active = ${param_idx}")
        params.append(user_request.is_active)
        param_idx += 1

    if updates:
        updates.append("updated_at = NOW()")
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = $1"
        await db.execute(query, *params)

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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve updated user",
        )

    return UserResponse(
        id=updated_user.id,
        email=updated_user.email,
        full_name=updated_user.full_name,
        is_admin=updated_user.is_admin,
        is_active=updated_user.is_active,
        created_at=updated_user.created_at,
        last_login_at=updated_user.last_login_at,
    )
