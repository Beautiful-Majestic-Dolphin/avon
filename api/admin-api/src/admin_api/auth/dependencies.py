"""FastAPI dependencies for authentication."""

from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import asyncpg
import structlog

from admin_api.auth.jwt import verify_token, TokenData
from admin_api.db.connection import get_db
from admin_api.db.queries import UserQueries
from admin_api.db.models import DbUser

logger = structlog.get_logger()

security = HTTPBearer(auto_error=False)


class CurrentUser:
    """Current authenticated user context."""

    def __init__(self, user: DbUser, token_data: TokenData):
        self.user = user
        self.token_data = token_data

    @property
    def id(self) -> UUID:
        return self.user.id

    @property
    def email(self) -> str:
        return self.user.email

    @property
    def is_admin(self) -> bool:
        return self.user.is_admin

    @property
    def full_name(self) -> Optional[str]:
        return self.user.full_name


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: asyncpg.Connection = Depends(get_db),
) -> CurrentUser:
    """Get the current authenticated user.
    
    Raises HTTPException if not authenticated.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = verify_token(credentials.credentials)
    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await UserQueries.get_user(db, token_data.user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    return CurrentUser(user=user, token_data=token_data)


async def get_current_admin(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """Get the current authenticated admin user.
    
    Raises HTTPException if not an admin.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: asyncpg.Connection = Depends(get_db),
) -> Optional[CurrentUser]:
    """Get the current user if authenticated, None otherwise.
    
    Does not raise exceptions for missing/invalid tokens.
    """
    if credentials is None:
        return None

    token_data = verify_token(credentials.credentials)
    if token_data is None:
        return None

    user = await UserQueries.get_user(db, token_data.user_id)
    if user is None or not user.is_active:
        return None

    return CurrentUser(user=user, token_data=token_data)
