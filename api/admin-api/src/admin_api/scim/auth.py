"""SCIM bearer token authentication.

SCIM tokens are long-lived bearer tokens (separate from JWT) created by
admins and given to identity providers. Tokens are stored as SHA-256 hashes.
"""

import hashlib
import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import asyncpg

from admin_api.db.connection import get_db
from admin_api.db.queries import ScimTokenQueries

scim_bearer = HTTPBearer(auto_error=False)


def hash_token(token: str) -> str:
    """Hash a SCIM token with SHA-256."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token() -> str:
    """Generate a secure random SCIM token."""
    return secrets.token_urlsafe(48)


async def get_scim_auth(
    credentials: HTTPAuthorizationCredentials = Depends(scim_bearer),
    db: asyncpg.Connection = Depends(get_db),
) -> None:
    """Validate SCIM bearer token. Raises 401 if invalid."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SCIM authentication required",
        )

    token_hash = hash_token(credentials.credentials)
    scim_token = await ScimTokenQueries.get_active_by_hash(db, token_hash)

    if scim_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked SCIM token",
        )
