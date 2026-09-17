"""SCIM bearer token authentication.

SCIM tokens are long-lived bearer tokens (separate from JWT) created by
admins and given to identity providers. Tokens are stored as SHA-256 hashes.
"""

import hashlib
import secrets

import asyncpg
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from admin_api.db.connection import get_db
from admin_api.db.models import DbScimToken
from admin_api.db.queries import ScimTokenQueries

scim_bearer = HTTPBearer(auto_error=False)


def hash_token(token: str) -> bytes:
    """Hash a SCIM token with SHA-256; `scim_tokens.token_hash` is bytea."""
    return hashlib.sha256(token.encode()).digest()


def generate_token() -> str:
    """Generate a secure random SCIM token."""
    return secrets.token_urlsafe(48)


_SCOPE_RESOURCES = {"Users": "users", "Groups": "groups"}


def required_scope(request: Request) -> str | None:
    """The `<resource>:<read|write>` scope a SCIM request needs, or None for
    the discovery endpoints."""
    parts = request.url.path.split("/")
    resource = next((_SCOPE_RESOURCES[p] for p in parts if p in _SCOPE_RESOURCES), None)
    if resource is None:
        return None
    action = "read" if request.method in ("GET", "HEAD") else "write"
    return f"{resource}:{action}"


async def get_scim_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(scim_bearer),
    db: asyncpg.Connection = Depends(get_db),
) -> DbScimToken:
    """Validate the SCIM bearer token: 401 if unknown, revoked or expired,
    403 if it lacks the scope this request needs. Scopes the connection to
    the token's tenant so every query the request runs stays inside it."""
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
            detail="Invalid, revoked or expired SCIM token",
        )

    needed = required_scope(request)
    if needed and needed not in scim_token.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"SCIM token lacks the {needed} scope",
        )

    if scim_token.tenant_id is not None:
        await db.execute(
            "SELECT set_config('avon.tenant_id', $1, false)", str(scim_token.tenant_id)
        )
    return scim_token
