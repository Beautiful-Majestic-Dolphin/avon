"""SCIM token management endpoints for AVON Admin API.

Allows administrators to create, list, and revoke SCIM bearer tokens
that identity providers use to authenticate to the SCIM API.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
import asyncpg
import structlog

from admin_api.auth.dependencies import get_current_admin, CurrentUser
from admin_api.db.connection import get_db
from admin_api.db.queries import ActivityQueries, ScimTokenQueries
from admin_api.scim.auth import generate_token, hash_token

logger = structlog.get_logger()

router = APIRouter()


class CreateScimTokenRequest(BaseModel):
    """Request to create a new SCIM token."""

    description: str


class ScimTokenResponse(BaseModel):
    """SCIM token metadata (no plaintext)."""

    id: UUID
    description: str
    created_at: str
    last_used_at: str | None = None
    is_active: bool


class ScimTokenCreatedResponse(BaseModel):
    """Response after creating a SCIM token (includes plaintext once)."""

    id: UUID
    token: str
    description: str
    message: str = "Store this token securely. It will not be shown again."


@router.post("/", response_model=ScimTokenCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_scim_token(
    request: CreateScimTokenRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> ScimTokenCreatedResponse:
    """Create a new SCIM bearer token.

    The plaintext token is returned once and never stored. Give it to your
    identity provider for SCIM provisioning.
    """
    plaintext = generate_token()
    token_hash_value = hash_token(plaintext)

    scim_token = await ScimTokenQueries.create_token(
        db,
        token_hash=token_hash_value,
        description=request.description,
        created_by=current_user.user.id,
    )

    await ActivityQueries.log_activity(
        db,
        event_type="scim.token.created",
        actor_id=current_user.user.id,
        actor_type="user",
        target_id=scim_token.id,
        target_type="scim_token",
        details={"description": request.description},
    )

    logger.info(
        "scim_token_created",
        token_id=str(scim_token.id),
        created_by=str(current_user.user.id),
    )

    return ScimTokenCreatedResponse(
        id=scim_token.id,
        token=plaintext,
        description=request.description,
    )


@router.get("/", response_model=list[ScimTokenResponse])
async def list_scim_tokens(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> list[ScimTokenResponse]:
    """List all SCIM tokens (without plaintext values)."""
    tokens = await ScimTokenQueries.list_tokens(db)
    return [
        ScimTokenResponse(
            id=t.id,
            description=t.description,
            created_at=t.created_at.isoformat(),
            last_used_at=t.last_used_at.isoformat() if t.last_used_at else None,
            is_active=t.is_active,
        )
        for t in tokens
    ]


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_scim_token(
    token_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_admin),
) -> None:
    """Revoke a SCIM token."""
    revoked = await ScimTokenQueries.revoke_token(db, token_id)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SCIM token not found",
        )

    await ActivityQueries.log_activity(
        db,
        event_type="scim.token.revoked",
        actor_id=current_user.user.id,
        actor_type="user",
        target_id=token_id,
        target_type="scim_token",
    )

    logger.info(
        "scim_token_revoked",
        token_id=str(token_id),
        revoked_by=str(current_user.user.id),
    )
