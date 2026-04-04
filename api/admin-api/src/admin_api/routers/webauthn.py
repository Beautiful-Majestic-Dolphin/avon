"""WebAuthn FIDO2 hardware security key endpoints for AVON Admin API."""

import base64
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from webauthn.helpers.structs import PublicKeyCredentialDescriptor
import asyncpg
import structlog

from admin_api.auth.dependencies import get_current_user, CurrentUser
from admin_api.auth.jwt import (
    create_token_pair,
    verify_mfa_token,
)
from admin_api.auth.webauthn import WebAuthnManager
from admin_api.db.connection import get_db
from admin_api.db.queries import ActivityQueries, UserQueries, WebAuthnQueries
from admin_api.schemas.common import (
    TokenResponse,
    WebAuthnCredentialResponse,
)

logger = structlog.get_logger()

router = APIRouter()

# In-memory challenge store (use Redis in production with TTL)
# Key: f"{user_id}:{ceremony}" -> challenge bytes
_challenge_store: dict[str, bytes] = {}


def _store_challenge(user_id: UUID, ceremony: str, challenge: bytes) -> None:
    _challenge_store[f"{user_id}:{ceremony}"] = challenge


def _get_challenge(user_id: UUID, ceremony: str) -> bytes | None:
    return _challenge_store.pop(f"{user_id}:{ceremony}", None)


# --- Request/Response Models ---


class RegisterCompleteRequest(BaseModel):
    """Request body to complete WebAuthn registration."""

    credential: dict
    name: str = "Security Key"


class AuthenticateBeginRequest(BaseModel):
    """Request body to begin WebAuthn authentication."""

    mfa_token: str


class AuthenticateCompleteRequest(BaseModel):
    """Request body to complete WebAuthn authentication."""

    mfa_token: str
    credential: dict


# --- Registration Endpoints ---


@router.post("/register/begin")
async def register_begin(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Begin FIDO2 key registration.

    Returns PublicKeyCredentialCreationOptions for the browser to pass
    to navigator.credentials.create().
    """
    user = current_user.user

    # Get existing credentials to exclude (prevent re-registration of same key)
    existing = await WebAuthnQueries.get_credentials_for_user(db, user.id)
    existing_ids = [cred.credential_id for cred in existing]

    options, challenge = WebAuthnManager.generate_registration_options_for_user(
        user_id=user.id,
        user_email=user.email,
        user_name=user.full_name or user.email,
        existing_credential_ids=existing_ids,
    )

    _store_challenge(user.id, "registration", challenge)

    logger.info("webauthn_registration_begin", user_id=str(user.id))
    return options


@router.post("/register/complete", response_model=WebAuthnCredentialResponse)
async def register_complete(
    request: RegisterCompleteRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> WebAuthnCredentialResponse:
    """Complete FIDO2 key registration.

    Verifies the attestation response from the authenticator and stores
    the credential.
    """
    user = current_user.user

    challenge = _get_challenge(user.id, "registration")
    if challenge is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No registration challenge found. Call register/begin first.",
        )

    try:
        verification = WebAuthnManager.verify_registration(
            credential_json=request.credential,
            expected_challenge=challenge,
        )
    except Exception as e:
        logger.warning("webauthn_registration_failed", user_id=str(user.id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Registration verification failed: {e}",
        )

    # Store the credential
    credential = await WebAuthnQueries.create_credential(
        conn=db,
        user_id=user.id,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        transports=[],
        aaguid=verification.aaguid if hasattr(verification, "aaguid") else None,
        name=request.name,
    )

    await ActivityQueries.log_activity(
        db,
        event_type="user.webauthn_registered",
        actor_id=user.id,
        actor_type="user",
        details={"credential_name": request.name},
    )

    logger.info(
        "webauthn_registration_complete",
        user_id=str(user.id),
        credential_name=request.name,
    )

    return WebAuthnCredentialResponse(
        id=credential.id,
        name=credential.name,
        created_at=credential.created_at,
        last_used_at=credential.last_used_at,
        transports=credential.transports,
    )


# --- Credential Management ---


@router.get("/credentials", response_model=list[WebAuthnCredentialResponse])
async def list_credentials(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> list[WebAuthnCredentialResponse]:
    """List all registered FIDO2 keys for the current user."""
    credentials = await WebAuthnQueries.get_credentials_for_user(db, current_user.user.id)
    return [
        WebAuthnCredentialResponse(
            id=cred.id,
            name=cred.name,
            created_at=cred.created_at,
            last_used_at=cred.last_used_at,
            transports=cred.transports,
        )
        for cred in credentials
    ]


@router.delete("/credentials/{credential_id}")
async def delete_credential(
    credential_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Remove a registered FIDO2 key."""
    deleted = await WebAuthnQueries.delete_credential(db, credential_id, current_user.user.id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential not found",
        )

    await ActivityQueries.log_activity(
        db,
        event_type="user.webauthn_removed",
        actor_id=current_user.user.id,
        actor_type="user",
        details={"credential_id": str(credential_id)},
    )

    logger.info(
        "webauthn_credential_deleted",
        user_id=str(current_user.user.id),
        credential_id=str(credential_id),
    )

    return {"success": True, "message": "Credential removed"}


# --- Authentication (MFA) Endpoints ---


@router.post("/authenticate/begin")
async def authenticate_begin(
    request: AuthenticateBeginRequest,
    db: asyncpg.Connection = Depends(get_db),
) -> dict:
    """Begin FIDO2 MFA authentication.

    Requires a valid mfa_token (obtained from the /login endpoint when
    the user has registered FIDO2 keys). Returns PublicKeyCredentialRequestOptions
    for the browser to pass to navigator.credentials.get().
    """
    token_data = verify_mfa_token(request.mfa_token)
    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA token",
        )

    credentials = await WebAuthnQueries.get_credentials_for_user(db, token_data.user_id)
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No FIDO2 credentials registered for this user",
        )

    descriptors = [
        PublicKeyCredentialDescriptor(id=cred.credential_id)
        for cred in credentials
    ]

    options, challenge = WebAuthnManager.generate_authentication_options_for_user(
        credential_descriptors=descriptors,
    )

    _store_challenge(token_data.user_id, "authentication", challenge)

    logger.info("webauthn_authentication_begin", user_id=str(token_data.user_id))
    return options


@router.post("/authenticate/complete", response_model=TokenResponse)
async def authenticate_complete(
    request: AuthenticateCompleteRequest,
    db: asyncpg.Connection = Depends(get_db),
) -> TokenResponse:
    """Complete FIDO2 MFA authentication.

    Verifies the assertion from the authenticator and issues JWT tokens.
    This completes the login flow for users with FIDO2 keys.
    """
    token_data = verify_mfa_token(request.mfa_token)
    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA token",
        )

    challenge = _get_challenge(token_data.user_id, "authentication")
    if challenge is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No authentication challenge found. Call authenticate/begin first.",
        )

    # Find the credential used in the assertion
    raw_id = request.credential.get("rawId") or request.credential.get("id", "")
    try:
        credential_id_bytes = base64.urlsafe_b64decode(raw_id + "==")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid credential ID encoding",
        )

    stored_credential = await WebAuthnQueries.get_credential_by_credential_id(
        db, credential_id_bytes
    )
    if stored_credential is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unknown credential",
        )

    try:
        verification = WebAuthnManager.verify_authentication(
            credential_json=request.credential,
            expected_challenge=challenge,
            credential_public_key=stored_credential.public_key,
            credential_current_sign_count=stored_credential.sign_count,
        )
    except Exception as e:
        logger.warning(
            "webauthn_authentication_failed",
            user_id=str(token_data.user_id),
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication verification failed: {e}",
        )

    # Update sign count for clone detection
    await WebAuthnQueries.update_sign_count(
        db, stored_credential.credential_id, verification.new_sign_count
    )

    # Update last login
    await UserQueries.update_last_login(db, token_data.user_id)

    # Issue JWT tokens
    token_pair = create_token_pair(
        token_data.user_id, token_data.email, token_data.is_admin
    )

    await ActivityQueries.log_activity(
        db,
        event_type="user.login",
        actor_id=token_data.user_id,
        actor_type="user",
        details={"mfa_method": "webauthn"},
    )

    logger.info(
        "webauthn_authentication_complete",
        user_id=str(token_data.user_id),
    )

    return TokenResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
        expires_in=token_pair.expires_in,
    )
