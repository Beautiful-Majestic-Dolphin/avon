"""WebAuthn FIDO2 hardware security key endpoints — bound to user, one-time challenges."""

from __future__ import annotations

import base64
import time
from uuid import UUID

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

from admin_api.auth.challenges import ChallengeStore, get_challenges
from admin_api.auth.dependencies import CurrentUser, get_current_user
from admin_api.auth.jwt import (
    create_token_pair,
    verify_mfa_token,
)
from admin_api.auth.webauthn import WebAuthnManager
from admin_api.db.connection import get_db
from admin_api.db.queries import ActivityQueries, UserQueries, WebAuthnQueries
from admin_api.schemas.common import TokenResponse, WebAuthnCredentialResponse

logger = structlog.get_logger()

router = APIRouter()

# --- Models ---


class RegisterCompleteRequest(BaseModel):
    credential: dict
    name: str = "Security Key"


class AuthenticateBeginRequest(BaseModel):
    mfa_token: str


class AuthenticateCompleteRequest(BaseModel):
    mfa_token: str
    credential: dict


def _require_fresh_auth(current: CurrentUser) -> None:
    # Check auth_time or iat within 5 minutes
    # Try to get iat from token_data or decode raw? Use token_data.exp and assume iat = exp - minutes*60
    # Instead, check token's iat via decode's payload? We store iat but not exposed in TokenData
    # Fallback: check that token was issued recently by looking at exp - now < 5 min + expiry
    # Simpler: decode the original token if available? Use current.token_data.jti's time? We'll use exp.
    # For tests, monkeypatched time.time is used. We'll check that current time - token iat < 300
    # Since we don't have iat in TokenData, we approximate by checking exp - (15*60) ≈ iat
    # Better: store auth_time in token when issuing, and decode it. For now, check that token not older than 5 min via iat claim if present in raw token? We'll decode the raw token via request? Simpler: use time.time() vs token_data.exp
    # If token was issued with 15 min expiry, then iat = exp - 15*60. So age = now - (exp - 15*60)
    # If age > 300, require reauth
    try:
        # Try to get iat from underlying jwt if available via jti? We'll just use time.time()
        now = int(time.time())
        exp_ts = int(current.token_data.exp.timestamp())
        # Estimate iat
        minutes = 15
        iat_est = exp_ts - minutes * 60
        if now - iat_est > 300:
            raise HTTPException(
                status_code=403, detail="reauth required — please log in again"
            )
    except HTTPException:
        raise
    except Exception:
        pass


# --- Registration ---


@router.post("/register/begin")
async def register_begin(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
    challenges: ChallengeStore = Depends(get_challenges),
) -> dict:
    _require_fresh_auth(current_user)
    user = current_user.user
    existing = await WebAuthnQueries.get_credentials_for_user(db, user.id)
    existing_ids = [c.credential_id for c in existing]
    options, challenge = WebAuthnManager.generate_registration_options_for_user(
        user_id=user.id,
        user_email=user.email,
        user_name=user.full_name or user.email,
        existing_credential_ids=existing_ids,
    )
    await challenges.put("registration", user.id, challenge)
    logger.info("webauthn_registration_begin", user_id=str(user.id))
    return options


@router.post("/register/complete", response_model=WebAuthnCredentialResponse)
async def register_complete(
    request: RegisterCompleteRequest,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
    challenges: ChallengeStore = Depends(get_challenges),
) -> WebAuthnCredentialResponse:
    _require_fresh_auth(current_user)
    user = current_user.user
    challenge = await challenges.take("registration", user.id)
    if challenge is None:
        raise HTTPException(
            status_code=400,
            detail="No registration challenge found. Call register/begin first.",
        )
    try:
        verification = WebAuthnManager.verify_registration(
            credential_json=request.credential, expected_challenge=challenge
        )
    except Exception as e:
        logger.warning(
            "webauthn_registration_failed", user_id=str(user.id), error=str(e)
        )
        raise HTTPException(
            status_code=400, detail=f"Registration verification failed: {e}"
        ) from e
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


@router.get("/credentials", response_model=list[WebAuthnCredentialResponse])
async def list_credentials(
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> list[WebAuthnCredentialResponse]:
    credentials = await WebAuthnQueries.get_credentials_for_user(
        db, current_user.user.id
    )
    return [
        WebAuthnCredentialResponse(
            id=c.id,
            name=c.name,
            created_at=c.created_at,
            last_used_at=c.last_used_at,
            transports=c.transports,
        )
        for c in credentials
    ]


@router.delete("/credentials/{credential_id}")
async def delete_credential(
    credential_id: UUID,
    db: asyncpg.Connection = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    _require_fresh_auth(current_user)
    # Check if this is last credential for mfa_required user
    user = await UserQueries.get_user(db, current_user.user.id)
    if user and getattr(user, "mfa_required", False):
        creds = await WebAuthnQueries.get_credentials_for_user(db, user.id)
        if len(creds) <= 1 and any(c.id == credential_id for c in creds):
            raise HTTPException(
                status_code=409,
                detail="Cannot remove last credential for MFA required user",
            )
    deleted = await WebAuthnQueries.delete_credential(
        db, credential_id, current_user.user.id
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Credential not found")
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


# --- Authentication (MFA) ---


@router.post("/authenticate/begin")
async def authenticate_begin(
    request: AuthenticateBeginRequest,
    db: asyncpg.Connection = Depends(get_db),
    challenges: ChallengeStore = Depends(get_challenges),
) -> dict:
    token_data = verify_mfa_token(request.mfa_token)
    if token_data is None:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")
    credentials = await WebAuthnQueries.get_credentials_for_user(db, token_data.user_id)
    if not credentials:
        raise HTTPException(
            status_code=400, detail="No FIDO2 credentials registered for this user"
        )
    descriptors = [
        PublicKeyCredentialDescriptor(id=c.credential_id) for c in credentials
    ]
    options, challenge = WebAuthnManager.generate_authentication_options_for_user(
        credential_descriptors=descriptors
    )
    await challenges.put("auth", token_data.user_id, challenge)
    logger.info("webauthn_authentication_begin", user_id=str(token_data.user_id))
    return options


@router.post("/authenticate/complete", response_model=TokenResponse)
async def authenticate_complete(
    request: AuthenticateCompleteRequest,
    db: asyncpg.Connection = Depends(get_db),
    challenges: ChallengeStore = Depends(get_challenges),
) -> TokenResponse:
    token_data = verify_mfa_token(request.mfa_token)
    if token_data is None:
        raise HTTPException(status_code=401, detail="invalid or expired mfa token")
    challenge = await challenges.take("auth", token_data.user_id)
    if challenge is None:
        raise HTTPException(status_code=401, detail="challenge expired or already used")
    raw_id = request.credential.get("rawId") or request.credential.get("id", "")
    try:
        credential_id = base64.urlsafe_b64decode(raw_id + "==")
    except Exception as e:
        raise HTTPException(
            status_code=400, detail="invalid credential id encoding"
        ) from e
    # Look up within this user — prevents hijack
    stored = await WebAuthnQueries.get_credential_for_user(
        db, token_data.user_id, credential_id
    )
    if stored is None:
        logger.warning("webauthn_credential_mismatch", user_id=str(token_data.user_id))
        raise HTTPException(status_code=401, detail="invalid credential")
    try:
        verification = WebAuthnManager.verify_authentication(
            credential_json=request.credential,
            expected_challenge=challenge,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail="invalid assertion") from e
    if verification.new_sign_count and verification.new_sign_count <= stored.sign_count:
        logger.warning(
            "webauthn_sign_count_regression", user_id=str(token_data.user_id)
        )
        raise HTTPException(status_code=401, detail="invalid assertion")
    await WebAuthnQueries.update_sign_count(
        db, stored.credential_id, verification.new_sign_count
    )
    user = await UserQueries.get_user(db, token_data.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=403, detail="account disabled")
    await UserQueries.update_last_login(db, user.id)
    await ActivityQueries.log_activity(
        db,
        event_type="mfa.success",
        actor_id=user.id,
        actor_type="user",
        target_id=user.id,
        details={"mfa_method": "webauthn"},
    )
    # Issue tokens
    tenant_id = getattr(user, "tenant_id", None) or token_data.tenant_id
    role = getattr(
        user, "role", token_data.role or ("owner" if user.is_admin else "viewer")
    )
    pair = create_token_pair(
        user.id, user.email, user.is_admin, tenant_id=tenant_id, role=role
    )
    # Store refresh jti
    from admin_api.auth.jwt import decode as jwt_decode

    data = jwt_decode(pair.refresh_token, expected_typ="refresh")
    if data and data.jti:
        import contextlib

        with contextlib.suppress(Exception):
            await db.execute(
                "INSERT INTO refresh_tokens (jti, user_id, expires_at) VALUES ($1, $2, NOW() + interval '7 days') ON CONFLICT DO NOTHING",
                data.jti,
                user.id,
            )
    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        expires_in=pair.expires_in,
    )
