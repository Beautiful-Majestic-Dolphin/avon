"""WebAuthn ceremony handlers for AVON Admin API.

Manages FIDO2 hardware security key registration and authentication
using the py-webauthn library.
"""

import json
from uuid import UUID

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from admin_api.config import settings


class WebAuthnManager:
    """Manages WebAuthn registration and authentication ceremonies."""

    @staticmethod
    def generate_registration_options_for_user(
        user_id: UUID,
        user_email: str,
        user_name: str,
        existing_credential_ids: list[bytes],
    ) -> tuple[dict, bytes]:
        """Generate registration options for a new key.

        Returns (options_json_dict, challenge_bytes).
        """
        options = generate_registration_options(
            rp_id=settings.webauthn_rp_id,
            rp_name=settings.webauthn_rp_name,
            user_id=str(user_id).encode(),
            user_name=user_email,
            user_display_name=user_name or user_email,
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=cid)
                for cid in existing_credential_ids
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
                resident_key=ResidentKeyRequirement.DISCOURAGED,
                user_verification=UserVerificationRequirement.DISCOURAGED,
            ),
        )
        return json.loads(options_to_json(options)), options.challenge

    @staticmethod
    def verify_registration(
        credential_json: dict,
        expected_challenge: bytes,
    ):
        """Verify a registration response from the authenticator.

        Returns a VerifiedRegistration with credential_id, public_key, sign_count, etc.
        """
        return verify_registration_response(
            credential=credential_json,
            expected_challenge=expected_challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
        )

    @staticmethod
    def generate_authentication_options_for_user(
        credential_descriptors: list[PublicKeyCredentialDescriptor],
    ) -> tuple[dict, bytes]:
        """Generate authentication options for MFA challenge.

        Returns (options_json_dict, challenge_bytes).
        """
        options = generate_authentication_options(
            rp_id=settings.webauthn_rp_id,
            allow_credentials=credential_descriptors,
            user_verification=UserVerificationRequirement.DISCOURAGED,
        )
        return json.loads(options_to_json(options)), options.challenge

    @staticmethod
    def verify_authentication(
        credential_json: dict,
        expected_challenge: bytes,
        credential_public_key: bytes,
        credential_current_sign_count: int,
    ):
        """Verify an authentication response from the authenticator.

        Returns a VerifiedAuthentication with new_sign_count.
        """
        return verify_authentication_response(
            credential=credential_json,
            expected_challenge=expected_challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=credential_current_sign_count,
        )
