"""Enrollment service for AVON Admin API."""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import asyncpg
import structlog

from admin_api.config import settings
from admin_api.db.queries import EnrollmentQueries
from admin_api.schemas.device import EnrollmentTokenResponse
from admin_api.services.installation_package import InstallationPackageService

logger = structlog.get_logger()


class EnrollmentService:
    """Service for managing device enrollments."""

    def __init__(self, db: asyncpg.Connection):
        self.db = db
        self.installation_service = InstallationPackageService()

    async def create_enrollment(
        self,
        name: str,
        device_type: str,
        assigned_pods: list[UUID],
        created_by: UUID,
        expires_hours: Optional[int] = None,
        require_fido2: bool = False,
    ) -> EnrollmentTokenResponse:
        """Create a new device enrollment.
        
        Args:
            name: Device name
            device_type: Type of device (linux, windows, macos, ios, android)
            assigned_pods: List of pod IDs to assign the device to
            created_by: User ID who created the enrollment
            expires_hours: Hours until token expires (default from settings)
            
        Returns:
            EnrollmentTokenResponse with token and installation details
        """
        token = self._generate_enrollment_token()
        
        if expires_hours is None:
            expires_hours = settings.enrollment_token_expire_hours
        
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_hours)

        await EnrollmentQueries.create_enrollment_token(
            self.db,
            token=token,
            device_name=name,
            device_type=device_type,
            assigned_pods=assigned_pods,
            expires_at=expires_at,
            created_by=created_by,
            require_fido2=require_fido2,
        )

        installation_url = self.installation_service.get_installation_url(
            device_type=device_type,
            enrollment_token=token,
        )

        installation_instructions = self._get_installation_instructions(
            device_type=device_type,
            token=token,
        )

        logger.info(
            "enrollment_created",
            device_name=name,
            device_type=device_type,
            expires_at=expires_at.isoformat(),
            created_by=str(created_by),
        )

        return EnrollmentTokenResponse(
            token=token,
            device_name=name,
            device_type=device_type,
            require_fido2=require_fido2,
            expires_at=expires_at,
            installation_url=installation_url,
            installation_instructions=installation_instructions,
        )

    async def complete_enrollment(
        self,
        enrollment_token: str,
        hardware_fingerprint: bytes,
        device_id: UUID,
    ) -> bool:
        """Complete device enrollment.
        
        Called by the agent on first connect.
        
        Args:
            enrollment_token: The enrollment token
            hardware_fingerprint: Device hardware fingerprint
            device_id: The device ID
            
        Returns:
            True if enrollment was successful
        """
        token_record = await EnrollmentQueries.get_enrollment_token(
            self.db,
            enrollment_token,
        )

        if token_record is None:
            logger.warning("enrollment_token_not_found", token=enrollment_token[:8] + "...")
            return False

        if token_record.consumed_at is not None:
            logger.warning("enrollment_token_already_consumed", token=enrollment_token[:8] + "...")
            return False

        if token_record.expires_at < datetime.now(timezone.utc):
            logger.warning("enrollment_token_expired", token=enrollment_token[:8] + "...")
            return False

        success = await EnrollmentQueries.consume_enrollment_token(
            self.db,
            enrollment_token,
            device_id,
        )

        if success:
            logger.info(
                "enrollment_completed",
                device_id=str(device_id),
                device_name=token_record.device_name,
            )

        return success

    async def get_enrollment_status(self, token: str) -> Optional[dict]:
        """Get the status of an enrollment token.
        
        Args:
            token: The enrollment token
            
        Returns:
            Dict with token status or None if not found
        """
        token_record = await EnrollmentQueries.get_enrollment_token(self.db, token)
        if token_record is None:
            return None

        now = datetime.now(timezone.utc)
        is_expired = token_record.expires_at < now
        is_consumed = token_record.consumed_at is not None

        status = "valid"
        if is_consumed:
            status = "consumed"
        elif is_expired:
            status = "expired"

        return {
            "token": token[:8] + "...",
            "device_name": token_record.device_name,
            "device_type": token_record.device_type,
            "status": status,
            "expires_at": token_record.expires_at.isoformat(),
            "consumed_at": token_record.consumed_at.isoformat() if token_record.consumed_at else None,
            "device_id": str(token_record.device_id) if token_record.device_id else None,
        }

    def _generate_enrollment_token(self) -> str:
        """Generate a secure enrollment token."""
        return secrets.token_urlsafe(32)

    def _get_installation_instructions(self, device_type: str, token: str) -> str:
        """Get installation instructions for a device type."""
        base_url = settings.installation_package_base_url
        
        instructions = {
            "linux": f"""To install the AVON agent on Linux:

1. Download the installer:
   curl -fsSL {base_url}/install.sh | sudo bash

2. Enroll the device:
   sudo avon-agent enroll --token {token}

3. Start the agent:
   sudo systemctl enable --now avon-agent
""",
            "windows": f"""To install the AVON agent on Windows:

1. Download the installer from:
   {base_url}/avon-agent-setup.exe

2. Run the installer as Administrator

3. Open PowerShell as Administrator and run:
   avon-agent enroll --token {token}

4. The agent will start automatically
""",
            "macos": f"""To install the AVON agent on macOS:

1. Download and install:
   curl -fsSL {base_url}/install.sh | sudo bash

2. Enroll the device:
   sudo avon-agent enroll --token {token}

3. Start the agent:
   sudo launchctl load /Library/LaunchDaemons/com.avon.agent.plist
""",
            "ios": f"""To install the AVON agent on iOS:

1. Download the AVON app from the App Store

2. Open the app and enter the enrollment token:
   {token}

3. Follow the on-screen instructions to complete setup
""",
            "android": f"""To install the AVON agent on Android:

1. Download the AVON app from Google Play Store

2. Open the app and enter the enrollment token:
   {token}

3. Follow the on-screen instructions to complete setup
""",
        }

        return instructions.get(device_type, f"Enrollment token: {token}")
