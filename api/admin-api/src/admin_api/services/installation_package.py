"""Installation package service for AVON Admin API."""

import hashlib
import hmac
import json
import time
from urllib.parse import urlencode

import structlog

from admin_api.config import settings

logger = structlog.get_logger()


class InstallationPackageService:
    """Service for generating installation packages and URLs."""

    def __init__(self):
        self.base_url = settings.installation_package_base_url
        self.control_plane_addresses = settings.control_plane_addresses

    def get_installation_url(
        self,
        device_type: str,
        enrollment_token: str,
        expires_in: int = 86400,
    ) -> str:
        """Generate a signed installation URL.

        Args:
            device_type: Type of device (linux, windows, macos, ios, android)
            enrollment_token: The enrollment token
            expires_in: URL expiration time in seconds (default 24 hours)

        Returns:
            Signed installation URL
        """
        timestamp = int(time.time())
        expires_at = timestamp + expires_in

        params = {
            "token": enrollment_token,
            "type": device_type,
            "expires": expires_at,
        }

        signature = self._sign_params(params)
        params["sig"] = signature

        endpoint = self._get_endpoint_for_device_type(device_type)
        return f"{self.base_url}/{endpoint}?{urlencode(params)}"

    def generate_config_file(
        self,
        device_id: str,
        enrollment_token: str,
        device_type: str,
    ) -> str:
        """Generate a configuration file for the agent.

        Args:
            device_id: The device ID
            enrollment_token: The enrollment token
            device_type: Type of device

        Returns:
            Configuration file contents as string
        """
        config = {
            "device_id": device_id,
            "enrollment_token": enrollment_token,
            "control_plane": {
                "addresses": self.control_plane_addresses,
                "port": 8443,
            },
            "agent": {
                "log_level": "INFO",
                "metrics_port": 9090,
            },
        }

        if device_type in ("linux", "macos"):
            config["agent"]["config_path"] = "/etc/avon/agent.conf"
            config["agent"]["data_path"] = "/var/lib/avon"
            config["agent"]["log_path"] = "/var/log/avon"
        elif device_type == "windows":
            config["agent"]["config_path"] = "C:\\ProgramData\\AVON\\agent.conf"
            config["agent"]["data_path"] = "C:\\ProgramData\\AVON\\data"
            config["agent"]["log_path"] = "C:\\ProgramData\\AVON\\logs"

        return json.dumps(config, indent=2)

    def get_download_url(
        self,
        device_type: str,
        version: str | None = None,
    ) -> str:
        """Get the download URL for the agent installer.

        Args:
            device_type: Type of device
            version: Specific version to download (default: latest)

        Returns:
            Download URL for the installer
        """
        version_str = version or "latest"

        filenames = {
            "linux": f"avon-agent-{version_str}-linux-amd64.tar.gz",
            "windows": f"avon-agent-{version_str}-windows-amd64.exe",
            "macos": f"avon-agent-{version_str}-darwin-amd64.tar.gz",
            "ios": "avon-agent-ios.ipa",
            "android": "avon-agent-android.apk",
        }

        filename = filenames.get(device_type, f"avon-agent-{version_str}.tar.gz")
        return f"{self.base_url}/downloads/{filename}"

    def get_checksum_url(
        self,
        device_type: str,
        version: str | None = None,
    ) -> str:
        """Get the checksum URL for verifying the installer.

        Args:
            device_type: Type of device
            version: Specific version (default: latest)

        Returns:
            URL for the checksum file
        """
        version_str = version or "latest"
        return f"{self.base_url}/downloads/checksums-{version_str}.txt"

    def _get_endpoint_for_device_type(self, device_type: str) -> str:
        """Get the installation endpoint for a device type."""
        endpoints = {
            "linux": "install/linux",
            "windows": "install/windows",
            "macos": "install/macos",
            "ios": "install/ios",
            "android": "install/android",
        }
        return endpoints.get(device_type, "install")

    def _sign_params(self, params: dict) -> str:
        """Sign URL parameters using HMAC-SHA256.

        Args:
            params: Parameters to sign

        Returns:
            Hex-encoded signature
        """
        sorted_params = sorted(params.items())
        message = "&".join(f"{k}={v}" for k, v in sorted_params)

        signature = hmac.new(
            settings.jwt_secret_key.encode(),
            message.encode(),
            hashlib.sha256,
        ).hexdigest()

        return signature

    def verify_signature(self, params: dict, signature: str) -> bool:
        """Verify a URL signature.

        Args:
            params: Parameters that were signed
            signature: The signature to verify

        Returns:
            True if signature is valid
        """
        params_copy = {k: v for k, v in params.items() if k != "sig"}
        expected = self._sign_params(params_copy)
        return hmac.compare_digest(expected, signature)
