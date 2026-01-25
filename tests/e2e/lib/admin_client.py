"""Admin API Client for E2E Tests

Provides async interface to the AVON Admin API for test setup and verification.
"""

import asyncio
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential


@dataclass
class EnrollmentToken:
    """Enrollment token response."""
    token: str
    device_id: str
    expires_at: datetime


@dataclass
class Device:
    """Device information."""
    id: str
    name: str
    status: str
    platform: str
    last_seen: Optional[datetime]


@dataclass
class Pod:
    """Pod information."""
    id: str
    name: str
    description: str
    device_ids: List[str]


@dataclass
class Policy:
    """Policy information."""
    id: str
    source_pod_id: str
    destination_pod_id: str
    action: str
    priority: int


class AdminClient:
    """Async client for AVON Admin API."""

    def __init__(self, base_url: str, timeout: float = 30.0):
        """Initialize the admin client.

        Args:
            base_url: Base URL of the admin API (e.g., http://admin-api:8082)
            timeout: Default timeout for requests in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "AdminClient":
        """Async context manager entry."""
        self._session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._session:
            await self._session.close()
            self._session = None

    @property
    def session(self) -> aiohttp.ClientSession:
        """Get the HTTP session."""
        if self._session is None:
            raise RuntimeError("Client not initialized. Use async context manager.")
        return self._session

    # =====================
    # Health Check
    # =====================

    async def health_check(self) -> bool:
        """Check if the admin API is healthy."""
        try:
            async with self.session.get(f"{self.base_url}/health") as resp:
                return resp.status == 200
        except Exception:
            return False

    @retry(stop=stop_after_attempt(30), wait=wait_exponential(multiplier=1, max=10))
    async def wait_for_ready(self) -> None:
        """Wait for the admin API to be ready."""
        if not await self.health_check():
            raise RuntimeError("Admin API not ready")

    # =====================
    # Enrollment Management
    # =====================

    async def create_enrollment(
        self,
        name: str,
        platform: str = "linux",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EnrollmentToken:
        """Create a new enrollment token for a device.

        Args:
            name: Human-readable name for the device
            platform: Target platform (linux, macos, windows)
            metadata: Optional metadata to attach to the device

        Returns:
            EnrollmentToken with token string and device ID
        """
        payload = {
            "name": name,
            "platform": platform,
            "metadata": metadata or {},
        }
        async with self.session.post(
            f"{self.base_url}/api/v1/enrollments",
            json=payload,
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return EnrollmentToken(
                token=data["token"],
                device_id=data["device_id"],
                expires_at=datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")),
            )

    async def get_enrollment(self, device_id: str) -> Dict[str, Any]:
        """Get enrollment status for a device."""
        async with self.session.get(
            f"{self.base_url}/api/v1/enrollments/{device_id}"
        ) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def revoke_enrollment(self, device_id: str) -> None:
        """Revoke an enrollment token."""
        async with self.session.delete(
            f"{self.base_url}/api/v1/enrollments/{device_id}"
        ) as resp:
            resp.raise_for_status()

    # =====================
    # Device Management
    # =====================

    async def get_device(self, device_id: str) -> Device:
        """Get device information."""
        async with self.session.get(
            f"{self.base_url}/api/v1/devices/{device_id}"
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return Device(
                id=data["id"],
                name=data["name"],
                status=data["status"],
                platform=data["platform"],
                last_seen=datetime.fromisoformat(data["last_seen"].replace("Z", "+00:00"))
                if data.get("last_seen")
                else None,
            )

    async def list_devices(self, status: Optional[str] = None) -> List[Device]:
        """List all devices, optionally filtered by status."""
        params = {}
        if status:
            params["status"] = status
        async with self.session.get(
            f"{self.base_url}/api/v1/devices",
            params=params,
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return [
                Device(
                    id=d["id"],
                    name=d["name"],
                    status=d["status"],
                    platform=d["platform"],
                    last_seen=datetime.fromisoformat(d["last_seen"].replace("Z", "+00:00"))
                    if d.get("last_seen")
                    else None,
                )
                for d in data["devices"]
            ]

    async def suspend_device(self, device_id: str) -> None:
        """Suspend a device."""
        async with self.session.post(
            f"{self.base_url}/api/v1/devices/{device_id}/suspend"
        ) as resp:
            resp.raise_for_status()

    async def revoke_device(self, device_id: str) -> None:
        """Permanently revoke a device."""
        async with self.session.post(
            f"{self.base_url}/api/v1/devices/{device_id}/revoke"
        ) as resp:
            resp.raise_for_status()

    async def reactivate_device(self, device_id: str) -> None:
        """Reactivate a suspended device."""
        async with self.session.post(
            f"{self.base_url}/api/v1/devices/{device_id}/reactivate"
        ) as resp:
            resp.raise_for_status()

    # =====================
    # Pod Management
    # =====================

    async def create_pod(
        self,
        name: str,
        description: str = "",
        parent_id: Optional[str] = None,
    ) -> Pod:
        """Create a new pod."""
        payload = {
            "name": name,
            "description": description,
        }
        if parent_id:
            payload["parent_id"] = parent_id
        async with self.session.post(
            f"{self.base_url}/api/v1/pods",
            json=payload,
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return Pod(
                id=data["id"],
                name=data["name"],
                description=data.get("description", ""),
                device_ids=data.get("device_ids", []),
            )

    async def get_pod(self, pod_id: str) -> Pod:
        """Get pod information."""
        async with self.session.get(
            f"{self.base_url}/api/v1/pods/{pod_id}"
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return Pod(
                id=data["id"],
                name=data["name"],
                description=data.get("description", ""),
                device_ids=data.get("device_ids", []),
            )

    async def add_device_to_pod(self, pod_id: str, device_id: str) -> None:
        """Add a device to a pod."""
        async with self.session.post(
            f"{self.base_url}/api/v1/pods/{pod_id}/devices",
            json={"device_id": device_id},
        ) as resp:
            resp.raise_for_status()

    async def remove_device_from_pod(self, pod_id: str, device_id: str) -> None:
        """Remove a device from a pod."""
        async with self.session.delete(
            f"{self.base_url}/api/v1/pods/{pod_id}/devices/{device_id}"
        ) as resp:
            resp.raise_for_status()

    async def delete_pod(self, pod_id: str) -> None:
        """Delete a pod."""
        async with self.session.delete(
            f"{self.base_url}/api/v1/pods/{pod_id}"
        ) as resp:
            resp.raise_for_status()

    # =====================
    # Policy Management
    # =====================

    async def create_policy(
        self,
        source_pod_id: str,
        destination_pod_id: str,
        action: str = "allow",
        priority: int = 100,
        conditions: Optional[Dict[str, Any]] = None,
    ) -> Policy:
        """Create a new policy.

        Args:
            source_pod_id: Source pod ID
            destination_pod_id: Destination pod ID
            action: Policy action (allow, deny)
            priority: Policy priority (lower = higher priority)
            conditions: Optional conditions for the policy
        """
        payload = {
            "source_pod_id": source_pod_id,
            "destination_pod_id": destination_pod_id,
            "action": action,
            "priority": priority,
            "conditions": conditions or {},
        }
        async with self.session.post(
            f"{self.base_url}/api/v1/policies",
            json=payload,
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return Policy(
                id=data["id"],
                source_pod_id=data["source_pod_id"],
                destination_pod_id=data["destination_pod_id"],
                action=data["action"],
                priority=data["priority"],
            )

    async def delete_policy(self, policy_id: str) -> None:
        """Delete a policy."""
        async with self.session.delete(
            f"{self.base_url}/api/v1/policies/{policy_id}"
        ) as resp:
            resp.raise_for_status()

    # =====================
    # Tunnel Management
    # =====================

    async def list_tunnels(self, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List active tunnels."""
        params = {}
        if device_id:
            params["device_id"] = device_id
        async with self.session.get(
            f"{self.base_url}/api/v1/tunnels",
            params=params,
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return data.get("tunnels", [])

    async def close_tunnel(self, session_id: str) -> None:
        """Force close a tunnel."""
        async with self.session.delete(
            f"{self.base_url}/api/v1/tunnels/{session_id}"
        ) as resp:
            resp.raise_for_status()
