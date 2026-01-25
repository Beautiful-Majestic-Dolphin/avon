"""Agent Control Client for E2E Tests

Provides async interface to control AVON agents during testing.
The agents expose a simple HTTP control API for test orchestration.
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential


@dataclass
class AgentStatus:
    """Agent status information."""
    device_id: Optional[str]
    status: str  # disconnected, connecting, connected, enrolled
    enrolled: bool
    connected: bool
    active_tunnels: int
    last_pulse: Optional[str]


@dataclass
class TunnelInfo:
    """Tunnel information from agent perspective."""
    session_id: str
    peer_device_id: str
    peer_address: str
    state: str
    bytes_sent: int
    bytes_received: int
    established_at: str


class AgentClient:
    """Async client for controlling AVON agents during E2E tests.

    Each agent exposes a control API for test orchestration that allows:
    - Triggering enrollment
    - Requesting tunnel establishment
    - Sending/receiving test data
    - Querying status
    """

    def __init__(self, base_url: str, timeout: float = 30.0):
        """Initialize the agent client.

        Args:
            base_url: Base URL of the agent control API (e.g., http://agent-1:8090)
            timeout: Default timeout for requests in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "AgentClient":
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
        """Check if the agent control API is healthy."""
        try:
            async with self.session.get(f"{self.base_url}/health") as resp:
                return resp.status == 200
        except Exception:
            return False

    @retry(stop=stop_after_attempt(30), wait=wait_exponential(multiplier=1, max=10))
    async def wait_for_ready(self) -> None:
        """Wait for the agent to be ready."""
        if not await self.health_check():
            raise RuntimeError("Agent not ready")

    # =====================
    # Status
    # =====================

    async def get_status(self) -> AgentStatus:
        """Get agent status."""
        async with self.session.get(f"{self.base_url}/status") as resp:
            resp.raise_for_status()
            data = await resp.json()
            return AgentStatus(
                device_id=data.get("device_id"),
                status=data["status"],
                enrolled=data.get("enrolled", False),
                connected=data.get("connected", False),
                active_tunnels=data.get("active_tunnels", 0),
                last_pulse=data.get("last_pulse"),
            )

    async def get_device_id(self) -> Optional[str]:
        """Get the agent's device ID (only available after enrollment)."""
        status = await self.get_status()
        return status.device_id

    # =====================
    # Enrollment
    # =====================

    async def enroll(
        self,
        token: str,
        control_plane_addr: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Trigger enrollment with the given token.

        Args:
            token: Enrollment token from admin API
            control_plane_addr: Optional override for control plane address

        Returns:
            Enrollment result with device_id and certificate info
        """
        payload = {"token": token}
        if control_plane_addr:
            payload["control_plane_addr"] = control_plane_addr

        async with self.session.post(
            f"{self.base_url}/enroll",
            json=payload,
        ) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def is_enrolled(self) -> bool:
        """Check if the agent is enrolled."""
        status = await self.get_status()
        return status.enrolled

    # =====================
    # Connection Management
    # =====================

    async def connect(self) -> Dict[str, Any]:
        """Connect to the control plane."""
        async with self.session.post(f"{self.base_url}/connect") as resp:
            resp.raise_for_status()
            return await resp.json()

    async def disconnect(self) -> Dict[str, Any]:
        """Disconnect from the control plane."""
        async with self.session.post(f"{self.base_url}/disconnect") as resp:
            resp.raise_for_status()
            return await resp.json()

    async def is_connected(self) -> bool:
        """Check if the agent is connected to the control plane."""
        status = await self.get_status()
        return status.connected

    # =====================
    # Tunnel Management
    # =====================

    async def request_tunnel(self, peer_device_id: str) -> Dict[str, Any]:
        """Request a tunnel to another device.

        Args:
            peer_device_id: Device ID of the peer to connect to

        Returns:
            Tunnel request result with session_id
        """
        async with self.session.post(
            f"{self.base_url}/tunnels",
            json={"peer_device_id": peer_device_id},
        ) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def list_tunnels(self) -> List[TunnelInfo]:
        """List active tunnels."""
        async with self.session.get(f"{self.base_url}/tunnels") as resp:
            resp.raise_for_status()
            data = await resp.json()
            return [
                TunnelInfo(
                    session_id=t["session_id"],
                    peer_device_id=t["peer_device_id"],
                    peer_address=t["peer_address"],
                    state=t["state"],
                    bytes_sent=t.get("bytes_sent", 0),
                    bytes_received=t.get("bytes_received", 0),
                    established_at=t["established_at"],
                )
                for t in data.get("tunnels", [])
            ]

    async def get_tunnel(self, session_id: str) -> Optional[TunnelInfo]:
        """Get information about a specific tunnel."""
        async with self.session.get(f"{self.base_url}/tunnels/{session_id}") as resp:
            if resp.status == 404:
                return None
            resp.raise_for_status()
            t = await resp.json()
            return TunnelInfo(
                session_id=t["session_id"],
                peer_device_id=t["peer_device_id"],
                peer_address=t["peer_address"],
                state=t["state"],
                bytes_sent=t.get("bytes_sent", 0),
                bytes_received=t.get("bytes_received", 0),
                established_at=t["established_at"],
            )

    async def close_tunnel(self, session_id: str) -> None:
        """Close a specific tunnel."""
        async with self.session.delete(f"{self.base_url}/tunnels/{session_id}") as resp:
            resp.raise_for_status()

    async def has_tunnel_to(self, peer_device_id: str) -> bool:
        """Check if there's an active tunnel to a specific peer."""
        tunnels = await self.list_tunnels()
        return any(t.peer_device_id == peer_device_id and t.state == "active" for t in tunnels)

    # =====================
    # Data Transfer (for testing)
    # =====================

    async def send_test_data(
        self,
        peer_device_id: str,
        data: bytes,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        """Send test data to a peer through the tunnel.

        Args:
            peer_device_id: Device ID of the peer
            data: Raw bytes to send
            timeout: Timeout in seconds

        Returns:
            Send result with bytes_sent
        """
        import base64
        async with self.session.post(
            f"{self.base_url}/test/send",
            json={
                "peer_device_id": peer_device_id,
                "data": base64.b64encode(data).decode("ascii"),
            },
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def receive_test_data(
        self,
        timeout: float = 10.0,
    ) -> Optional[bytes]:
        """Receive test data from the test data buffer.

        Args:
            timeout: Timeout in seconds to wait for data

        Returns:
            Received bytes or None if no data available
        """
        import base64
        async with self.session.get(
            f"{self.base_url}/test/receive",
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status == 204:
                return None
            resp.raise_for_status()
            data = await resp.json()
            if data.get("data"):
                return base64.b64decode(data["data"])
            return None

    async def clear_test_buffer(self) -> None:
        """Clear the test data receive buffer."""
        async with self.session.delete(f"{self.base_url}/test/buffer") as resp:
            resp.raise_for_status()

    # =====================
    # Metrics
    # =====================

    async def get_metrics(self) -> Dict[str, Any]:
        """Get agent metrics."""
        async with self.session.get(f"{self.base_url}/metrics") as resp:
            resp.raise_for_status()
            return await resp.json()
