"""End-to-End Test: Full Enrollment and Communication Flow

This test validates the complete AVON workflow:
1. Device enrollment
2. Pod and policy creation
3. Tunnel establishment
4. Encrypted data transmission
"""

import pytest
import pytest_asyncio

from lib.admin_client import AdminClient
from lib.agent_client import AgentClient
from lib.config import config
from lib.helpers import generate_test_id, wait_for_condition, TestContext


@pytest.mark.asyncio
class TestFullFlow:
    """Full end-to-end flow tests."""

    async def test_enrollment_creates_device(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        test_context: TestContext,
    ):
        """Test that enrollment creates a device in the system."""
        # Create enrollment token
        enrollment = await admin_client.create_enrollment(
            name=generate_test_id("device"),
            platform="linux",
        )
        test_context.track_device(enrollment.device_id)

        # Verify device exists with pending status
        device = await admin_client.get_device(enrollment.device_id)
        assert device.status == "pending_enrollment"

        # Trigger enrollment on agent
        result = await agent_1.enroll(enrollment.token)
        assert "device_id" in result

        # Wait for enrollment to complete
        await wait_for_condition(
            lambda: agent_1.is_enrolled(),
            timeout=config.enrollment_timeout,
            description="agent enrollment",
        )

        # Verify device is now active
        device = await admin_client.get_device(enrollment.device_id)
        assert device.status == "active"

    async def test_full_enrollment_and_tunnel_flow(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        test_context: TestContext,
    ):
        """Test complete flow: enrollment -> pod -> policy -> tunnel -> data transfer."""
        # Step 1: Create enrollments
        enrollment_1 = await admin_client.create_enrollment(
            name=generate_test_id("agent-1"),
            platform="linux",
        )
        test_context.track_device(enrollment_1.device_id)

        enrollment_2 = await admin_client.create_enrollment(
            name=generate_test_id("agent-2"),
            platform="linux",
        )
        test_context.track_device(enrollment_2.device_id)

        # Step 2: Enroll both agents
        await agent_1.enroll(enrollment_1.token)
        await agent_2.enroll(enrollment_2.token)

        # Wait for enrollments
        await wait_for_condition(
            lambda: agent_1.is_enrolled(),
            timeout=config.enrollment_timeout,
            description="agent-1 enrollment",
        )
        await wait_for_condition(
            lambda: agent_2.is_enrolled(),
            timeout=config.enrollment_timeout,
            description="agent-2 enrollment",
        )

        # Step 3: Connect to control plane
        await agent_1.connect()
        await agent_2.connect()

        await wait_for_condition(
            lambda: agent_1.is_connected(),
            timeout=30,
            description="agent-1 connection",
        )
        await wait_for_condition(
            lambda: agent_2.is_connected(),
            timeout=30,
            description="agent-2 connection",
        )

        # Step 4: Wait for devices to become active
        await wait_for_condition(
            lambda: self._device_is_active(admin_client, enrollment_1.device_id),
            timeout=30,
            description="agent-1 active",
        )
        await wait_for_condition(
            lambda: self._device_is_active(admin_client, enrollment_2.device_id),
            timeout=30,
            description="agent-2 active",
        )

        # Step 5: Create pod
        pod = await admin_client.create_pod(
            name=generate_test_id("pod"),
            description="E2E test pod",
        )
        test_context.track_pod(pod.id)

        # Step 6: Add devices to pod
        await admin_client.add_device_to_pod(pod.id, enrollment_1.device_id)
        await admin_client.add_device_to_pod(pod.id, enrollment_2.device_id)

        # Step 7: Create allow policy
        policy = await admin_client.create_policy(
            source_pod_id=pod.id,
            destination_pod_id=pod.id,
            action="allow",
        )
        test_context.track_policy(policy.id)

        # Step 8: Request tunnel from agent-1 to agent-2
        tunnel_result = await agent_1.request_tunnel(enrollment_2.device_id)
        assert "session_id" in tunnel_result

        # Step 9: Wait for tunnel to be established
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(enrollment_2.device_id),
            timeout=config.tunnel_timeout,
            description="tunnel establishment",
        )

        # Step 10: Verify tunnel exists on both sides
        agent_1_tunnels = await agent_1.list_tunnels()
        assert len(agent_1_tunnels) >= 1
        assert any(t.peer_device_id == enrollment_2.device_id for t in agent_1_tunnels)

        agent_2_tunnels = await agent_2.list_tunnels()
        assert len(agent_2_tunnels) >= 1
        assert any(t.peer_device_id == enrollment_1.device_id for t in agent_2_tunnels)

        # Step 11: Send test data
        test_data = b"Hello AVON E2E Test!"
        await agent_1.send_test_data(enrollment_2.device_id, test_data)

        # Step 12: Receive and verify data
        received = await agent_2.receive_test_data(timeout=10)
        assert received == test_data

        # Step 13: Send data in reverse direction
        reverse_data = b"Response from agent-2!"
        await agent_2.send_test_data(enrollment_1.device_id, reverse_data)

        received_reverse = await agent_1.receive_test_data(timeout=10)
        assert received_reverse == reverse_data

        print("Full flow test passed!")

    async def test_tunnel_survives_reconnection(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        pod_with_policy,
    ):
        """Test that tunnel survives control plane reconnection."""
        device_1_id, device_2_id, pod_id, policy_id = pod_with_policy

        # Establish tunnel
        await agent_1.request_tunnel(device_2_id)
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel establishment",
        )

        # Send initial data to verify tunnel works
        await agent_1.send_test_data(device_2_id, b"Before reconnect")
        received = await agent_2.receive_test_data(timeout=10)
        assert received == b"Before reconnect"

        # Disconnect and reconnect agent-1
        await agent_1.disconnect()
        await wait_for_condition(
            lambda: self._not_connected(agent_1),
            timeout=10,
            description="agent-1 disconnection",
        )

        await agent_1.connect()
        await wait_for_condition(
            lambda: agent_1.is_connected(),
            timeout=30,
            description="agent-1 reconnection",
        )

        # Verify tunnel still works (or is re-established)
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel after reconnect",
        )

        # Send data after reconnection
        await agent_1.send_test_data(device_2_id, b"After reconnect")
        received = await agent_2.receive_test_data(timeout=10)
        assert received == b"After reconnect"

    async def test_large_data_transfer(
        self,
        agent_1: AgentClient,
        agent_2: AgentClient,
        pod_with_policy,
    ):
        """Test transfer of larger data payloads."""
        device_1_id, device_2_id, pod_id, policy_id = pod_with_policy

        # Establish tunnel
        await agent_1.request_tunnel(device_2_id)
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel establishment",
        )

        # Send 1MB of data in chunks
        chunk_size = 64 * 1024  # 64KB chunks
        total_size = 1024 * 1024  # 1MB total
        test_data = bytes(range(256)) * (chunk_size // 256)

        chunks_sent = 0
        for offset in range(0, total_size, chunk_size):
            chunk = test_data[:min(chunk_size, total_size - offset)]
            await agent_1.send_test_data(device_2_id, chunk)
            chunks_sent += 1

        # Receive and count chunks
        chunks_received = 0
        total_received = 0
        for _ in range(chunks_sent):
            received = await agent_2.receive_test_data(timeout=30)
            if received:
                chunks_received += 1
                total_received += len(received)

        assert chunks_received == chunks_sent
        assert total_received == total_size

    @staticmethod
    async def _device_is_active(client: AdminClient, device_id: str) -> bool:
        """Check if device is active."""
        try:
            device = await client.get_device(device_id)
            return device.status == "active"
        except Exception:
            return False

    @staticmethod
    async def _not_connected(agent: AgentClient) -> bool:
        """Check if agent is not connected."""
        return not await agent.is_connected()


@pytest.mark.asyncio
async def test_simple_enrollment(
    admin_client: AdminClient,
    agent_1: AgentClient,
    test_context: TestContext,
):
    """Simple test that enrollment works."""
    enrollment = await admin_client.create_enrollment(
        name=generate_test_id("simple"),
        platform="linux",
    )
    test_context.track_device(enrollment.device_id)

    assert enrollment.token is not None
    assert enrollment.device_id is not None

    # Enroll the agent
    result = await agent_1.enroll(enrollment.token)
    assert result is not None

    # Wait for enrollment
    await wait_for_condition(
        lambda: agent_1.is_enrolled(),
        timeout=config.enrollment_timeout,
        description="enrollment",
    )

    assert await agent_1.is_enrolled()
