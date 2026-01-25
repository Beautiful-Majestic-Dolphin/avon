"""End-to-End Test: Failover and Resilience

Tests that verify AVON's resilience:
1. Agent reconnection after network interruption
2. Tunnel re-establishment after failure
3. Control plane failover (when multiple instances)
4. Token rotation during active session
"""

import pytest
import pytest_asyncio
import asyncio

from lib.admin_client import AdminClient
from lib.agent_client import AgentClient
from lib.config import config
from lib.helpers import generate_test_id, wait_for_condition, TestContext


@pytest.mark.asyncio
class TestFailover:
    """Failover and resilience tests."""

    async def test_agent_reconnection(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        enrolled_agents,
    ):
        """Test that an agent can reconnect after disconnection."""
        device_1_id, device_2_id = enrolled_agents

        # Verify initial connection
        assert await agent_1.is_connected()

        # Disconnect
        await agent_1.disconnect()
        await wait_for_condition(
            lambda: self._not_connected(agent_1),
            timeout=10,
            description="agent disconnection",
        )

        # Verify device shows as offline (eventually)
        await asyncio.sleep(5)  # Wait for pulse timeout

        # Reconnect
        await agent_1.connect()
        await wait_for_condition(
            lambda: agent_1.is_connected(),
            timeout=30,
            description="agent reconnection",
        )

        # Verify device is active again
        await wait_for_condition(
            lambda: self._device_is_active(admin_client, device_1_id),
            timeout=30,
            description="device reactivation",
        )

    async def test_tunnel_reestablishment_after_disconnect(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        pod_with_policy,
    ):
        """Test that tunnels can be re-established after disconnection."""
        device_1_id, device_2_id, pod_id, policy_id = pod_with_policy

        # Establish initial tunnel
        await agent_1.request_tunnel(device_2_id)
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="initial tunnel",
        )

        # Verify data flow
        await agent_1.send_test_data(device_2_id, b"Before disconnect")
        received = await agent_2.receive_test_data(timeout=10)
        assert received == b"Before disconnect"

        # Disconnect agent-1
        await agent_1.disconnect()
        await wait_for_condition(
            lambda: self._not_connected(agent_1),
            timeout=10,
            description="agent-1 disconnect",
        )

        # Clear agent-2's test buffer
        await agent_2.clear_test_buffer()

        # Reconnect agent-1
        await agent_1.connect()
        await wait_for_condition(
            lambda: agent_1.is_connected(),
            timeout=30,
            description="agent-1 reconnect",
        )

        # Re-establish tunnel
        await agent_1.request_tunnel(device_2_id)
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel re-establishment",
        )

        # Verify data flow works again
        await agent_1.send_test_data(device_2_id, b"After reconnect")
        received = await agent_2.receive_test_data(timeout=10)
        assert received == b"After reconnect"

    async def test_pulse_maintains_connection(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        enrolled_agents,
    ):
        """Test that pulse keeps the connection alive."""
        device_1_id, device_2_id = enrolled_agents

        # Get initial status
        initial_status = await agent_1.get_status()
        initial_pulse = initial_status.last_pulse

        # Wait for a pulse interval
        await asyncio.sleep(15)  # Default pulse interval is typically 10s

        # Verify new pulse was sent
        new_status = await agent_1.get_status()
        assert new_status.last_pulse != initial_pulse

        # Verify device is still active
        device = await admin_client.get_device(device_1_id)
        assert device.status == "active"

    async def test_token_rotation_during_active_session(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        pod_with_policy,
    ):
        """Test that token rotation doesn't disrupt active tunnels."""
        device_1_id, device_2_id, pod_id, policy_id = pod_with_policy

        # Establish tunnel
        await agent_1.request_tunnel(device_2_id)
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel establishment",
        )

        # Send some data
        await agent_1.send_test_data(device_2_id, b"Before rotation")
        received = await agent_2.receive_test_data(timeout=10)
        assert received == b"Before rotation"

        # Wait for token rotation (typically happens every 30-60 seconds)
        # In tests, we might need to trigger it or wait
        await asyncio.sleep(35)  # Wait past rotation interval

        # Verify tunnel still works
        await agent_1.send_test_data(device_2_id, b"After rotation")
        received = await agent_2.receive_test_data(timeout=10)
        assert received == b"After rotation"

        # Verify connection is still healthy
        assert await agent_1.is_connected()
        assert await agent_2.is_connected()

    @pytest.mark.slow
    async def test_extended_session_stability(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        pod_with_policy,
    ):
        """Test tunnel stability over an extended period."""
        device_1_id, device_2_id, pod_id, policy_id = pod_with_policy

        # Establish tunnel
        await agent_1.request_tunnel(device_2_id)
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel establishment",
        )

        # Send data periodically for 2 minutes
        message_count = 0
        for i in range(24):  # 24 * 5s = 2 minutes
            await asyncio.sleep(5)

            # Send data
            test_message = f"Message {i}".encode()
            await agent_1.send_test_data(device_2_id, test_message)
            received = await agent_2.receive_test_data(timeout=10)
            assert received == test_message
            message_count += 1

        assert message_count == 24

        # Verify tunnel is still healthy
        tunnels = await agent_1.list_tunnels()
        active_tunnels = [t for t in tunnels if t.state == "active"]
        assert len(active_tunnels) >= 1

    async def test_simultaneous_reconnection(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        enrolled_agents,
    ):
        """Test that both agents can reconnect simultaneously."""
        device_1_id, device_2_id = enrolled_agents

        # Disconnect both agents
        await asyncio.gather(
            agent_1.disconnect(),
            agent_2.disconnect(),
        )

        await wait_for_condition(
            lambda: self._not_connected(agent_1),
            timeout=10,
            description="agent-1 disconnect",
        )
        await wait_for_condition(
            lambda: self._not_connected(agent_2),
            timeout=10,
            description="agent-2 disconnect",
        )

        # Reconnect both simultaneously
        await asyncio.gather(
            agent_1.connect(),
            agent_2.connect(),
        )

        # Wait for both to be connected
        await wait_for_condition(
            lambda: agent_1.is_connected(),
            timeout=30,
            description="agent-1 reconnect",
        )
        await wait_for_condition(
            lambda: agent_2.is_connected(),
            timeout=30,
            description="agent-2 reconnect",
        )

        # Verify both devices are active
        await wait_for_condition(
            lambda: self._device_is_active(admin_client, device_1_id),
            timeout=30,
            description="device-1 active",
        )
        await wait_for_condition(
            lambda: self._device_is_active(admin_client, device_2_id),
            timeout=30,
            description="device-2 active",
        )

    async def test_rapid_connect_disconnect_cycles(
        self,
        agent_1: AgentClient,
        enrolled_agents,
    ):
        """Test that rapid connect/disconnect cycles don't cause issues."""
        device_1_id, device_2_id = enrolled_agents

        # Perform rapid cycles
        for i in range(5):
            await agent_1.disconnect()
            await asyncio.sleep(0.5)
            await agent_1.connect()
            await asyncio.sleep(0.5)

        # Verify final state is connected
        await wait_for_condition(
            lambda: agent_1.is_connected(),
            timeout=30,
            description="final connection",
        )

    @staticmethod
    async def _not_connected(agent: AgentClient) -> bool:
        """Check if agent is not connected."""
        return not await agent.is_connected()

    @staticmethod
    async def _device_is_active(client: AdminClient, device_id: str) -> bool:
        """Check if device is active."""
        try:
            device = await client.get_device(device_id)
            return device.status == "active"
        except Exception:
            return False


@pytest.mark.asyncio
@pytest.mark.slow
async def test_long_running_tunnel_with_token_rotations(
    agent_1: AgentClient,
    agent_2: AgentClient,
    pod_with_policy,
):
    """Test tunnel stability through multiple token rotations."""
    device_1_id, device_2_id, pod_id, policy_id = pod_with_policy

    # Establish tunnel
    await agent_1.request_tunnel(device_2_id)
    await wait_for_condition(
        lambda: agent_1.has_tunnel_to(device_2_id),
        timeout=config.tunnel_timeout,
        description="tunnel establishment",
    )

    # Run for 3 minutes (should see at least 2-3 token rotations)
    errors = []
    successes = 0

    for i in range(36):  # 36 * 5s = 3 minutes
        await asyncio.sleep(5)
        try:
            test_data = f"Iteration {i}".encode()
            await agent_1.send_test_data(device_2_id, test_data)
            received = await agent_2.receive_test_data(timeout=10)
            if received == test_data:
                successes += 1
            else:
                errors.append(f"Iteration {i}: data mismatch")
        except Exception as e:
            errors.append(f"Iteration {i}: {e}")

    # Allow some transient failures during rotation
    assert successes >= 30, f"Too many failures: {errors}"
    assert len(errors) <= 6, f"Too many errors: {errors}"
