"""End-to-End Test: Policy Enforcement

Tests that verify AVON's policy enforcement:
1. Allow policies permit tunnel establishment
2. Deny policies block tunnel establishment
3. Policy changes take effect on existing tunnels
4. Time-based and conditional policies
"""

import pytest
import pytest_asyncio
import asyncio

from lib.admin_client import AdminClient
from lib.agent_client import AgentClient
from lib.config import config
from lib.helpers import generate_test_id, wait_for_condition, TestContext


@pytest.mark.asyncio
class TestPolicyEnforcement:
    """Policy enforcement tests."""

    async def test_allow_policy_permits_tunnel(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        enrolled_agents,
        test_context: TestContext,
    ):
        """Test that an allow policy permits tunnel establishment."""
        device_1_id, device_2_id = enrolled_agents

        # Create pod and add devices
        pod = await admin_client.create_pod(
            name=generate_test_id("allow-pod"),
            description="Pod for allow policy test",
        )
        test_context.track_pod(pod.id)

        await admin_client.add_device_to_pod(pod.id, device_1_id)
        await admin_client.add_device_to_pod(pod.id, device_2_id)

        # Create allow policy
        policy = await admin_client.create_policy(
            source_pod_id=pod.id,
            destination_pod_id=pod.id,
            action="allow",
        )
        test_context.track_policy(policy.id)

        # Request tunnel - should succeed
        result = await agent_1.request_tunnel(device_2_id)
        assert "session_id" in result

        # Wait for tunnel establishment
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel with allow policy",
        )

        # Verify data can flow
        await agent_1.send_test_data(device_2_id, b"Policy test data")
        received = await agent_2.receive_test_data(timeout=10)
        assert received == b"Policy test data"

    async def test_deny_policy_blocks_tunnel(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        enrolled_agents,
        test_context: TestContext,
    ):
        """Test that a deny policy blocks tunnel establishment."""
        device_1_id, device_2_id = enrolled_agents

        # Create separate pods
        pod_1 = await admin_client.create_pod(
            name=generate_test_id("deny-pod-1"),
            description="Source pod",
        )
        test_context.track_pod(pod_1.id)

        pod_2 = await admin_client.create_pod(
            name=generate_test_id("deny-pod-2"),
            description="Destination pod",
        )
        test_context.track_pod(pod_2.id)

        await admin_client.add_device_to_pod(pod_1.id, device_1_id)
        await admin_client.add_device_to_pod(pod_2.id, device_2_id)

        # Create explicit deny policy
        policy = await admin_client.create_policy(
            source_pod_id=pod_1.id,
            destination_pod_id=pod_2.id,
            action="deny",
            priority=10,  # High priority
        )
        test_context.track_policy(policy.id)

        # Request tunnel - should fail
        result = await agent_1.request_tunnel(device_2_id)

        # Tunnel should not be established (or be rejected quickly)
        with pytest.raises(TimeoutError):
            await wait_for_condition(
                lambda: agent_1.has_tunnel_to(device_2_id),
                timeout=10,  # Short timeout since it should fail
                description="tunnel with deny policy (expected to fail)",
            )

    async def test_no_policy_denies_by_default(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        enrolled_agents,
        test_context: TestContext,
    ):
        """Test that default-deny works when no policy exists."""
        device_1_id, device_2_id = enrolled_agents

        # Create pods but NO policy
        pod_1 = await admin_client.create_pod(
            name=generate_test_id("no-policy-1"),
        )
        test_context.track_pod(pod_1.id)

        pod_2 = await admin_client.create_pod(
            name=generate_test_id("no-policy-2"),
        )
        test_context.track_pod(pod_2.id)

        await admin_client.add_device_to_pod(pod_1.id, device_1_id)
        await admin_client.add_device_to_pod(pod_2.id, device_2_id)

        # Request tunnel - should fail due to default deny
        await agent_1.request_tunnel(device_2_id)

        # Verify tunnel is not established
        with pytest.raises(TimeoutError):
            await wait_for_condition(
                lambda: agent_1.has_tunnel_to(device_2_id),
                timeout=10,
                description="tunnel without policy (expected to fail)",
            )

    async def test_policy_priority_enforcement(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        enrolled_agents,
        test_context: TestContext,
    ):
        """Test that policy priority is respected (lower number = higher priority)."""
        device_1_id, device_2_id = enrolled_agents

        # Create pods
        pod = await admin_client.create_pod(
            name=generate_test_id("priority-pod"),
        )
        test_context.track_pod(pod.id)

        await admin_client.add_device_to_pod(pod.id, device_1_id)
        await admin_client.add_device_to_pod(pod.id, device_2_id)

        # Create low-priority allow policy
        allow_policy = await admin_client.create_policy(
            source_pod_id=pod.id,
            destination_pod_id=pod.id,
            action="allow",
            priority=100,  # Lower priority (higher number)
        )
        test_context.track_policy(allow_policy.id)

        # Create high-priority deny policy
        deny_policy = await admin_client.create_policy(
            source_pod_id=pod.id,
            destination_pod_id=pod.id,
            action="deny",
            priority=10,  # Higher priority (lower number)
        )
        test_context.track_policy(deny_policy.id)

        # Tunnel should be denied because deny has higher priority
        await agent_1.request_tunnel(device_2_id)

        with pytest.raises(TimeoutError):
            await wait_for_condition(
                lambda: agent_1.has_tunnel_to(device_2_id),
                timeout=10,
                description="tunnel with priority deny",
            )

    async def test_policy_removal_closes_tunnel(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        enrolled_agents,
        test_context: TestContext,
    ):
        """Test that removing an allow policy closes existing tunnels."""
        device_1_id, device_2_id = enrolled_agents

        # Create pod and policy
        pod = await admin_client.create_pod(
            name=generate_test_id("removal-pod"),
        )
        test_context.track_pod(pod.id)

        await admin_client.add_device_to_pod(pod.id, device_1_id)
        await admin_client.add_device_to_pod(pod.id, device_2_id)

        policy = await admin_client.create_policy(
            source_pod_id=pod.id,
            destination_pod_id=pod.id,
            action="allow",
        )
        # Don't track - we'll delete it manually

        # Establish tunnel
        await agent_1.request_tunnel(device_2_id)
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel establishment",
        )

        # Verify tunnel works
        await agent_1.send_test_data(device_2_id, b"Before policy removal")
        received = await agent_2.receive_test_data(timeout=10)
        assert received == b"Before policy removal"

        # Delete the policy
        await admin_client.delete_policy(policy.id)

        # Wait for tunnel to be closed
        await wait_for_condition(
            lambda: self._no_tunnel(agent_1, device_2_id),
            timeout=30,
            description="tunnel closure after policy removal",
        )

        # Verify no tunnels remain
        tunnels = await agent_1.list_tunnels()
        active_to_peer = [t for t in tunnels if t.peer_device_id == device_2_id and t.state == "active"]
        assert len(active_to_peer) == 0

    async def test_device_suspension_closes_tunnel(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        enrolled_agents,
        test_context: TestContext,
    ):
        """Test that suspending a device closes its tunnels."""
        device_1_id, device_2_id = enrolled_agents

        # Create pod and policy
        pod = await admin_client.create_pod(
            name=generate_test_id("suspend-pod"),
        )
        test_context.track_pod(pod.id)

        await admin_client.add_device_to_pod(pod.id, device_1_id)
        await admin_client.add_device_to_pod(pod.id, device_2_id)

        policy = await admin_client.create_policy(
            source_pod_id=pod.id,
            destination_pod_id=pod.id,
            action="allow",
        )
        test_context.track_policy(policy.id)

        # Establish tunnel
        await agent_1.request_tunnel(device_2_id)
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel establishment",
        )

        # Suspend device 2
        await admin_client.suspend_device(device_2_id)

        # Wait for tunnel to close
        await wait_for_condition(
            lambda: self._no_tunnel(agent_1, device_2_id),
            timeout=30,
            description="tunnel closure after suspension",
        )

        # Reactivate for cleanup
        await admin_client.reactivate_device(device_2_id)

    async def test_pod_membership_change_affects_policy(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        enrolled_agents,
        test_context: TestContext,
    ):
        """Test that removing a device from a pod affects its policy evaluation."""
        device_1_id, device_2_id = enrolled_agents

        # Create pod and policy
        pod = await admin_client.create_pod(
            name=generate_test_id("membership-pod"),
        )
        test_context.track_pod(pod.id)

        await admin_client.add_device_to_pod(pod.id, device_1_id)
        await admin_client.add_device_to_pod(pod.id, device_2_id)

        policy = await admin_client.create_policy(
            source_pod_id=pod.id,
            destination_pod_id=pod.id,
            action="allow",
        )
        test_context.track_policy(policy.id)

        # Establish tunnel
        await agent_1.request_tunnel(device_2_id)
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel establishment",
        )

        # Remove device 2 from pod
        await admin_client.remove_device_from_pod(pod.id, device_2_id)

        # Wait for tunnel to close (policy no longer applies)
        await wait_for_condition(
            lambda: self._no_tunnel(agent_1, device_2_id),
            timeout=30,
            description="tunnel closure after membership change",
        )

    @staticmethod
    async def _no_tunnel(agent: AgentClient, peer_device_id: str) -> bool:
        """Check if there's no active tunnel to peer."""
        return not await agent.has_tunnel_to(peer_device_id)


@pytest.mark.asyncio
async def test_bidirectional_policy(
    admin_client: AdminClient,
    agent_1: AgentClient,
    agent_2: AgentClient,
    enrolled_agents,
    test_context: TestContext,
):
    """Test that policies are evaluated correctly for both directions."""
    device_1_id, device_2_id = enrolled_agents

    # Create pods
    pod = await admin_client.create_pod(name=generate_test_id("bidir-pod"))
    test_context.track_pod(pod.id)

    await admin_client.add_device_to_pod(pod.id, device_1_id)
    await admin_client.add_device_to_pod(pod.id, device_2_id)

    # Create bidirectional policy
    policy = await admin_client.create_policy(
        source_pod_id=pod.id,
        destination_pod_id=pod.id,
        action="allow",
    )
    test_context.track_policy(policy.id)

    # Test tunnel from agent-1 to agent-2
    await agent_1.request_tunnel(device_2_id)
    await wait_for_condition(
        lambda: agent_1.has_tunnel_to(device_2_id),
        timeout=config.tunnel_timeout,
        description="tunnel 1->2",
    )

    # Close that tunnel
    tunnels = await agent_1.list_tunnels()
    for t in tunnels:
        if t.peer_device_id == device_2_id:
            await agent_1.close_tunnel(t.session_id)

    await asyncio.sleep(2)  # Wait for tunnel cleanup

    # Test tunnel from agent-2 to agent-1
    await agent_2.request_tunnel(device_1_id)
    await wait_for_condition(
        lambda: agent_2.has_tunnel_to(device_1_id),
        timeout=config.tunnel_timeout,
        description="tunnel 2->1",
    )
