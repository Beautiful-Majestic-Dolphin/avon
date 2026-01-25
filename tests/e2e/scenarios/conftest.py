"""Pytest Configuration and Fixtures for E2E Tests"""

import asyncio
from typing import AsyncGenerator

import pytest
import pytest_asyncio

from lib.admin_client import AdminClient
from lib.agent_client import AgentClient
from lib.config import config
from lib.helpers import (
    cleanup_test_data,
    reset_test_environment,
    wait_for_service,
    TestContext,
)


# Configure pytest-asyncio
pytest_plugins = ["pytest_asyncio"]


def pytest_configure(config):
    """Configure custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "multi_peer: marks tests that require 3+ agents"
    )


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def wait_for_services():
    """Wait for all services to be ready before running tests."""
    print("\nWaiting for services to be ready...")

    # Wait for admin API
    await wait_for_service(f"{config.admin_api_url}/health", timeout=120)
    print("  - Admin API ready")

    # Wait for policy engine
    await wait_for_service(f"{config.policy_engine_url}/health", timeout=60)
    print("  - Policy Engine ready")

    # Wait for agents
    await wait_for_service(f"{config.agent_1_url}/health", timeout=60)
    print("  - Agent 1 ready")

    await wait_for_service(f"{config.agent_2_url}/health", timeout=60)
    print("  - Agent 2 ready")

    print("All services ready!")


@pytest_asyncio.fixture(scope="session")
async def clean_environment(wait_for_services):
    """Reset the test environment before running tests."""
    print("\nResetting test environment...")
    await reset_test_environment()
    print("Environment reset complete!")


@pytest_asyncio.fixture
async def admin_client(wait_for_services) -> AsyncGenerator[AdminClient, None]:
    """Provide an admin API client."""
    async with AdminClient(config.admin_api_url) as client:
        yield client


@pytest_asyncio.fixture
async def agent_1(wait_for_services) -> AsyncGenerator[AgentClient, None]:
    """Provide a client for agent-1."""
    async with AgentClient(config.agent_1_url) as client:
        yield client


@pytest_asyncio.fixture
async def agent_2(wait_for_services) -> AsyncGenerator[AgentClient, None]:
    """Provide a client for agent-2."""
    async with AgentClient(config.agent_2_url) as client:
        yield client


@pytest_asyncio.fixture
async def agent_3(wait_for_services) -> AsyncGenerator[AgentClient, None]:
    """Provide a client for agent-3 (only available with multi-peer profile)."""
    if not config.agent_3_url:
        pytest.skip("Agent 3 not available (requires multi-peer profile)")
    async with AgentClient(config.agent_3_url) as client:
        yield client


@pytest_asyncio.fixture
async def test_context() -> AsyncGenerator[TestContext, None]:
    """Provide a test context with automatic cleanup."""
    async with TestContext() as ctx:
        yield ctx


@pytest_asyncio.fixture
async def enrolled_agents(
    admin_client: AdminClient,
    agent_1: AgentClient,
    agent_2: AgentClient,
    test_context: TestContext,
):
    """Fixture that provides two enrolled and connected agents.

    Returns:
        Tuple of (agent_1_device_id, agent_2_device_id)
    """
    from lib.helpers import generate_test_id, wait_for_condition

    # Create enrollments
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

    # Enroll agents
    await agent_1.enroll(enrollment_1.token)
    await agent_2.enroll(enrollment_2.token)

    # Wait for enrollment to complete
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

    # Connect to control plane
    await agent_1.connect()
    await agent_2.connect()

    # Wait for connection
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

    # Wait for devices to become active
    await wait_for_condition(
        lambda: _device_is_active(admin_client, enrollment_1.device_id),
        timeout=30,
        description="agent-1 active status",
    )
    await wait_for_condition(
        lambda: _device_is_active(admin_client, enrollment_2.device_id),
        timeout=30,
        description="agent-2 active status",
    )

    return enrollment_1.device_id, enrollment_2.device_id


async def _device_is_active(client: AdminClient, device_id: str) -> bool:
    """Check if a device is active."""
    try:
        device = await client.get_device(device_id)
        return device.status == "active"
    except Exception:
        return False


@pytest_asyncio.fixture
async def pod_with_policy(
    admin_client: AdminClient,
    enrolled_agents,
    test_context: TestContext,
):
    """Fixture that provides enrolled agents in a pod with allow policy.

    Returns:
        Tuple of (device_1_id, device_2_id, pod_id, policy_id)
    """
    from lib.helpers import generate_test_id

    device_1_id, device_2_id = enrolled_agents

    # Create pod
    pod = await admin_client.create_pod(
        name=generate_test_id("pod"),
        description="E2E test pod",
    )
    test_context.track_pod(pod.id)

    # Add devices to pod
    await admin_client.add_device_to_pod(pod.id, device_1_id)
    await admin_client.add_device_to_pod(pod.id, device_2_id)

    # Create allow policy
    policy = await admin_client.create_policy(
        source_pod_id=pod.id,
        destination_pod_id=pod.id,
        action="allow",
    )
    test_context.track_policy(policy.id)

    return device_1_id, device_2_id, pod.id, policy.id
