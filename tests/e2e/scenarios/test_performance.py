"""End-to-End Test: Performance

Tests that measure AVON's performance characteristics:
1. Enrollment latency
2. Tunnel establishment latency
3. Data throughput
4. Concurrent tunnel capacity
"""

import pytest
import pytest_asyncio
import asyncio
import time
from typing import List, Tuple
from dataclasses import dataclass

from lib.admin_client import AdminClient
from lib.agent_client import AgentClient
from lib.config import config
from lib.helpers import generate_test_id, wait_for_condition, TestContext


@dataclass
class LatencyResult:
    """Result of a latency measurement."""
    operation: str
    latency_ms: float
    success: bool
    error: str = ""


@dataclass
class ThroughputResult:
    """Result of a throughput measurement."""
    bytes_sent: int
    bytes_received: int
    duration_seconds: float
    throughput_mbps: float


@pytest.mark.asyncio
class TestPerformance:
    """Performance measurement tests."""

    async def test_enrollment_latency(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        test_context: TestContext,
    ):
        """Measure enrollment latency."""
        # Create enrollment
        enrollment = await admin_client.create_enrollment(
            name=generate_test_id("perf-enroll"),
            platform="linux",
        )
        test_context.track_device(enrollment.device_id)

        # Measure enrollment time
        start = time.perf_counter()
        await agent_1.enroll(enrollment.token)

        await wait_for_condition(
            lambda: agent_1.is_enrolled(),
            timeout=config.enrollment_timeout,
            description="enrollment",
        )
        enrollment_latency = (time.perf_counter() - start) * 1000

        # Connect and measure
        start = time.perf_counter()
        await agent_1.connect()
        await wait_for_condition(
            lambda: agent_1.is_connected(),
            timeout=30,
            description="connection",
        )
        connection_latency = (time.perf_counter() - start) * 1000

        print(f"\nEnrollment latency: {enrollment_latency:.2f}ms")
        print(f"Connection latency: {connection_latency:.2f}ms")

        # Assert reasonable latencies
        assert enrollment_latency < 10000, f"Enrollment too slow: {enrollment_latency}ms"
        assert connection_latency < 5000, f"Connection too slow: {connection_latency}ms"

    async def test_tunnel_establishment_latency(
        self,
        agent_1: AgentClient,
        agent_2: AgentClient,
        pod_with_policy,
    ):
        """Measure tunnel establishment latency."""
        device_1_id, device_2_id, pod_id, policy_id = pod_with_policy

        # Measure tunnel establishment
        start = time.perf_counter()
        await agent_1.request_tunnel(device_2_id)

        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel",
        )
        tunnel_latency = (time.perf_counter() - start) * 1000

        print(f"\nTunnel establishment latency: {tunnel_latency:.2f}ms")

        # Assert reasonable latency (tunnel handshake involves crypto)
        assert tunnel_latency < 5000, f"Tunnel establishment too slow: {tunnel_latency}ms"

    async def test_small_message_latency(
        self,
        agent_1: AgentClient,
        agent_2: AgentClient,
        pod_with_policy,
    ):
        """Measure round-trip latency for small messages."""
        device_1_id, device_2_id, pod_id, policy_id = pod_with_policy

        # Establish tunnel
        await agent_1.request_tunnel(device_2_id)
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel",
        )

        # Warm up
        for _ in range(5):
            await agent_1.send_test_data(device_2_id, b"warmup")
            await agent_2.receive_test_data(timeout=5)

        # Clear buffer
        await agent_2.clear_test_buffer()

        # Measure latency for small messages
        latencies = []
        for i in range(100):
            test_data = f"ping-{i}".encode()

            start = time.perf_counter()
            await agent_1.send_test_data(device_2_id, test_data)
            received = await agent_2.receive_test_data(timeout=5)
            latency = (time.perf_counter() - start) * 1000

            if received == test_data:
                latencies.append(latency)

        # Calculate statistics
        if latencies:
            avg_latency = sum(latencies) / len(latencies)
            min_latency = min(latencies)
            max_latency = max(latencies)
            p50 = sorted(latencies)[len(latencies) // 2]
            p99 = sorted(latencies)[int(len(latencies) * 0.99)]

            print(f"\nSmall message latency (n={len(latencies)}):")
            print(f"  Average: {avg_latency:.2f}ms")
            print(f"  Min: {min_latency:.2f}ms")
            print(f"  Max: {max_latency:.2f}ms")
            print(f"  P50: {p50:.2f}ms")
            print(f"  P99: {p99:.2f}ms")

            # Assert reasonable latencies
            assert avg_latency < 100, f"Average latency too high: {avg_latency}ms"
            assert p99 < 500, f"P99 latency too high: {p99}ms"

    async def test_throughput(
        self,
        agent_1: AgentClient,
        agent_2: AgentClient,
        pod_with_policy,
    ):
        """Measure data throughput."""
        device_1_id, device_2_id, pod_id, policy_id = pod_with_policy

        # Establish tunnel
        await agent_1.request_tunnel(device_2_id)
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel",
        )

        # Generate test data (64KB chunks)
        chunk_size = 64 * 1024
        num_chunks = 16  # 1MB total
        test_data = bytes(range(256)) * (chunk_size // 256)

        # Clear buffer
        await agent_2.clear_test_buffer()

        # Measure throughput
        start = time.perf_counter()

        for _ in range(num_chunks):
            await agent_1.send_test_data(device_2_id, test_data)

        # Wait for all data to be received
        received_bytes = 0
        for _ in range(num_chunks):
            received = await agent_2.receive_test_data(timeout=30)
            if received:
                received_bytes += len(received)

        duration = time.perf_counter() - start
        total_bytes = chunk_size * num_chunks
        throughput_mbps = (received_bytes * 8) / (duration * 1_000_000)

        print(f"\nThroughput test:")
        print(f"  Sent: {total_bytes / 1024 / 1024:.2f} MB")
        print(f"  Received: {received_bytes / 1024 / 1024:.2f} MB")
        print(f"  Duration: {duration:.2f}s")
        print(f"  Throughput: {throughput_mbps:.2f} Mbps")

        # Assert reasonable throughput (at least 1 Mbps in containers)
        assert throughput_mbps >= 1.0, f"Throughput too low: {throughput_mbps} Mbps"
        assert received_bytes >= total_bytes * 0.95, "Too much data loss"

    async def test_concurrent_tunnels(
        self,
        admin_client: AdminClient,
        agent_1: AgentClient,
        agent_2: AgentClient,
        enrolled_agents,
        test_context: TestContext,
    ):
        """Test performance with multiple concurrent tunnel requests."""
        device_1_id, device_2_id = enrolled_agents

        # Create pod and policy
        pod = await admin_client.create_pod(name=generate_test_id("concurrent-pod"))
        test_context.track_pod(pod.id)

        await admin_client.add_device_to_pod(pod.id, device_1_id)
        await admin_client.add_device_to_pod(pod.id, device_2_id)

        policy = await admin_client.create_policy(
            source_pod_id=pod.id,
            destination_pod_id=pod.id,
            action="allow",
        )
        test_context.track_policy(policy.id)

        # Make multiple tunnel requests in parallel
        # (In practice, these might be separate device pairs)
        num_requests = 10
        start = time.perf_counter()

        async def request_and_verify():
            await agent_1.request_tunnel(device_2_id)
            # Small delay to avoid overwhelming
            await asyncio.sleep(0.1)

        # Note: With only 2 agents, we're testing the control plane's ability
        # to handle rapid requests, not actual concurrent tunnels
        tasks = [request_and_verify() for _ in range(num_requests)]
        await asyncio.gather(*tasks, return_exceptions=True)

        duration = time.perf_counter() - start
        requests_per_second = num_requests / duration

        print(f"\nConcurrent tunnel requests:")
        print(f"  Requests: {num_requests}")
        print(f"  Duration: {duration:.2f}s")
        print(f"  Rate: {requests_per_second:.2f} req/s")

        # Verify at least one tunnel was established
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel after concurrent requests",
        )

    @pytest.mark.slow
    async def test_sustained_throughput(
        self,
        agent_1: AgentClient,
        agent_2: AgentClient,
        pod_with_policy,
    ):
        """Test sustained throughput over time."""
        device_1_id, device_2_id, pod_id, policy_id = pod_with_policy

        # Establish tunnel
        await agent_1.request_tunnel(device_2_id)
        await wait_for_condition(
            lambda: agent_1.has_tunnel_to(device_2_id),
            timeout=config.tunnel_timeout,
            description="tunnel",
        )

        # Test sustained throughput for 30 seconds
        chunk_size = 32 * 1024  # 32KB chunks
        test_data = bytes(range(256)) * (chunk_size // 256)
        duration_seconds = 30

        start = time.perf_counter()
        total_sent = 0
        total_received = 0

        while time.perf_counter() - start < duration_seconds:
            await agent_1.send_test_data(device_2_id, test_data)
            total_sent += chunk_size

            received = await agent_2.receive_test_data(timeout=5)
            if received:
                total_received += len(received)

        actual_duration = time.perf_counter() - start
        throughput_mbps = (total_received * 8) / (actual_duration * 1_000_000)

        print(f"\nSustained throughput test:")
        print(f"  Duration: {actual_duration:.2f}s")
        print(f"  Sent: {total_sent / 1024 / 1024:.2f} MB")
        print(f"  Received: {total_received / 1024 / 1024:.2f} MB")
        print(f"  Throughput: {throughput_mbps:.2f} Mbps")

        # Verify sustained performance
        assert throughput_mbps >= 0.5, f"Sustained throughput too low: {throughput_mbps} Mbps"


@pytest.mark.asyncio
async def test_enrollment_under_load(
    admin_client: AdminClient,
    agent_1: AgentClient,
    test_context: TestContext,
):
    """Test enrollment performance under load."""
    # Create multiple enrollments rapidly
    num_enrollments = 5
    latencies = []

    for i in range(num_enrollments):
        start = time.perf_counter()

        enrollment = await admin_client.create_enrollment(
            name=generate_test_id(f"load-{i}"),
            platform="linux",
        )
        test_context.track_device(enrollment.device_id)

        latency = (time.perf_counter() - start) * 1000
        latencies.append(latency)

    avg_latency = sum(latencies) / len(latencies)
    print(f"\nEnrollment creation under load:")
    print(f"  Count: {num_enrollments}")
    print(f"  Average latency: {avg_latency:.2f}ms")

    assert avg_latency < 1000, f"Enrollment creation too slow under load: {avg_latency}ms"
