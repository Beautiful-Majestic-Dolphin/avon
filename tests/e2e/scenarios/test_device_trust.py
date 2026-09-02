"""Device trust end to end: hardware-backed identity, attestation-gated policy,
and fail-closed behaviour when the tunnel is down.

`agent-tpm` runs a binary built with the `tpm2` feature against the `swtpm`
service, so these exercise the real provider: keys sealed under a TPM primary,
and `TPM2_Quote` answered by a restricted attestation key that the control plane
verifies and pins.
"""

import time

import pytest

pytestmark = pytest.mark.l5

HTTP_TARGET = "172.30.0.10"


def test_tpm_backed_agent_reports_its_provider_and_becomes_verified(agents, admin, witness):
    a = agents["agent-tpm"]
    st = a.wait_connected(timeout=180)
    provider = a.key_provider()
    witness("key provider", provider)
    assert provider == "tpm2", "the TPM sidecar should have been used"
    device = admin.wait_until(
        lambda: (d := admin.device(st["device_id"]))["attestation_state"] == "verified" and d,
        timeout=120,
    )
    witness("device record once verified", device)
    assert device["attestation"]["pcr_digest"]
    assert device["key_provider"] == "tpm2"


def test_a_software_agent_never_reaches_verified(agents, admin, witness):
    """A device with no attestation hardware must not drift into `verified`
    just because it is well behaved."""
    a = agents["agent-a"]
    st = a.wait_connected()
    provider = a.key_provider()
    witness("key provider", provider)
    assert provider == "software"
    time.sleep(30)  # more than one pulse interval
    state = admin.device(st["device_id"])["attestation_state"]
    witness("attestation state after 30s", state)
    assert state in ("none", "unverified", "failed")


def test_policy_requiring_verified_attestation_admits_only_the_tpm_agent(agents, admin, witness):
    tpm, soft = agents["agent-tpm"], agents["agent-a"]
    tpm.wait_connected(timeout=180)
    soft.wait_connected()
    pod = admin.create_pod("attested")
    for ag in (tpm, soft):
        admin.add_device_to_pod(ag.status()["device_id"], pod)
    admin.wait_until(
        lambda: admin.device(tpm.status()["device_id"])["attestation_state"] == "verified",
        timeout=120,
    )
    witness("tpm agent attestation state", "verified")

    admin.create_policy(
        {
            "version": 2,
            "effect": "allow",
            "source": {"pods": [pod]},
            "destination": {"cidrs": ["172.30.0.0/24"]},
            "l4": [{"protocol": "tcp", "ports": "80"}],
            "conditions": {"attestation": "verified"},
        }
    )
    admin.wait_until(lambda: tpm.tcp_open(HTTP_TARGET, 80), timeout=15)
    witness("port 80 from the tpm agent", True)
    soft_open = soft.tcp_open(HTTP_TARGET, 80)
    witness("port 80 from the software agent", soft_open)
    assert not soft_open, "an unattested device must not match the policy"


def test_a_cloned_identity_directory_cannot_impersonate_the_tpm_device(compose, agents, witness):
    """Copy agent-tpm's data directory into a container without that TPM: the
    sealed material must not open, so the clone cannot authenticate."""
    agents["agent-tpm"].wait_connected(timeout=180)
    compose.exec("agent-tpm", "sh", "-c", "tar -C /var/lib/avon -cf /shared/clone.tar .")
    compose.exec(
        "agent-clone",
        "sh",
        "-c",
        "mkdir -p /var/lib/avon && tar -C /var/lib/avon -xf /shared/clone.tar",
    )
    rc, out = compose.exec_capture("agent-clone", "avon-agent", "status", "--json")
    witness("clone status before running", (rc, out.strip()))
    assert rc != 0 or '"state":"connected"' not in out, (
        f"a cloned directory must not yield a working identity: {out}"
    )
    # The clone container is idle, so it has no config of its own: give it one
    # that points at the copied directory, which is the whole attack.
    rc, logs = compose.exec_capture(
        "agent-clone",
        "sh",
        "-c",
        "mkdir -p /etc/avon && printf 'control_plane = \"control:50051\"\\n"
        "data_dir = \"/var/lib/avon\"\\ntun_name = \"avon1\"\\n' > /etc/avon/agent.toml && "
        "timeout 20 avon-agent run --config /etc/avon/agent.toml --no-helper 2>&1 | head -20 || true",
        timeout=40,
    )
    witness("clone run log (head)", logs.strip()[:800])
    assert any(word in logs.lower() for word in ("unseal", "corrupt", "tpm", "identity")), logs


def test_fail_closed_firewall_blocks_protected_traffic_when_the_gateway_is_down(
    agents, compose, admin, witness
):
    a = agents["agent-a"]
    a.wait_connected()
    pod = admin.create_pod("failclosed")
    admin.add_device_to_pod(a.status()["device_id"], pod)
    admin.create_policy(
        {
            "version": 2,
            "effect": "allow",
            "source": {"pods": [pod]},
            "destination": {"cidrs": ["172.30.0.0/24"]},
            "l4": [{"protocol": "tcp", "ports": "80"}],
        }
    )
    admin.wait_until(lambda: a.tcp_open(HTTP_TARGET, 80), timeout=15)
    witness("port 80 with the gateway up", True)

    compose.stop("gateway")
    try:
        # The route is gone, but the firewall must keep the traffic from taking
        # the default path out of the container.
        deadline = time.time() + 10
        blocked_after = None
        start = time.time()
        while time.time() < deadline:
            if not a.tcp_open(HTTP_TARGET, 80, timeout=2):
                blocked_after = round(time.time() - start, 2)
                break
            time.sleep(0.5)
        witness("seconds until port 80 was blocked after the gateway stopped", blocked_after)
        if blocked_after is None:
            raise AssertionError("traffic to a protected CIDR continued after the tunnel dropped")
        leaks = a.protected_route_leaks(HTTP_TARGET)
        witness("route to the protected target leaves by a non-tunnel interface", leaks)
        assert not leaks, "packets escaped outside the tunnel"
    finally:
        compose.start("gateway")
    a.wait_connected(timeout=120)
    admin.wait_until(lambda: a.tcp_open(HTTP_TARGET, 80), timeout=30)
    witness("port 80 after the gateway returned", True)
