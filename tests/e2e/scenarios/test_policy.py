"""Policy end to end: authored through the admin API, enforced at the gateway."""
import time

import pytest

from lib.agent import Agent

pytestmark = pytest.mark.l4

HTTP_TARGET = "172.30.0.10"


def test_authoring_a_policy_turns_a_tenant_zero_trust_and_deny_overrides_allow(agents, admin, witness):
    """A tenant with no policy is unconfigured, not deny-everything: the gateway
    is permissive until the first policy exists, matching the control plane's
    session admission. Authoring one policy flips the tenant to zero-trust, so
    only the permitted port passes; and an explicit deny then overrides the
    allow."""
    a = agents["agent-a"]
    st = a.wait_connected()

    # Unconfigured tenant: the data plane carries traffic before any policy.
    before = a.tcp_open(HTTP_TARGET, 80)
    witness("port 80 before any policy (unconfigured tenant is permissive)", before)
    assert before, "an unconfigured tenant is permissive, matching session admission"

    pod = admin.create_pod("eng")
    admin.add_device_to_pod(st["device_id"], pod)
    admin.create_policy({
        "version": 2, "effect": "allow",
        "source": {"pods": [pod]},
        "destination": {"cidrs": ["172.30.0.0/24"]},
        "l4": [{"protocol": "tcp", "ports": "80"}],
    })
    # Now configured: 80 is permitted, and 443 -- with no matching permit -- is
    # denied. The transition from permissive to zero-trust is what we assert.
    admin.wait_until(lambda: not a.tcp_open(HTTP_TARGET, 443), timeout=10)
    witness("port 443 once the tenant is configured", False)
    assert a.tcp_open(HTTP_TARGET, 80), "the permitted port stays open"
    witness("port 80 under the allow", True)

    explained = admin.explain(st["device_id"], HTTP_TARGET, "tcp", 80)
    witness("explain", explained)
    assert explained["allow"] is True

    # Deny overrides allow: an explicit deny for the target closes 80.
    admin.create_policy({
        "version": 2, "effect": "deny", "source": {"any": True},
        "destination": {"cidrs": [f"{HTTP_TARGET}/32"]},
    })
    start = time.time()
    admin.wait_until(lambda: not a.tcp_open(HTTP_TARGET, 80), timeout=5)
    elapsed = time.time() - start
    witness("seconds until the deny took effect", round(elapsed, 2))
    assert elapsed < 5


def test_a_deny_policy_overrides_an_allow(agents, admin, witness):
    a = agents["agent-b"]
    st = a.wait_connected()
    pod = admin.create_pod("override")
    admin.add_device_to_pod(st["device_id"], pod)
    admin.create_policy({
        "version": 2, "effect": "allow", "source": {"pods": [pod]},
        "destination": {"cidrs": ["172.30.0.0/24"]}, "l4": [{"protocol": "tcp", "ports": "80"}],
    })
    admin.wait_until(lambda: a.tcp_open(HTTP_TARGET, 80), timeout=10)
    witness("port 80 under allow alone", True)
    admin.create_policy({
        "version": 2, "effect": "deny", "source": {"any": True},
        "destination": {"cidrs": [f"{HTTP_TARGET}/32"]},
    })
    admin.wait_until(lambda: not a.tcp_open(HTTP_TARGET, 80), timeout=5)
    witness("port 80 once a deny is added", False)


@pytest.mark.missing(
    reason="posture.firewall_enabled is never collected: platform/posture/linux.rs:43 "
           "hard-codes None (macos.rs and windows.rs likewise), so a policy conditioned "
           "on it can never match, and there is no `avon-agent debug set-posture` to "
           "stand in for a real collector"
)
def test_posture_change_blocks_a_flow_within_one_pulse():
    ...


def test_pending_approval_gates_a_new_device(compose, admin, witness):
    """A device enrolled under a token that requires approval is recorded as
    pending, is refused by control until an admin approves it, and connects
    once approved.

    agent-c enrolled at container start with the shared bootstrap token, so it
    is re-enrolled here from scratch: wipe its data directory, drop the
    approval-gated token where the entrypoint looks first, and restart it.
    """
    name = f"agent-c-pending-{int(time.time())}"
    token = admin.create_enroll_token(
        device_name=name, require_approval=True, max_uses=1, expires_in_hours=1,
    )
    compose.exec(
        "agent-c", "sh", "-c",
        f"rm -rf /var/lib/avon/* && printf '%s' '{token}' > /var/lib/avon/enroll.token",
    )
    compose.restart("agent-c")
    c = Agent(compose, "agent-c")

    pending = admin.wait_until(
        lambda: [d for d in admin.pending_devices() if d["name"] == name] or None,
        timeout=60,
    )
    witness("pending devices named for this run", pending)
    assert len(pending) == 1
    device_id = pending[0]["id"]

    # Give the run loop several attempts to authenticate before judging.
    time.sleep(5)
    st = c.try_status()
    witness("agent-c status while pending", st)
    assert (st or {}).get("state") != "connected", "a pending device must not be admitted"

    admin.approve_device(device_id)
    st = c.wait_connected(timeout=60)
    witness("agent-c status after approval", st)
    device = admin.device(device_id)
    witness("device record after approval", device)
    assert device["status"] == "active"
