"""Policy end to end: authored through the admin API, enforced at the gateway."""
import time


def test_default_deny_then_allow_by_port_then_deny_again(agents, admin):
    a = agents["agent-a"]
    st = a.wait_connected()
    assert not a.tcp_open("172.30.0.10", 80), "nothing is permitted before a policy exists"

    pod = admin.create_pod("eng")
    admin.add_device_to_pod(st["device_id"], pod)
    policy = admin.create_policy({
        "version": 2, "effect": "allow",
        "source": {"pods": [pod]},
        "destination": {"cidrs": ["172.30.0.0/24"]},
        "l4": [{"protocol": "tcp", "ports": "80"}],
    })
    admin.wait_until(lambda: a.tcp_open("172.30.0.10", 80), timeout=10)
    assert not a.tcp_open("172.30.0.10", 443), "only the listed port is allowed"

    explained = admin.explain(st["device_id"], "172.30.0.10", "tcp", 80)
    assert explained["allow"] is True

    admin.disable_policy(policy["id"])
    start = time.time()
    admin.wait_until(lambda: not a.tcp_open("172.30.0.10", 80), timeout=2)
    assert time.time() - start < 2.5


def test_a_deny_policy_overrides_an_allow(agents, admin):
    a = agents["agent-b"]
    st = a.wait_connected()
    pod = admin.create_pod("override")
    admin.add_device_to_pod(st["device_id"], pod)
    admin.create_policy({
        "version": 2, "effect": "allow", "source": {"pods": [pod]},
        "destination": {"cidrs": ["172.30.0.0/24"]}, "l4": [{"protocol": "tcp", "ports": "80"}],
    })
    admin.wait_until(lambda: a.tcp_open("172.30.0.10", 80), timeout=10)
    admin.create_policy({
        "version": 2, "effect": "deny", "source": {"any": True},
        "destination": {"cidrs": ["172.30.0.10/32"]},
    })
    admin.wait_until(lambda: not a.tcp_open("172.30.0.10", 80), timeout=5)


def test_posture_change_blocks_a_flow_within_one_pulse(agents, admin, compose):
    a = agents["agent-b"]
    st = a.wait_connected()
    pod = admin.create_pod("secure")
    admin.add_device_to_pod(st["device_id"], pod)
    admin.create_policy({
        "version": 2, "effect": "allow", "source": {"pods": [pod]},
        "destination": {"cidrs": ["172.30.0.0/24"]}, "l4": [{"protocol": "tcp", "ports": "80"}],
        "conditions": {"posture": {"firewall_enabled": True}},
    })
    admin.wait_until(lambda: a.tcp_open("172.30.0.10", 80), timeout=15)
    compose.exec("agent-b", "avon-agent", "debug", "set-posture", "firewall_enabled=false")
    admin.wait_until(lambda: not a.tcp_open("172.30.0.10", 80), timeout=20)
    compose.exec("agent-b", "avon-agent", "debug", "set-posture", "firewall_enabled=true")
    admin.wait_until(lambda: a.tcp_open("172.30.0.10", 80), timeout=20)


def test_pending_approval_gates_a_new_device(compose, admin, agent_factory):
    token = admin.create_enroll_token(device_name="agent-c", require_approval=True, max_uses=1, expires_in_hours=1)
    compose.exec("agent-c", "avon-agent", "enroll", "--control", "https://control:50051",
                 "--token", token, "--ca-file", "/certs/ca.crt", "--data-dir", "/var/lib/avon")
    compose.exec_detached("agent-c", "sh", "-c", "avon-agent run --config /etc/avon/agent.toml >/var/log/agent.log 2>&1")
    pending = admin.wait_until(lambda: admin.pending_devices() or None, timeout=30)
    assert len(pending) == 1
    device_id = pending[0]["id"]
    c = agent_factory("agent-c")
    time.sleep(3)
    assert c.status().get("state") != "connected", "a pending device must not be admitted"
    admin.approve_device(device_id)
    c.wait_connected(timeout=60)
    assert admin.device(device_id)["status"] == "active"
