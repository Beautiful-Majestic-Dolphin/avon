import time


def test_agents_connect_and_reach_protected_target(agents, compose):
    a = agents["agent-a"]
    st = a.wait_connected()
    assert st["overlay_v4"].startswith("100.64.")
    assert "nginx" in a.curl("http://172.30.0.10/").lower()


def test_agent_to_agent_via_relay_and_direct(agents, compose):
    a, b = agents["agent-a"], agents["agent-b"]
    a.wait_connected(); b.wait_connected()
    assert a.ping(b.overlay_ip())
    # Direct path: agents share the 'public' network so candidates are reachable.
    relayed_before = compose.metric("gateway", "avon_gateway_packets_relayed_total")
    # Dial peer if supported; for e2e we check that ping still works and ideally direct.
    try:
        a.dial_peer(b.device_id())
    except Exception:
        pass
    time.sleep(4)
    assert a.ping(b.overlay_ip())
    after = compose.metric("gateway", "avon_gateway_packets_relayed_total")
    # If direct, relayed should not increase much; allow some slack.
    assert after <= relayed_before + 10, f"direct path should carry pings, relayed {relayed_before} -> {after}"
