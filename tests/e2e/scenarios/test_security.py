import time


def test_replayed_packets_are_dropped_and_service_continues(agents, compose):
    a = agents["agent-a"]; a.wait_connected()
    before = compose.metric("gateway", "avon_tunnel_replays_dropped_total")
    out = compose.exec("agent-a", "avon-pktfuzz", "--iface", "eth0", "--port", "4600", "--capture-secs", "5", "--replay", "20", "--gateway", "gateway:4600")
    assert '"replayed": 20' in out
    time.sleep(1)
    assert compose.metric("gateway", "avon_tunnel_replays_dropped_total") >= before + 20
    assert "nginx" in a.curl("http://172.30.0.10/").lower()


def test_corrupted_packets_never_reach_the_tun(agents, compose):
    a = agents["agent-a"]; a.wait_connected()
    before = compose.metric("gateway", "avon_tunnel_packets_dropped_total", {"reason": "auth"})
    compose.exec("agent-a", "avon-pktfuzz", "--iface", "eth0", "--port", "4600", "--capture-secs", "3", "--corrupt", "50", "--gateway", "gateway:4600")
    time.sleep(1)
    assert compose.metric("gateway", "avon_tunnel_packets_dropped_total", {"reason": "auth"}) >= before + 50


def test_revocation_closes_the_session_within_two_seconds(agents, compose, admin):
    a = agents["agent-a"]; st = a.wait_connected()
    assert "nginx" in a.curl("http://172.30.0.10/").lower()
    admin.revoke_device(st["device_id"], reason="e2e")
    deadline = time.time() + 2.0
    closed = False
    while time.time() < deadline:
        if a.status()["state"] != "connected":
            closed = True
            break
        time.sleep(0.1)
    assert closed, "session must close within 2s of revocation"
    try:
        a.curl("http://172.30.0.10/", timeout=3)
        assert False, "traffic must stop"
    except Exception:
        pass


def test_rekey_occurs(agents, compose):
    a = agents["agent-b"]; st = a.wait_connected()
    e0 = st.get("epoch", 0)
    time.sleep(15)   # e2e gateway/agent run with AVON_*_REKEY_SECS=10
    assert a.status()["epoch"] >= e0 + 1
    assert a.ping(a.overlay_ip())  # still healthy
