import time


def test_gateway_restart_recovers_within_ten_seconds(agents, compose):
    a = agents["agent-a"]; a.wait_connected()
    compose.restart("gateway")
    deadline = time.time() + 10
    ok = False
    while time.time() < deadline:
        try:
            if "nginx" in a.curl("http://172.30.0.10/", timeout=2).lower():
                ok = True
                break
        except Exception:
            time.sleep(0.5)
    assert ok


def test_control_outage_keeps_data_plane_and_agents_reconnect(agents, compose):
    a = agents["agent-a"]; a.wait_connected()
    compose.stop("control")
    time.sleep(5)
    assert "nginx" in a.curl("http://172.30.0.10/").lower(), "data plane must survive a control outage"
    compose.start("control")
    deadline = time.time() + 60
    while time.time() < deadline and a.status()["state"] != "connected":
        time.sleep(1)
    assert a.status()["state"] == "connected"


def test_lossy_network_does_not_break_the_tunnel(agents, compose):
    a = agents["agent-a"]; a.wait_connected()
    compose.exec("gateway", "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "10%", "delay", "50ms")
    try:
        ok = sum(1 for _ in range(5) if "nginx" in a.curl("http://172.30.0.10/", timeout=10).lower())
        assert ok >= 4
    finally:
        compose.exec("gateway", "tc", "qdisc", "del", "dev", "eth0", "root")
