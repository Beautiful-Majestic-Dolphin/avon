"""The data plane under faults: a gateway restart, a control outage, a lossy
path. Each fetch is an observed result, not a swallowed exception: `http_get`
returns curl's exit code, and only the harness itself raises."""
import time

import pytest

pytestmark = pytest.mark.l4

HTTP_URL = "http://172.30.0.10/"


def _fetch_ok(agent, timeout=2) -> bool:
    code, body = agent.http_get(HTTP_URL, timeout=timeout)
    return code == 0 and "nginx" in body.lower()


@pytest.mark.missing(
    reason="no fast dead-gateway detection. A restarted gateway comes back with "
    "an empty session table, and the agent has no signal that its hub session "
    "died: it keeps sending on the old receiver index (the gateway drops those "
    "as unknown_index) until the 180s idle timeout fires and it re-opens. "
    "Control is not in the path -- it stays up across a gateway restart and is "
    "never told the sessions are gone. Recovery within any bounded test needs "
    "active liveness (a keepalive whose missing ACK triggers re-open, or control "
    "closing a gateway's sessions when it re-registers); neither is wired."
)
def test_gateway_restart_recovers_quickly():
    ...


def test_control_outage_keeps_data_plane_and_agents_reconnect(agents, compose, witness):
    a = agents["agent-a"]
    a.wait_connected()
    compose.stop("control")
    try:
        time.sleep(5)
        during = _fetch_ok(a)
        witness("fetch during control outage", during)
        assert during, "data plane must survive a control outage"
    finally:
        compose.start("control")
    deadline = time.time() + 60
    state = None
    while time.time() < deadline:
        state = (a.try_status() or {}).get("state")
        if state == "connected":
            break
        time.sleep(1)
    witness("agent state after control returned", state)
    assert state == "connected"


def test_lossy_network_does_not_break_the_tunnel(agents, compose, witness):
    a = agents["agent-a"]
    a.wait_connected()
    compose.exec("gateway", "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "10%", "delay", "50ms")
    try:
        ok = sum(1 for _ in range(5) if _fetch_ok(a, timeout=10))
    finally:
        compose.exec("gateway", "tc", "qdisc", "del", "dev", "eth0", "root")
    witness("successful fetches of 5 under 10% loss + 50ms", ok)
    assert ok >= 4


def test_revocation_closes_the_session_promptly(agents, compose, admin, witness):
    """Revoking a device pushes a close: control updates the CRL and sends a
    PulseDown::Close to the device and a GatewayDown::Close to its gateway, so
    the session ends without waiting for the next pulse. This needs the admin
    API to reach control; the data-plane layer has none, which is why this is
    an l4 scenario rather than living beside the other security tests.

    Uses agent-b, which nothing after this scenario depends on: revocation is
    permanent, so revoking a device the device-trust layer later expects to be
    connected (agent-a) would break it."""
    a = agents["agent-b"]
    st = a.wait_connected()
    assert _fetch_ok(a, timeout=5), "precondition: the target is reachable before revocation"

    admin.revoke_device(st["device_id"], reason="e2e")

    deadline = time.time() + 5.0
    closed_after = None
    start = time.time()
    while time.time() < deadline:
        if (a.try_status() or {}).get("state") != "connected":
            closed_after = round(time.time() - start, 2)
            break
        time.sleep(0.1)
    witness("seconds until the session closed after revocation", closed_after)
    assert closed_after is not None, "session must close promptly after revocation"

    # The tunnel is gone, so protected traffic must stop.
    assert not _fetch_ok(a, timeout=3), "traffic must stop once the session is revoked"
