import json
import time

import pytest

pytestmark = pytest.mark.l3

# The fault tap runs on the gateway, not the agent. On the agent, AF_PACKET only
# sees ingress (the gateway-to-agent half, carrying the agent's receiver index),
# which a gateway rejects as an unknown index when replayed to it. On the gateway
# the ingress is the agent-to-gateway half: it carries the gateway's own index
# and a counter the gateway has already advanced past, so a replay is recognised
# as a replay and a corrupted copy fails authentication. `--iface any` avoids
# guessing whether the public side is eth0 or eth1; replays go to the gateway's
# own listener on 127.0.0.1:4600.


def test_replayed_packets_are_dropped_and_service_continues(agents, compose, witness):
    a = agents["agent-a"]
    a.wait_connected()
    before = compose.metric("gateway", "avon_tunnel_replays_dropped_total")
    # An agent floods real agent-to-gateway packets for the tap to capture; an
    # idle path produces none and the replays would be dummies the gateway drops
    # as malformed rather than as replays.
    compose.exec_detached("agent-a", "sh", "-c", "ping -f -w 8 172.30.0.10 >/dev/null 2>&1")
    out = compose.exec(
        "gateway", "avon-pktfuzz", "--iface", "any", "--port", "4600",
        "--capture-secs", "5", "--replay", "20", "--gateway", "127.0.0.1:4600",
    )
    result = json.loads(out.strip().splitlines()[-1])
    assert result["captured"] > 0, f"nothing captured; replays would be dummies: {result}"
    assert result["replayed"] == 20, result
    time.sleep(1)
    after = compose.metric("gateway", "avon_tunnel_replays_dropped_total")
    witness("replays dropped", f"{before} -> {after}")
    assert after >= before + 20
    assert "nginx" in a.curl("http://172.30.0.10/").lower(), "service continues after a replay burst"


def test_corrupted_packets_never_reach_the_tun(agents, compose, witness):
    agents["agent-a"].wait_connected()
    before = compose.metric("gateway", "avon_tunnel_packets_dropped_total", {"reason": "auth"})
    compose.exec_detached("agent-a", "sh", "-c", "ping -f -w 8 172.30.0.10 >/dev/null 2>&1")
    out = compose.exec(
        "gateway", "avon-pktfuzz", "--iface", "any", "--port", "4600",
        "--capture-secs", "5", "--corrupt", "50", "--gateway", "127.0.0.1:4600",
    )
    result = json.loads(out.strip().splitlines()[-1])
    assert result["captured"] > 0, f"nothing captured; corruptions would be dummies: {result}"
    time.sleep(1)
    after = compose.metric("gateway", "avon_tunnel_packets_dropped_total", {"reason": "auth"})
    witness("auth-dropped packets", f"{before} -> {after}")
    assert after >= before + 50


# Revocation lives in the policy layer (test_resilience.py): it needs the admin
# API to reach control, which pushes the session close. The data-plane layer has
# no admin service, so a revocation there could only touch the database directly,
# which never notifies control and never closes the session.
