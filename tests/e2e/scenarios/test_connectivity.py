import pytest

pytestmark = pytest.mark.l3


def test_agents_connect_and_reach_protected_target(agents, compose, witness):
    a = agents["agent-a"]
    st = a.wait_connected()
    witness("overlay_v4", st["overlay_v4"])
    assert st["overlay_v4"].startswith("100.64.")
    assert "nginx" in a.curl("http://172.30.0.10/").lower()


def test_agent_to_agent_traffic_relays_through_the_gateway(agents, compose, witness):
    a, b = agents["agent-a"], agents["agent-b"]
    a.wait_connected()
    b.wait_connected()
    before = compose.metric("gateway", "avon_gateway_packets_relayed_total")
    assert a.ping(b.overlay_ip())
    after = compose.metric("gateway", "avon_gateway_packets_relayed_total")
    witness("relayed packets", f"{before} -> {after}")
    assert after > before, "agent-to-agent traffic must relay via the gateway"


@pytest.mark.missing(
    reason="dial_peer has no production caller; PeerManager is built but the run "
           "loop never dials, nothing answers PeerSessionRequest, and AgentStatus "
           "has no direct-path field"
)
def test_agent_to_agent_takes_a_direct_path_when_reachable():
    ...
