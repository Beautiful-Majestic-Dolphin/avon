"""Layer 3: does the tunnel actually carry traffic, of more than one kind."""

import time

import pytest

pytestmark = pytest.mark.l3

HTTP = "172.30.0.10"
SSH = "172.30.0.11"
PG = "172.30.0.12"
UDP = "172.30.0.13"


def test_http_traverses_the_tunnel(agents, witness):
    a = agents["agent-a"]
    a.wait_connected()
    body = a.curl(f"http://{HTTP}/")
    witness("http body contains nginx", "nginx" in body.lower())
    assert "nginx" in body.lower()


def test_a_large_transfer_does_not_black_hole_at_the_mtu(agents, witness):
    """The classic VPN bug: small requests work, large ones hang forever."""
    a = agents["agent-a"]
    a.wait_connected()
    code, out = a.compose.exec_capture(
        a.service, "bash", "-c",
        f"curl -fsS --max-time 60 -o /tmp/big.bin http://{HTTP}/big.bin && "
        "stat -c %s /tmp/big.bin",
        timeout=70,
    )
    witness("bytes received", out.strip())
    assert code == 0, out
    assert int(out.strip()) == 8 * 1024 * 1024


def test_a_wire_protocol_survives_the_tunnel(agents, witness):
    """Postgres fails loudly on corruption where HTTP silently retries."""
    a = agents["agent-a"]
    a.wait_connected()
    code, out = a.compose.exec_capture(
        a.service, "bash", "-c",
        f"PGPASSWORD=avon-e2e psql -h {PG} -U postgres -d probe -tAc "
        "'select 42'",
        timeout=30,
    )
    witness("psql result", out.strip())
    assert code == 0, out
    assert "42" in out


def test_udp_echoes_through_the_tunnel(agents, witness):
    """UDP has no retransmission to paper over drops."""
    a = agents["agent-a"]
    a.wait_connected()
    code, out = a.compose.exec_capture(
        a.service, "bash", "-c",
        f"printf 'avon-probe' | timeout 5 socat - UDP-SENDTO:{UDP}:9999",
        timeout=15,
    )
    witness("udp echo", out.strip())
    assert code == 0, out
    assert "avon-probe" in out


def test_a_long_lived_session_survives_a_rekey(agents, witness):
    """The real rekey assertion.

    The previous version of this test finished with a.ping(a.overlay_ip()) --
    the agent pinging its own overlay address, which proves nothing about the
    tunnel and passes with the gateway stopped.
    """
    a = agents["agent-a"]
    st = a.wait_connected()
    before = st.get("epoch", 0)

    a.compose.exec(
        a.service, "bash", "-c",
        f"(sshpass -p avon-e2e ssh -p 2222 -o StrictHostKeyChecking=no "
        f"-o ServerAliveInterval=5 avon@{SSH} "
        "'for i in $(seq 1 40); do echo tick-$i; sleep 1; done' "
        "> /tmp/ssh.log 2>&1 &) ",
        timeout=15,
    )

    deadline = time.time() + 40
    after = before
    while time.time() < deadline:
        after = a.status().get("epoch", before)
        if after > before:
            break
        time.sleep(1)

    witness("epoch", f"{before} -> {after}")
    assert after > before, "no rekey observed within 40s"

    code, out = a.compose.exec_capture(
        a.service, "bash", "-c", "tail -3 /tmp/ssh.log"
    )
    witness("ssh output after rekey", out.strip())
    assert "tick-" in out, "the ssh session did not survive the rekey"
