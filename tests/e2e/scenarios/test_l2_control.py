"""Layer 2: the control plane, with no data plane beneath it.

Enrolling needs the agent binary, not a TUN or NET_ADMIN, so this whole layer
runs in unprivileged containers. That makes it the dependable floor of the map.
"""

import pytest

pytestmark = pytest.mark.l2

AGENT_IMAGE = "avons-corners-agent-tpm:latest"
CERTS = {"avons-corners_certs": "/certs"}
NETWORK = "avons-corners_public"


def _enrol(compose, token, data_dir, provider="software"):
    return compose.run_in_new_container(
        AGENT_IMAGE,
        "avon-agent", "enroll",
        "--control", "https://control:50051",
        "--token", token,
        "--ca-file", "/certs/trust-ca.crt",
        "--data-dir", data_dir,
        "--key-provider", provider,
        network=NETWORK,
        volumes=CERTS,
        env={},
    )


def test_a_device_can_enrol_against_the_control_plane(compose, witness):
    token = compose.mint_token(max_uses=1)
    code, out = _enrol(compose, token, "/tmp/d1")
    assert code == 0, out
    assert "Device enrolled successfully" in out, out
    device_id = [line for line in out.splitlines() if "Device ID:" in line][0]
    witness("enrolled", device_id.strip())


def test_a_tokens_uses_are_finite(compose, witness):
    """A token minted for one use must not enrol a second device."""
    token = compose.mint_token(max_uses=1)

    first_code, first_out = _enrol(compose, token, "/tmp/d2")
    assert first_code == 0, first_out
    witness("first enrolment exit", first_code)

    second_code, second_out = _enrol(compose, token, "/tmp/d3")
    witness("second enrolment exit", second_code)
    assert second_code != 0, (
        "a token whose uses are exhausted must not enrol a second device: "
        + second_out
    )


def test_an_expired_token_is_refused(compose, witness):
    token = compose.mint_token(max_uses=1, expires_in="-1 hour")
    code, out = _enrol(compose, token, "/tmp/d4")
    witness("expired token exit", code)
    assert code != 0, "an expired token must not enrol: " + out


def test_a_garbage_token_is_rejected_without_saying_why(compose, witness):
    """The control plane returns one message for every rejection reason, so
    enrollment cannot be used as an oracle for which tokens exist."""
    code, out = _enrol(compose, "not-a-real-token", "/tmp/d5")
    witness("rejected exit", code)
    assert code != 0
    assert "enrollment rejected" in out or "PermissionDenied" in out, (
        "expected the control plane's generic rejection, got something else "
        "entirely (a harness failure would satisfy the negative checks below "
        "without ever exercising the uniform-rejection contract): " + out
    )
    lowered = out.lower()
    assert "expired" not in lowered and "exhausted" not in lowered, (
        "the rejection must not say which check failed: " + out
    )
