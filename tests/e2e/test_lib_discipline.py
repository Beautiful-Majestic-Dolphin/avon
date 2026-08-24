"""A broken harness must not look like a working security control.

Agent.tcp_open() wrapped compose.exec in `except Exception: return False`, and
Compose._run raises on any non-zero exit including docker's own. So a typo'd
service name read as 'port closed' and every negative assertion in the suite was
satisfied by a broken harness.
"""

import pytest

from lib import compose as compose_mod
from lib.compose import Compose, HarnessError
from lib.agent import Agent


class FakeCompose:
    def __init__(self, behaviour):
        self.behaviour = behaviour

    def exec_capture(self, service, *cmd, timeout=60):
        if self.behaviour == "docker-broken":
            raise HarnessError("No such service: agent-typo")
        if self.behaviour == "refused":
            return 1, "Connection refused"
        return 0, ""


def test_a_missing_service_raises_rather_than_reading_as_closed():
    agent = Agent(FakeCompose("docker-broken"), "agent-typo")
    with pytest.raises(HarnessError):
        agent.tcp_open("10.0.0.1", 80)


def test_a_refused_connection_returns_false():
    agent = Agent(FakeCompose("refused"), "agent-a")
    assert agent.tcp_open("10.0.0.1", 80) is False


def test_an_open_connection_returns_true():
    agent = Agent(FakeCompose("open"), "agent-a")
    assert agent.tcp_open("10.0.0.1", 80) is True


class FakeCompletedProcess:
    """Stands in for subprocess.run's return value."""

    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _stub_subprocess_run(monkeypatch, returncode, stderr=""):
    def fake_run(*args, **kwargs):
        return FakeCompletedProcess(returncode, stderr=stderr)

    monkeypatch.setattr(compose_mod.subprocess, "run", fake_run)


# R14: exit codes 126/127 are POSIX's unambiguous "could not execute" signals.
# A container with no `bash` (e.g. nginx:alpine, used by the `target` service)
# exits 127 with a message ("bash: not found") that matches none of the marker
# strings in exec_capture's harness_failures tuple -- message text alone proved
# incomplete, so the exit code must be checked directly.


def test_exit_127_raises_even_when_no_marker_string_matches(monkeypatch):
    _stub_subprocess_run(monkeypatch, 127, stderr="bash: not found")
    agent = Agent(Compose(), "target")
    with pytest.raises(HarnessError):
        agent.tcp_open("10.0.0.1", 80)


def test_exit_1_connection_refused_still_returns_false(monkeypatch):
    _stub_subprocess_run(monkeypatch, 1, stderr="Connection refused")
    agent = Agent(Compose(), "agent-a")
    assert agent.tcp_open("10.0.0.1", 80) is False


def test_exit_124_timeout_is_an_observed_negative_not_a_harness_failure(monkeypatch):
    """124 is timeout(1) killing a probe that ran and hung -- exactly what a
    filtered or dropped port looks like. It must never be swept into the
    harness-failure condition alongside 126/127.
    """
    _stub_subprocess_run(monkeypatch, 124)
    agent = Agent(Compose(), "agent-a")
    assert agent.tcp_open("10.0.0.1", 80) is False
