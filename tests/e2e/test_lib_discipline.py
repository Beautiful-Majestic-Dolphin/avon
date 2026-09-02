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


# Admin.wait_until used to swallow its own timeout and return None, so a
# scenario whose only assertion was `admin.wait_until(lambda: ...)` passed
# whether or not the condition ever held.
class _NoCompose:
    pass


def _admin():
    from lib.admin import Admin

    return Admin(_NoCompose())


def test_wait_until_returns_the_truthy_value():
    calls = []

    def predicate():
        calls.append(1)
        return {"ok": True} if len(calls) >= 3 else None

    assert _admin().wait_until(predicate, timeout=5, interval=0.01) == {"ok": True}


def test_wait_until_raises_on_timeout_rather_than_returning_none():
    with pytest.raises(AssertionError, match="not met within"):
        _admin().wait_until(lambda: False, timeout=0.05, interval=0.01)


def test_wait_until_lets_a_harness_error_through():
    def broken():
        raise HarnessError("No such service: agent-typo")

    with pytest.raises(HarnessError):
        _admin().wait_until(broken, timeout=5, interval=0.01)


def test_wait_until_polls_through_transient_errors_and_reports_the_last_one():
    def flaky():
        raise ConnectionError("admin api restarting")

    with pytest.raises(AssertionError, match="admin api restarting"):
        _admin().wait_until(flaky, timeout=0.05, interval=0.01)


def test_try_status_is_none_when_the_agent_is_not_answering():
    class NotAnswering:
        def exec_capture(self, service, *cmd, timeout=60):
            return 1, "connection refused: /run/avon/agent.sock"

    assert Agent(NotAnswering(), "agent-c").try_status() is None


def test_try_status_parses_an_answer():
    class Answering:
        def exec_capture(self, service, *cmd, timeout=60):
            return 0, '{"state": "connecting"}'

    assert Agent(Answering(), "agent-c").try_status() == {"state": "connecting"}


def test_http_get_reports_a_failed_fetch_as_a_code_not_an_exception():
    class Refused:
        def exec_capture(self, service, *cmd, timeout=60):
            return 7, "curl: (7) Failed to connect"

    assert Agent(Refused(), "agent-a").http_get("http://172.30.0.10/")[0] == 7
