"""A broken harness must not look like a working security control.

Agent.tcp_open() wrapped compose.exec in `except Exception: return False`, and
Compose._run raises on any non-zero exit including docker's own. So a typo'd
service name read as 'port closed' and every negative assertion in the suite was
satisfied by a broken harness.
"""

import pytest

from lib.compose import HarnessError
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
