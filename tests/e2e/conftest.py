import time

import pytest

from lib.compose import Compose
from lib.agent import Agent
from lib.admin import Admin


@pytest.fixture(scope="session")
def compose():
    c = Compose()
    c.up()
    yield c
    c.down()


@pytest.fixture(scope="session")
def admin(compose):
    return Admin(compose)


@pytest.fixture(scope="session")
def agents(compose):
    # Wait for agents to be defined in compose; compose fixture already up.
    a = Agent(compose, "agent-a")
    b = Agent(compose, "agent-b")
    return {"agent-a": a, "agent-b": b}
