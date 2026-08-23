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
    return {
        name: Agent(compose, name)
        for name in ("agent-a", "agent-b", "agent-tpm", "agent-clone")
    }
