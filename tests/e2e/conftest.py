"""Harness rules.

Three properties this file exists to enforce:
  * a scenario that asserts nothing is a failure, not a pass;
  * a skipped scenario is a failure, not a pass;
  * a known gap is MISSING — collected, reported, never executed, and never
    laundered through pytest.skip.
"""

import json
import time

import pytest

MISSING_KEY = pytest.StashKey[list]()
WITNESS_KEY = pytest.StashKey[dict]()


def pytest_addoption(parser):
    parser.addoption(
        "--sidecar",
        action="store",
        default=None,
        help="write MISSING and witness records to this JSON path",
    )


def pytest_configure(config):
    config.stash[MISSING_KEY] = []
    config.stash[WITNESS_KEY] = {}


def pytest_collection_modifyitems(config, items):
    """Pull MISSING items out of the run before anything can execute them.

    Deliberately not implemented with pytest.skip: the skip-to-failure hook
    below would turn every MISSING into a FAIL, and exempting skips would hand
    anyone a one-word way to launder one.
    """
    kept = []
    for item in items:
        marker = item.get_closest_marker("missing")
        if marker is None:
            kept.append(item)
            continue
        reason = marker.kwargs.get("reason")
        if not reason:
            message = (
                f"{item.nodeid}: @pytest.mark.missing requires reason='why this is a gap'"
            )
            # pytest.UsageError's own text is written by wrap_session() straight
            # to the real stderr, which pytester's result.stdout never sees.
            # Print it ourselves so the failure is visible wherever this run's
            # output is being read.
            print(message)
            raise pytest.UsageError(message)
        config.stash[MISSING_KEY].append({"nodeid": item.nodeid, "reason": reason})
    items[:] = kept


@pytest.fixture
def witness(request):
    """Record something observed. A scenario that records nothing fails."""
    recorded: list[tuple[str, str]] = []
    request.config.stash[WITNESS_KEY][request.node.nodeid] = recorded

    def record(label: str, value: object) -> None:
        recorded.append((label, repr(value)))

    return record


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    if report.when != "call":
        return report

    if "pytester" in item.fixturenames:
        # A test that requests pytester spins up its own nested pytest
        # session to exercise these very rules against fake scenarios; it is
        # a meta-test of the harness, not a scenario, and is not itself
        # bound by the rules it is testing.
        return report

    if report.skipped:
        report.outcome = "failed"
        report.longrepr = (
            f"{item.nodeid} was skipped. Skips are failures in this suite: a "
            "missing prerequisite is a FAIL or a MISSING, never a quiet pass."
        )
        return report

    recorded = item.config.stash[WITNESS_KEY].get(item.nodeid, [])
    if report.passed and not recorded:
        report.outcome = "failed"
        report.longrepr = (
            f"{item.nodeid} passed without recording a witness. Every scenario "
            "must call witness(label, value) with something it observed."
        )
    return report


def pytest_sessionfinish(session, exitstatus):
    path = session.config.getoption("--sidecar")
    if not path:
        return
    payload = {
        "missing": session.config.stash[MISSING_KEY],
        "witnesses": session.config.stash[WITNESS_KEY],
    }
    with open(path, "w") as handle:
        json.dump(payload, handle, indent=2)


@pytest.fixture(scope="session")
def compose():
    """The stack the runner already brought up. Scenarios never start it."""
    from lib.compose import Compose

    return Compose()


@pytest.fixture(scope="session")
def admin(compose):
    from lib.admin import Admin

    return Admin(compose)


@pytest.fixture(scope="session")
def agents(compose):
    from lib.agent import Agent

    return {
        name: Agent(compose, name)
        for name in ("agent-a", "agent-b", "agent-tpm", "agent-clone")
    }
