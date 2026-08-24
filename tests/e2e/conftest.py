"""Harness rules.

Three properties this file exists to enforce:
  * a scenario that asserts nothing is a failure, not a pass;
  * a skipped scenario is a failure, not a pass;
  * a known gap is MISSING — collected, reported, never executed, and never
    laundered through pytest.skip.
"""

import json

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
        # reason must be passed as a keyword: @pytest.mark.missing("text") puts
        # "text" in marker.args, not marker.kwargs, so it is rejected below as
        # reason-less even though a reason was supplied. Use reason="text".
        reason = marker.kwargs.get("reason")
        if not reason:
            raise pytest.UsageError(
                f"{item.nodeid}: @pytest.mark.missing requires reason='why this is a gap'"
            )
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


def _is_scenario(item) -> bool:
    """True if `item` lives under scenarios/.

    The witness and skip-to-failure rules bind scenarios, because scenarios
    are the things that make claims about whether AVON actually works.
    Harness unit tests (test_conftest_rules.py, and later test_runner.py,
    test_ratchet.py, test_lib_discipline.py) sit beside scenarios/, not
    inside it, and are not scenarios themselves.
    """
    try:
        rel = item.path.relative_to(item.config.rootpath)
    except ValueError:
        rel = item.path
    return "scenarios" in rel.parts


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield

    if not _is_scenario(item):
        return report

    if report.skipped:
        # Deliberately not gated on report.when == "call": @pytest.mark.skip,
        # @pytest.mark.skipif, and pytest.skip() raised inside a fixture all
        # report at "setup" (there is no "call" phase at all once setup is
        # skipped) — a fixture skipping because a prerequisite is missing is
        # the single most common shape of "quiet pass" this rule exists to
        # catch. Checking every phase (setup/call/teardown) here, ahead of
        # the call-only gate below, is what makes that catch the skip
        # regardless of which phase it happened in.
        report.outcome = "failed"
        report.longrepr = (
            f"{item.nodeid} was skipped. Skips are failures in this suite: a "
            "missing prerequisite is a FAIL or a MISSING, never a quiet pass."
        )
        return report

    if report.when != "call":
        # The witness check below only makes sense for a test that actually
        # ran its body; a setup/teardown report that isn't a skip needs no
        # action here.
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
