"""Walk the layers, judge each one, report a map.

The point of this file is that a failure does not stop the walk. A layer that
fails marks everything above it BLOCKED, which is a different and far more
useful statement than a wall of red.

Two things this file deliberately does NOT do, because of the state of the
suite at this commit:

  * It does not parse pytest's textual summary for pass/fail counts. pytest
    buckets setup-phase failures as `errors=` rather than `failed=`, and text
    parsing would misreport precisely the case Task 3's conftest was fixed to
    expose. `passed`/`total` come from the JUnit XML the runner already asks
    pytest to write (`tests`/`failures`/`errors`/`skipped` on `<testsuite>`).

  * It does not treat "no tests collected" (pytest exit code 5) as a runner
    error. At this commit no layer has any marked scenarios yet (Task 6 adds
    l2's, Tasks 10-11 the rest), so every collect and every layer run would
    otherwise "fail" the moment you invoke the runner at all. An empty layer
    is NOT_RUN, not PASS and not FAIL: it must not masquerade as passing, and
    it must not block the layers above it either.

Every subprocess this file launches is bounded by a timeout (docker compose's
own --wait-timeout for bring-up; explicit `timeout=` for cargo, pytest
collection, and the pytest run itself). A hung registry fetch or a scenario
module that blocks on import must become a diagnosed FAIL, never an
unbounded hang and never a silently-swallowed PASS.

Every file this runner writes and later reads back as evidence --
results/sidecar-<layer>.json, results/junit-<layer>.xml, and
results/collect-<layer>.json -- is unlinked immediately before the
subprocess that (re)writes it runs. A `timeout=` above is a controlled
death; this guard is for the uncontrolled ones (SIGKILL, OOM, anything that
doesn't raise TimeoutExpired) that skip pytest_sessionfinish and would
otherwise leave a previous run's file to be read back as this run's. That
matters most for collect-<layer>.json: its MISSING count feeds the ratchet
Task 5 builds, which fails CI when MISSING grows, so a stale read there
could make a newly-added gap look like no change at all.
"""

import argparse
import enum
import json
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path

from layers import LAYERS, LAYER_NAMES

HERE = Path(__file__).parent
REPO = HERE.parent.parent
RESULTS = HERE / "results"

# pytest's ExitCode.NO_TESTS_COLLECTED. Not imported from pytest directly so
# this stays meaningful even when read out of context.
NO_TESTS_COLLECTED = 5

# Process-level bounds. None of these are "how long the work should take" --
# they exist so a hung registry fetch or a scenario module that blocks on
# import turns into a diagnosed FAIL instead of a harness that never returns.
CARGO_TIMEOUT = 1800  # a cold `cargo build --workspace` legitimately takes minutes
COLLECT_TIMEOUT = 120  # collection only; nothing here should take long
PYTEST_TIMEOUT = 900  # generous multiple of pytest.ini's own per-test timeout
                       # (120s); bounds a layer's *total* run without assuming
                       # how many scenarios that layer will eventually have

COMPOSE = [
    "docker", "compose",
    "-f", "docker-compose.yml",
    "-f", "tests/e2e/docker-compose.e2e.yml",
]


class Verdict(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    MISSING = "MISSING"
    NOT_RUN = "NOT_RUN"


@dataclass
class LayerResult:
    verdict: Verdict
    passed: int = 0
    total: int = 0
    missing: int = 0
    duration: float = 0.0
    detail: str = ""
    witnesses: dict = field(default_factory=dict)


# Imported here, not at module top, so ratchet's own `from runner import
# Verdict` finds Verdict already defined -- importing this earlier would be a
# circular import (runner -> ratchet -> runner) that fails before Verdict
# exists.
import ratchet  # noqa: E402


def propagate_blocked(results, order, missing_by_layer=None):
    """Fill in BLOCKED for every layer above the first failure."""
    missing_by_layer = missing_by_layer or {}
    out = {}
    blocker = None
    for name in order:
        if blocker is not None:
            out[name] = LayerResult(
                verdict=Verdict.BLOCKED,
                missing=missing_by_layer.get(name, 0),
                detail=f"upstream {blocker}",
            )
            continue
        result = results.get(name)
        if result is None:
            out[name] = LayerResult(
                verdict=Verdict.NOT_RUN,
                missing=missing_by_layer.get(name, 0),
            )
            continue
        out[name] = result
        if result.verdict is Verdict.FAIL:
            blocker = name
    return out


def _cargo_layer(layer):
    """l0 and l1 are aggregated, not orchestrated: shell out and record."""
    commands = {
        "l0": [["cargo", "build", "--workspace", "--locked"]],
        "l1": [["cargo", "test", "-p", "avon-crypto", "--locked",
                "--features", "test-vectors"]],
    }
    started = time.time()
    for cmd in commands[layer.name]:
        try:
            proc = subprocess.run(
                cmd, cwd=REPO, env={**_env(), "CARGO_INCREMENTAL": "0"},
                timeout=CARGO_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return LayerResult(
                verdict=Verdict.FAIL,
                duration=time.time() - started,
                detail=f"{' '.join(cmd)} timed out after {CARGO_TIMEOUT}s",
            )
        if proc.returncode != 0:
            return LayerResult(
                verdict=Verdict.FAIL,
                duration=time.time() - started,
                detail=" ".join(cmd) + " failed",
            )
    return LayerResult(verdict=Verdict.PASS, duration=time.time() - started)


def _env():
    import os
    return dict(os.environ)


def _bring_up(layer, timeout):
    """docker compose --profile <p> up -d --wait.

    --wait is only meaningful because every service has a healthcheck. This is
    what separates 'the services never became healthy' from 'the scenarios
    failed', which are different diagnoses.
    """
    cmd = COMPOSE + ["--profile", layer.profile, "up", "-d", "--wait",
                     "--wait-timeout", str(timeout)]
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _run_pytest(layer, sidecar):
    """Returns (code, output). code is None on a timeout, never raises.

    `code is None` is a sentinel distinct from every real pytest exit code
    (0-5): the caller in run_layers() checks for it before treating the
    return as a real result. pytest's own per-test timeout (pytest.ini)
    bounds a single test; it does not bound the process as a whole.
    """
    cmd = [
        "uv", "run", "pytest",
        "-m", layer.marker,
        f"--sidecar={sidecar}",
        "--junitxml", str(RESULTS / f"junit-{layer.name}.xml"),
        "-q",
    ]
    try:
        proc = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True,
                              timeout=PYTEST_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, f"pytest timed out after {PYTEST_TIMEOUT}s"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _collect_missing(layer, sidecar):
    """MISSING is known at collection, so a BLOCKED layer still reports it.

    Returns (missing_list, timeout_detail). timeout_detail is None unless the
    collect subprocess itself hung -- e.g. a scenario module blocking on
    import -- in which case missing_list is [] and timeout_detail explains
    why, for run_layers() to fold into that layer's verdict once it's
    actually reached.

    Exit code 5 ("no tests collected") is expected, not an error: at this
    commit no layer has any marked scenarios yet, so every collect for every
    compose layer returns it. The sidecar is still written by conftest's
    pytest_sessionfinish regardless of the exit code, so reading it back is
    enough -- the return code itself is deliberately not checked here.

    Stale-evidence guard: `sidecar` is unlinked before the subprocess runs.
    A TimeoutExpired below is already safe (this function returns before
    reading the file at all), but any *other* non-graceful death -- SIGKILL,
    OOM, anything that doesn't trip `timeout=` -- skips
    pytest_sessionfinish too, and without this unlink a leftover file from a
    previous run would be read back and reported as this run's MISSING list.
    That count feeds the ratchet Task 5 builds, which fails CI when MISSING
    grows; a stale collect sidecar could make a newly-added gap look like no
    change at all.
    """
    Path(sidecar).unlink(missing_ok=True)
    cmd = ["uv", "run", "pytest", "-m", layer.marker,
           f"--sidecar={sidecar}", "--collect-only", "-q"]
    try:
        subprocess.run(cmd, cwd=HERE, capture_output=True, text=True,
                       timeout=COLLECT_TIMEOUT)
    except subprocess.TimeoutExpired:
        return [], f"collection timed out after {COLLECT_TIMEOUT}s"
    if not Path(sidecar).exists():
        return [], None
    return json.loads(Path(sidecar).read_text()).get("missing", []), None


def _parse_junit(path):
    """Read passed/total off the JUnit XML the runner already wrote.

    Deliberately not pytest's text summary -- see the module docstring. If
    the XML is absent (the layer never got as far as running pytest, e.g.
    compose never came up healthy), report (0, 0) and let render() show '-'
    rather than a misleading '0/0'.
    """
    if not path.exists():
        return 0, 0
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return 0, 0
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    if suite is None:
        return 0, 0
    total = int(suite.get("tests", 0))
    failures = int(suite.get("failures", 0))
    errors = int(suite.get("errors", 0))
    skipped = int(suite.get("skipped", 0))
    passed = total - failures - errors - skipped
    return passed, total


def run_layers(selected=None, start_from=None, up_timeout=180):
    RESULTS.mkdir(exist_ok=True)
    order = [layer.name for layer in LAYERS]
    if selected:
        order = [n for n in order if n in selected]

    missing_by_layer = {}
    collect_timeouts = {}
    for layer in LAYERS:
        if layer.kind == "compose":
            sidecar = RESULTS / f"collect-{layer.name}.json"
            missing, timeout_detail = _collect_missing(layer, sidecar)
            missing_by_layer[layer.name] = len(missing)
            if timeout_detail:
                collect_timeouts[layer.name] = timeout_detail

    results = {}
    started_at = None
    for layer in LAYERS:
        if layer.name not in order:
            continue
        if start_from and started_at is None and layer.name != start_from:
            results[layer.name] = LayerResult(
                verdict=Verdict.NOT_RUN,
                missing=missing_by_layer.get(layer.name, 0),
                detail="--from skipped this layer; it was not verified",
            )
            continue
        started_at = layer.name

        if layer.kind == "cargo":
            results[layer.name] = _cargo_layer(layer)
            if results[layer.name].verdict is Verdict.FAIL:
                break
            continue

        if layer.name in collect_timeouts:
            # Collection itself hung -- e.g. a scenario module blocking on
            # import. That is a real problem with this layer, not merely an
            # unknown one, so treat it as a FAIL rather than bringing compose
            # up for a run we already know can't be trusted.
            results[layer.name] = LayerResult(
                verdict=Verdict.FAIL,
                missing=missing_by_layer.get(layer.name, 0),
                detail=collect_timeouts[layer.name],
            )
            break

        started = time.time()
        code, output = _bring_up(layer, up_timeout)
        if code != 0:
            results[layer.name] = LayerResult(
                verdict=Verdict.FAIL,
                duration=time.time() - started,
                missing=missing_by_layer.get(layer.name, 0),
                detail="services never became healthy: " + output.strip()[-400:],
            )
            break

        sidecar = RESULTS / f"sidecar-{layer.name}.json"
        junit_path = RESULTS / f"junit-{layer.name}.xml"
        # Stale-evidence guard: unlink before running so a pytest subprocess
        # that dies non-gracefully (SIGKILL, OOM, our own timeout below)
        # never leaves a *previous* run's sidecar/JUnit behind to be misread
        # as this run's passed/total/witnesses.
        sidecar.unlink(missing_ok=True)
        junit_path.unlink(missing_ok=True)

        code, output = _run_pytest(layer, sidecar)
        payload = json.loads(sidecar.read_text()) if sidecar.exists() else {}
        passed, total = _parse_junit(junit_path)

        if code == NO_TESTS_COLLECTED:
            # No scenarios are marked for this layer yet. Not a failure --
            # the walk keeps going -- but not a PASS either, so an empty
            # layer never masquerades as a passing one.
            results[layer.name] = LayerResult(
                verdict=Verdict.NOT_RUN,
                passed=passed,
                total=total,
                missing=len(payload.get("missing", [])),
                duration=time.time() - started,
                detail="no scenarios marked for this layer yet",
                witnesses=payload.get("witnesses", {}),
            )
            continue

        # code is None here means _run_pytest itself timed out. That is not
        # 0 and not NO_TESTS_COLLECTED, so it falls straight into the FAIL
        # branch below with `output` already holding "pytest timed out after
        # <n>s" -- no special case needed, and passed/total/missing are
        # honestly (0, 0, 0) since the killed subprocess never wrote evidence.
        results[layer.name] = LayerResult(
            verdict=Verdict.PASS if code == 0 else Verdict.FAIL,
            passed=passed,
            total=total,
            missing=len(payload.get("missing", [])),
            duration=time.time() - started,
            detail="" if code == 0 else output.strip()[-400:],
            witnesses=payload.get("witnesses", {}),
        )
        if code != 0:
            break

    return propagate_blocked(results, order, missing_by_layer)


def render(results):
    lines = [
        f"{'layer':6} {'name':20} {'verdict':9} {'scenarios':>9} "
        f"{'missing':>7}  detail"
    ]
    for layer in LAYERS:
        r = results.get(layer.name)
        if r is None:
            continue
        scenarios = f"{r.passed}/{r.total}" if r.total else "—"
        lines.append(
            f"{layer.name:6} {layer.description:20} {r.verdict.value:9} "
            f"{scenarios:>9} {r.missing:>7}  {r.detail[:60]}"
        )
    total_missing = sum(r.missing for r in results.values())
    lines.append("")
    lines.append(f"MISSING total: {total_missing}")
    return "\n".join(lines)


def main(argv=None):
    # There is no `avon-e2e` command on PATH (tests/e2e is a harness, not an
    # installed package -- see R9). The canonical invocation is
    # `uv run python runner.py`, so --help should show something a reader can
    # paste verbatim rather than a program name that doesn't exist.
    parser = argparse.ArgumentParser(prog="uv run python runner.py")
    parser.add_argument("--layer", choices=LAYER_NAMES,
                        help="run one layer plus its prerequisites")
    parser.add_argument("--from", dest="start_from", choices=LAYER_NAMES,
                        help="start here against an already-running stack; "
                             "lower layers are reported NOT_RUN, not PASS")
    parser.add_argument("--update-baseline", action="store_true",
                        help="record the current verdicts as the new baseline "
                             "(requires a full walk -- not --layer or --from)")
    args = parser.parse_args(argv)

    # R10: snapshot(results) records only the layers present in `results`. On
    # a partial run (--layer or --from) it would silently drop every unrun
    # layer from the baseline -- destroying the ratchet's memory that those
    # layers used to PASS -- and would write a MISSING total that
    # undercounts, so the next full run reports "MISSING grew" and fails CI
    # spuriously. Both push toward false confidence, so refuse before doing
    # any work at all, not merely warn after the fact.
    if args.update_baseline and (args.layer or args.start_from):
        parser.error(
            "--update-baseline requires a full walk; it cannot be combined "
            "with --layer or --from, or it would silently erase the "
            "baseline's memory of every layer this run skipped"
        )

    selected = None
    if args.layer:
        idx = LAYER_NAMES.index(args.layer)
        selected = LAYER_NAMES[: idx + 1]

    results = run_layers(selected=selected, start_from=args.start_from)
    print(render(results))

    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "report.json").write_text(
        json.dumps({k: asdict(v) for k, v in results.items()},
                   indent=2, default=str)
    )

    baseline = ratchet.load()
    problems = ratchet.compare(results, baseline)

    if args.update_baseline:
        ratchet.BASELINE.write_text(
            json.dumps(ratchet.snapshot(results), indent=2) + "\n"
        )
        print("\nbaseline updated")
        return 0

    if problems:
        print("\nREGRESSION:")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print("\nno regression against baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
