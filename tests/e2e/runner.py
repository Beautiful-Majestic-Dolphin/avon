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
        proc = subprocess.run(cmd, cwd=REPO, env={**_env(), "CARGO_INCREMENTAL": "0"})
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
    cmd = [
        "uv", "run", "pytest",
        "-m", layer.marker,
        f"--sidecar={sidecar}",
        "--junitxml", str(RESULTS / f"junit-{layer.name}.xml"),
        "-q",
    ]
    proc = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _collect_missing(layer, sidecar):
    """MISSING is known at collection, so a BLOCKED layer still reports it.

    Exit code 5 ("no tests collected") is expected, not an error: at this
    commit no layer has any marked scenarios yet, so every collect for every
    compose layer returns it. The sidecar is still written by conftest's
    pytest_sessionfinish regardless of the exit code, so reading it back is
    enough -- the return code itself is deliberately not checked here.
    """
    cmd = ["uv", "run", "pytest", "-m", layer.marker,
           f"--sidecar={sidecar}", "--collect-only", "-q"]
    subprocess.run(cmd, cwd=HERE, capture_output=True, text=True)
    if not Path(sidecar).exists():
        return []
    return json.loads(Path(sidecar).read_text()).get("missing", [])


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
    for layer in LAYERS:
        if layer.kind == "compose":
            sidecar = RESULTS / f"collect-{layer.name}.json"
            missing_by_layer[layer.name] = len(_collect_missing(layer, sidecar))

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
        code, output = _run_pytest(layer, sidecar)
        payload = json.loads(sidecar.read_text()) if sidecar.exists() else {}
        passed, total = _parse_junit(RESULTS / f"junit-{layer.name}.xml")

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
    parser = argparse.ArgumentParser(prog="avon-e2e")
    parser.add_argument("--layer", help="run one layer plus its prerequisites")
    parser.add_argument("--from", dest="start_from",
                        help="start here against an already-running stack; "
                             "lower layers are reported NOT_RUN, not PASS")
    args = parser.parse_args(argv)

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
    return 0


if __name__ == "__main__":
    sys.exit(main())
