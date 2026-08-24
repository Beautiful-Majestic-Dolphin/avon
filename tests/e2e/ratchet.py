"""Fail on regression, not on imperfection.

An all-green gate would be red on day one and stay red while several layers get
fixed, which is how the previous suite became something nobody ran. This
tightens automatically: when every layer is PASS and MISSING is zero, the
ratchet is an all-green gate with no policy change.
"""

import json
from pathlib import Path

from runner import Verdict

BASELINE = Path(__file__).parent / "baseline.json"

# A layer that was passing is expected to keep passing. BLOCKED counts as a
# regression: if it were excused, breaking a low layer would launder every
# failure above it.
_REGRESSED_FROM_PASS = {Verdict.FAIL, Verdict.BLOCKED, Verdict.NOT_RUN}

# The two keys compare()/snapshot() actually read/write. Both are required
# (see load()'s corruption check) -- they are NOT symmetric under a partial
# baseline. Losing "missing" defaults compare()'s was_missing to 0, so the
# next run reports "MISSING grew from 0 to N": a spurious failure, annoying
# but safe -- someone investigates. Losing "layers" defaults compare()'s
# lookup to {}, so every layer looks absent from the baseline and every
# PASS->FAIL/BLOCKED/NOT_RUN regression goes unreported: a silent pass,
# which is the one direction this harness exists to rule out. So a baseline
# missing *either* key is corruption, not a partially-usable baseline.
_EXPECTED_KEYS = {"layers", "missing"}


class BaselineError(Exception):
    """The baseline file exists but cannot be trusted.

    A *missing* baseline is a legitimate first-run bootstrap -- there is
    nothing to compare against yet, so load() returns the empty baseline for
    that case and says so. This is different: the file is present but either
    not valid JSON, or valid JSON that isn't structurally a complete baseline
    (not an object, or an object missing "layers" and/or "missing"). Partial
    is not good enough here: a baseline with "missing" but no "layers" would
    silently erase every recorded PASS -- compare() would find nothing to
    regress against and print the harness's most reassuring message, "no
    regression against baseline", for exactly the case that most needs a
    loud failure instead of a quiet one.
    """


def load(path=None):
    """Read the baseline, or bootstrap an empty one.

    `path` defaults to the module-level BASELINE, resolved *inside* the
    function body rather than as `def load(path=BASELINE)`. A parameter
    default is bound once, at function-definition time (i.e. at import), so
    a default of `path=BASELINE` would freeze in the file this module
    happened to point at on import -- reassigning `ratchet.BASELINE`
    afterwards (as tests do, and as any future caller reasonably expects to
    be able to do) would silently have no effect on a no-arg load() call.
    Resolving here keeps every no-arg load() looking at whatever BASELINE
    currently points at, which is what main()'s --update-baseline write path
    already does.
    """
    path = Path(path) if path is not None else BASELINE

    if not path.exists():
        print(f"no baseline at {path}; starting from an empty baseline "
              "(first run, or --update-baseline has never been used)")
        return {"layers": {}, "missing": 0}

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise BaselineError(
            f"baseline at {path} exists but is not valid JSON ({e}); "
            "fix or remove it -- a corrupt baseline must not be read as an "
            "empty one, which would silently erase every recorded PASS"
        ) from e

    if not isinstance(data, dict):
        raise BaselineError(
            f"baseline at {path} does not look like a baseline (expected a "
            f"JSON object with 'layers' and 'missing' keys, got {data!r}); "
            "fix or remove it rather than let it be read as empty"
        )

    missing_keys = _EXPECTED_KEYS - data.keys()
    if missing_keys:
        raise BaselineError(
            f"baseline at {path} is missing required key(s) "
            f"{sorted(missing_keys)} (expected both 'layers' and 'missing'); "
            "a partial baseline is corruption, not something to silently "
            "fill in -- fix or remove the file rather than let it be read "
            "as empty"
        )
    return data


def compare(results, baseline):
    problems = []
    for name, result in results.items():
        was = baseline.get("layers", {}).get(name)
        if was != Verdict.PASS.value:
            continue
        if result.verdict in _REGRESSED_FROM_PASS:
            problems.append(
                f"{name} regressed: baseline PASS, now {result.verdict.value}"
            )

    now_missing = sum(r.missing for r in results.values())
    was_missing = baseline.get("missing", 0)
    if now_missing > was_missing:
        problems.append(
            f"MISSING grew from {was_missing} to {now_missing}; "
            "a new gap needs a reason and a baseline update"
        )
    return problems


def snapshot(results):
    return {
        "layers": {name: r.verdict.value for name, r in results.items()},
        "missing": sum(r.missing for r in results.values()),
    }
