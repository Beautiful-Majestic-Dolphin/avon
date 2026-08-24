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


def load(path=BASELINE):
    if not Path(path).exists():
        return {"layers": {}, "missing": 0}
    return json.loads(Path(path).read_text())


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
