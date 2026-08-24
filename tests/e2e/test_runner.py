"""The runner's decision logic, tested without Docker."""

from runner import LayerResult, Verdict, propagate_blocked


def _r(verdict, missing=0):
    return LayerResult(verdict=verdict, passed=0, total=0, missing=missing,
                       duration=0.0, detail="")


def test_a_failed_layer_blocks_everything_above_it():
    results = {
        "l2": _r(Verdict.PASS),
        "l3": _r(Verdict.FAIL),
    }
    out = propagate_blocked(results, order=["l2", "l3", "l4", "l5"])
    assert out["l2"].verdict is Verdict.PASS
    assert out["l3"].verdict is Verdict.FAIL
    assert out["l4"].verdict is Verdict.BLOCKED
    assert out["l5"].verdict is Verdict.BLOCKED
    assert "upstream l3" in out["l4"].detail


def test_blocked_layers_still_report_their_missing_count():
    results = {"l3": _r(Verdict.FAIL)}
    out = propagate_blocked(
        results, order=["l3", "lnet"], missing_by_layer={"lnet": 3}
    )
    assert out["lnet"].verdict is Verdict.BLOCKED
    assert out["lnet"].missing == 3


def test_nothing_is_blocked_when_everything_passes():
    results = {"l2": _r(Verdict.PASS), "l3": _r(Verdict.PASS)}
    out = propagate_blocked(results, order=["l2", "l3"])
    assert all(r.verdict is Verdict.PASS for r in out.values())
