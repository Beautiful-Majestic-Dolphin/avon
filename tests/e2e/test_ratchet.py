import pytest

from ratchet import compare
from runner import LayerResult, Verdict, main


def _r(verdict, missing=0):
    return LayerResult(verdict=verdict, missing=missing)


def test_no_regression_when_nothing_changed():
    baseline = {"layers": {"l2": "PASS"}, "missing": 0}
    assert compare({"l2": _r(Verdict.PASS)}, baseline) == []


def test_pass_going_to_fail_is_a_regression():
    baseline = {"layers": {"l2": "PASS"}, "missing": 0}
    out = compare({"l2": _r(Verdict.FAIL)}, baseline)
    assert len(out) == 1 and "l2" in out[0]


def test_pass_going_to_blocked_is_a_regression():
    """Otherwise breaking a low layer silently excuses every layer above it."""
    baseline = {"layers": {"l4": "PASS"}, "missing": 0}
    out = compare({"l4": _r(Verdict.BLOCKED)}, baseline)
    assert len(out) == 1 and "l4" in out[0]


def test_a_layer_absent_from_the_baseline_is_not_a_regression():
    baseline = {"layers": {}, "missing": 0}
    assert compare({"lnet": _r(Verdict.FAIL)}, baseline) == []


def test_growing_missing_is_a_regression():
    baseline = {"layers": {}, "missing": 3}
    out = compare({"lnet": _r(Verdict.FAIL, missing=4)}, baseline)
    assert len(out) == 1 and "MISSING" in out[0]


def test_shrinking_missing_is_not_a_regression():
    baseline = {"layers": {}, "missing": 3}
    assert compare({"lnet": _r(Verdict.FAIL, missing=1)}, baseline) == []


# -- R10: --update-baseline refuses a partial run -----------------------------
#
# snapshot(results) only records the layers present in `results`. On a
# partial run (--layer or --from) it would silently drop every unrun layer
# from the baseline -- destroying the ratchet's memory that those layers used
# to PASS -- and would write a MISSING total that undercounts, so the next
# full run reports "MISSING grew" and fails CI spuriously. Both push toward
# false confidence, so this must be refused before anything is written, not
# merely warned about.


def test_update_baseline_with_layer_selection_is_refused(monkeypatch, capsys):
    called = []
    monkeypatch.setattr("runner.run_layers", lambda **kw: called.append(kw))

    with pytest.raises(SystemExit) as exc:
        main(["--layer", "l2", "--update-baseline"])

    assert exc.value.code != 0
    assert not called, "a partial run must not be executed at all"
    err = capsys.readouterr().err
    assert "--update-baseline" in err
    assert "full walk" in err.lower()


def test_update_baseline_with_from_is_refused(monkeypatch, capsys):
    called = []
    monkeypatch.setattr("runner.run_layers", lambda **kw: called.append(kw))

    with pytest.raises(SystemExit) as exc:
        main(["--from", "l3", "--update-baseline"])

    assert exc.value.code != 0
    assert not called, "a partial run must not be executed at all"
    err = capsys.readouterr().err
    assert "--update-baseline" in err
    assert "full walk" in err.lower()


def test_update_baseline_refusal_does_not_touch_the_baseline_file(
    monkeypatch, tmp_path, capsys
):
    baseline_path = tmp_path / "baseline.json"
    monkeypatch.setattr("ratchet.BASELINE", baseline_path)
    monkeypatch.setattr("runner.run_layers", lambda **kw: (_ for _ in ()).throw(
        AssertionError("run_layers must not be called")
    ))

    with pytest.raises(SystemExit):
        main(["--layer", "l2", "--update-baseline"])

    assert not baseline_path.exists()
