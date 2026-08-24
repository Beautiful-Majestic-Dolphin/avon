import json

import pytest

from ratchet import BaselineError, compare, load, snapshot
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


def test_pass_going_to_not_run_is_a_regression():
    """NOT_RUN is in _REGRESSED_FROM_PASS alongside FAIL and BLOCKED, but
    only the other two were ever exercised -- dropping NOT_RUN from that set
    would go unnoticed without this."""
    baseline = {"layers": {"l3": "PASS"}, "missing": 0}
    out = compare({"l3": _r(Verdict.NOT_RUN)}, baseline)
    assert len(out) == 1 and "l3" in out[0] and "NOT_RUN" in out[0]


# -- load(): missing / malformed / valid --------------------------------------


def test_load_returns_empty_baseline_and_says_so_when_file_is_missing(
    monkeypatch, tmp_path, capsys
):
    missing_path = tmp_path / "does-not-exist.json"
    monkeypatch.setattr("ratchet.BASELINE", missing_path)

    result = load()

    assert result == {"layers": {}, "missing": 0}
    out = capsys.readouterr().out
    assert str(missing_path) in out


def test_load_raises_on_malformed_json(tmp_path):
    bad = tmp_path / "baseline.json"
    bad.write_text("{not: valid json")

    with pytest.raises(BaselineError, match=str(bad)):
        load(bad)


def test_load_raises_on_structurally_wrong_json(tmp_path):
    """Valid JSON, but neither a 'layers' nor a 'missing' key -- not a
    baseline, so this must not be silently treated as an empty one."""
    wrong = tmp_path / "baseline.json"
    wrong.write_text(json.dumps({"unrelated": "stuff"}))

    with pytest.raises(BaselineError, match=str(wrong)):
        load(wrong)


def test_load_raises_when_json_is_not_an_object(tmp_path):
    wrong = tmp_path / "baseline.json"
    wrong.write_text(json.dumps(["l2", "PASS"]))

    with pytest.raises(BaselineError):
        load(wrong)


def test_load_accepts_a_valid_baseline(tmp_path):
    good = tmp_path / "baseline.json"
    good.write_text(json.dumps({"layers": {"l2": "PASS"}, "missing": 2}))

    assert load(good) == {"layers": {"l2": "PASS"}, "missing": 2}


def test_load_resolves_baseline_at_call_time_not_import_time(monkeypatch, tmp_path):
    """The bug this closes: `def load(path=BASELINE)` binds BASELINE once,
    at import, so reassigning ratchet.BASELINE afterwards would have no
    effect on a no-arg load() call -- it would keep reading whatever file
    BASELINE pointed at when ratchet.py was first imported, silently
    disagreeing with main()'s write path (which does honour the
    reassignment), and any test that monkeypatches BASELINE and calls
    load() with no args would read the wrong file and pass while proving
    nothing."""
    reassigned = tmp_path / "reassigned-baseline.json"
    reassigned.write_text(json.dumps({"layers": {"l2": "PASS"}, "missing": 7}))
    monkeypatch.setattr("ratchet.BASELINE", reassigned)

    assert load() == {"layers": {"l2": "PASS"}, "missing": 7}


# -- snapshot() round-tripping through compare() ------------------------------


def test_snapshot_round_trip_is_silent_when_nothing_changed():
    results = {
        "l2": _r(Verdict.PASS),
        "l3": _r(Verdict.PASS, missing=1),
    }
    baseline = snapshot(results)

    assert compare(results, baseline) == []


def test_snapshot_round_trip_catches_a_degraded_run():
    good_run = {
        "l2": _r(Verdict.PASS),
        "l3": _r(Verdict.PASS, missing=1),
    }
    baseline = snapshot(good_run)

    degraded_run = {
        "l2": _r(Verdict.PASS),
        "l3": _r(Verdict.FAIL, missing=1),
    }
    out = compare(degraded_run, baseline)

    assert len(out) == 1 and "l3" in out[0] and "FAIL" in out[0]


# -- the successful --update-baseline write path (previously untested) -------


def test_update_baseline_writes_the_snapshot_of_the_full_run(monkeypatch, tmp_path):
    baseline_path = tmp_path / "baseline.json"
    monkeypatch.setattr("ratchet.BASELINE", baseline_path)
    monkeypatch.setattr("runner.RESULTS", tmp_path)

    fake_results = {
        "l0": LayerResult(verdict=Verdict.PASS),
        "l2": LayerResult(verdict=Verdict.FAIL, missing=2),
    }
    monkeypatch.setattr("runner.run_layers", lambda **kw: fake_results)

    exit_code = main(["--update-baseline"])

    assert exit_code == 0
    written = json.loads(baseline_path.read_text())
    assert written == {
        "layers": {"l0": "PASS", "l2": "FAIL"},
        "missing": 2,
    }
