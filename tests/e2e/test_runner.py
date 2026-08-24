"""The runner's decision logic, tested without Docker."""

import subprocess

import pytest

import runner
from layers import Layer, LAYER_NAMES
from runner import LayerResult, Verdict, main, propagate_blocked


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


# -- --layer / --from validation (fix round 2, Important 2) -----------------
#
# An unrecognized value used to either silently no-op the whole walk
# (--from) or raise a raw ValueError from LAYER_NAMES.index (--layer).
# Both now go through argparse's `choices=`, so both fail the same way:
# immediately, with a message listing the valid names.


def test_unrecognized_layer_fails_immediately_with_valid_names(capsys):
    with pytest.raises(SystemExit):
        main(["--layer", "l33"])
    err = capsys.readouterr().err
    assert "l33" in err
    for name in LAYER_NAMES:
        assert name in err


def test_unrecognized_from_fails_immediately_with_valid_names(capsys):
    with pytest.raises(SystemExit):
        main(["--from", "l33"])
    err = capsys.readouterr().err
    assert "l33" in err
    for name in LAYER_NAMES:
        assert name in err


# -- subprocess timeouts (fix round 2, Important 1) --------------------------
#
# Each test substitutes a real `sleep` subprocess for the real command and a
# deliberately tiny timeout, so subprocess.TimeoutExpired is raised by actual
# OS-level subprocess machinery -- not synthesized -- while still finishing in
# well under a second. No Docker, no cargo, no real pytest run required.


def _sleepy_run(monkeypatch, seconds=2):
    """Make runner.subprocess.run ignore its cmd and sleep instead."""
    real_run = subprocess.run

    def fake_run(cmd, **kwargs):
        return real_run(["sleep", str(seconds)], **kwargs)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)


def test_cargo_layer_timeout_is_a_fail_not_a_crash(monkeypatch):
    _sleepy_run(monkeypatch)
    monkeypatch.setattr(runner, "CARGO_TIMEOUT", 0.1)
    layer = Layer("l0", "l0", "cargo", description="build")

    result = runner._cargo_layer(layer)

    assert result.verdict is Verdict.FAIL
    assert "timed out after 0.1s" in result.detail


def test_run_pytest_timeout_returns_a_sentinel_not_a_crash(monkeypatch, tmp_path):
    _sleepy_run(monkeypatch)
    monkeypatch.setattr(runner, "PYTEST_TIMEOUT", 0.1)
    layer = Layer("l2", "l2", "compose", profile="l2", description="control plane")

    code, output = runner._run_pytest(layer, tmp_path / "sidecar.json")

    assert code is None
    assert "timed out after 0.1s" in output


def test_collect_missing_timeout_reports_but_does_not_crash(monkeypatch, tmp_path):
    _sleepy_run(monkeypatch)
    monkeypatch.setattr(runner, "COLLECT_TIMEOUT", 0.1)
    layer = Layer("l2", "l2", "compose", profile="l2", description="control plane")

    missing, timeout_detail = runner._collect_missing(layer, tmp_path / "collect.json")

    assert missing == []
    assert timeout_detail is not None
    assert "timed out after 0.1s" in timeout_detail


def test_walk_continues_past_a_cargo_timeout_instead_of_raising(monkeypatch, tmp_path):
    """End-to-end through run_layers(): a hung l0 build FAILs, l1 BLOCKs, and
    nothing propagates as an exception."""
    monkeypatch.setattr(runner, "RESULTS", tmp_path)
    monkeypatch.setattr(runner, "CARGO_TIMEOUT", 0.1)
    # Skip real collection subprocesses entirely -- selected=["l0", "l1"]
    # never reaches a compose layer, but run_layers's pre-walk loop still
    # collects for every compose layer regardless of selection.
    monkeypatch.setattr(runner, "_collect_missing", lambda layer, sidecar: ([], None))
    _sleepy_run(monkeypatch)

    results = runner.run_layers(selected=["l0", "l1"])

    assert results["l0"].verdict is Verdict.FAIL
    assert "timed out after 0.1s" in results["l0"].detail
    assert results["l1"].verdict is Verdict.BLOCKED
    assert "upstream l0" in results["l1"].detail
