"""The harness's rules about itself, tested with pytest's own pytester.

`pytester` runs each case in a temporary directory, so the real conftest is read
through an absolute path — a relative open() would resolve against the tmpdir
and fail.
"""

from pathlib import Path

pytest_plugins = ["pytester"]

CONFTEST = (Path(__file__).parent / "conftest.py").read_text()


def test_a_passing_test_without_a_witness_is_a_failure(pytester):
    # The witness rule only binds scenarios/ (Ruling R5): place the fake test
    # under scenarios/ so this actually exercises the enforcement path,
    # rather than trivially passing because the rule never looked at it.
    pytester.makeconftest(CONFTEST)
    pytester.makepyfile(**{
        "scenarios/test_x": """
        def test_no_witness():
            assert 1 == 1
        """
    })
    result = pytester.runpytest("-p", "no:cacheprovider")
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(["*without recording a witness*"])


def test_a_witnessed_test_passes(pytester):
    pytester.makeconftest(CONFTEST)
    pytester.makepyfile(**{
        "scenarios/test_x": """
        def test_with_witness(witness):
            witness("observed", 42)
        """
    })
    result = pytester.runpytest("-p", "no:cacheprovider")
    result.assert_outcomes(passed=1)


def test_a_skip_is_a_failure(pytester):
    pytester.makeconftest(CONFTEST)
    pytester.makepyfile(**{
        "scenarios/test_x": """
        import pytest
        def test_skipped(witness):
            pytest.skip("nope")
        """
    })
    result = pytester.runpytest("-p", "no:cacheprovider")
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(["*Skips are failures*"])


def test_a_decorator_skip_is_a_failure(pytester):
    # @pytest.mark.skip / @pytest.mark.skipif report at "setup", never
    # "call" — there is no call phase at all once setup is skipped. This is
    # a distinct escape route from test_a_skip_is_a_failure above (which
    # calls pytest.skip() from inside the test body, a "call"-phase skip).
    pytester.makeconftest(CONFTEST)
    pytester.makepyfile(**{
        "scenarios/test_x": """
        import pytest
        @pytest.mark.skip(reason="decorator skip")
        def test_decorator_skipped(witness):
            witness("observed", 1)
        """
    })
    result = pytester.runpytest("-p", "no:cacheprovider")
    # pytest categorizes a setup-phase failure as "errors" in its own
    # summary counts, not "failed" (that word is reserved for the "call"
    # phase) -- confirmed by the actual output below. What Task 4 consumes
    # is the exit code, and that must be non-zero regardless of the label.
    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*Skips are failures*"])
    assert result.ret != 0


def test_a_fixture_level_skip_is_a_failure(pytester):
    # pytest.skip() raised inside a fixture is the ordinary shape of "a
    # missing prerequisite quietly skipped the scenario" — also a
    # "setup"-phase skip with no "call" phase.
    pytester.makeconftest(CONFTEST)
    pytester.makepyfile(**{
        "scenarios/test_x": """
        import pytest

        @pytest.fixture
        def prerequisite():
            pytest.skip("prerequisite missing")

        def test_needs_prerequisite(witness, prerequisite):
            witness("observed", 1)
        """
    })
    result = pytester.runpytest("-p", "no:cacheprovider")
    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*Skips are failures*"])
    assert result.ret != 0


def test_missing_requires_a_reason(pytester):
    pytester.makeconftest(CONFTEST)
    pytester.makepyfile(
        test_x="""
        import pytest
        @pytest.mark.missing
        def test_no_reason(witness):
            pass
        """
    )
    result = pytester.runpytest("-p", "no:cacheprovider")
    assert result.ret != 0
    # pytest.UsageError's own text is written straight to stderr by
    # wrap_session(); look where the behavior already is (Ruling R6) rather
    # than adding a print() to the code under test.
    result.stderr.fnmatch_lines(["*requires reason=*"])


def test_missing_is_not_executed_and_is_recorded(pytester, tmp_path):
    sidecar = tmp_path / "sidecar.json"
    pytester.makeconftest(CONFTEST)
    pytester.makepyfile(
        test_x="""
        import pytest
        @pytest.mark.missing(reason="dial_peer has no production caller")
        def test_gap(witness):
            raise AssertionError("must never run")
        """
    )
    result = pytester.runpytest(
        "-p", "no:cacheprovider", f"--sidecar={sidecar}"
    )
    result.assert_outcomes(passed=0, failed=0)

    import json
    data = json.loads(sidecar.read_text())
    assert len(data["missing"]) == 1
    assert data["missing"][0]["reason"] == "dial_peer has no production caller"
