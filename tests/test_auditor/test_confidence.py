"""Tests for the confidence scoring model."""

from __future__ import annotations

import pytest

from deep_code_security.auditor.confidence import (
    compute_confidence,
    confidence_to_status,
    cwe_baseline_score,
    exploit_bonus_score,
    sanitizer_score,
    taint_completeness_score,
)
from deep_code_security.auditor.models import ExploitResult
from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath, TaintStep


@pytest.fixture
def base_source() -> Source:
    return Source(
        file="/test.py", line=5, column=0,
        function="request.form", category="web_input", language="python"
    )


@pytest.fixture
def base_sink() -> Sink:
    return Sink(
        file="/test.py", line=10, column=0,
        function="cursor.execute", category="sql_injection",
        cwe="CWE-89", language="python"
    )


@pytest.fixture
def full_taint_path(base_source: Source, base_sink: Sink) -> TaintPath:
    """A taint path with 3 steps (full path)."""
    steps = [
        TaintStep(file="/test.py", line=5, column=0, variable="user_input", transform="source"),
        TaintStep(file="/test.py", line=7, column=0, variable="query", transform="concatenation"),
        TaintStep(file="/test.py", line=10, column=0, variable="query", transform="sink_argument"),
    ]
    return TaintPath(steps=steps, sanitized=False)


@pytest.fixture
def partial_taint_path() -> TaintPath:
    """A taint path with 2 steps."""
    steps = [
        TaintStep(file="/test.py", line=5, column=0, variable="user_input", transform="source"),
        TaintStep(file="/test.py", line=10, column=0, variable="user_input", transform="sink_argument"),
    ]
    return TaintPath(steps=steps, sanitized=False)


@pytest.fixture
def sanitized_taint_path() -> TaintPath:
    """A sanitized taint path."""
    steps = [
        TaintStep(file="/test.py", line=5, column=0, variable="user_input", transform="source"),
    ]
    return TaintPath(steps=steps, sanitized=True, sanitizer="shlex.quote")


@pytest.fixture
def make_finding(base_source, base_sink):
    def _make(taint_path: TaintPath, cwe: str = "CWE-89", severity: str = "critical") -> RawFinding:
        sink = Sink(
            file=base_sink.file, line=base_sink.line, column=base_sink.column,
            function=base_sink.function, category=base_sink.category,
            cwe=cwe, language=base_sink.language
        )
        return RawFinding(
            source=base_source,
            sink=sink,
            taint_path=taint_path,
            vulnerability_class=f"{cwe}: Test",
            severity=severity,
            language="python",
            raw_confidence=0.5,
        )
    return _make


@pytest.fixture
def exploit_result_success() -> ExploitResult:
    return ExploitResult(
        exploit_script_hash="a" * 64,
        exit_code=0,
        stdout_truncated="uid=0(root)",
        stderr_truncated="",
        exploitable=True,
        execution_time_ms=300,
    )


@pytest.fixture
def exploit_result_failed() -> ExploitResult:
    return ExploitResult(
        exploit_script_hash="b" * 64,
        exit_code=1,
        stdout_truncated="Error: missing context",
        stderr_truncated="",
        exploitable=False,
        execution_time_ms=200,
    )


class TestTaintCompletenessScore:
    def test_three_steps_full_score(self, full_taint_path) -> None:
        assert taint_completeness_score(full_taint_path) == 100.0

    def test_two_steps_partial_score(self, partial_taint_path) -> None:
        assert taint_completeness_score(partial_taint_path) == 50.0

    def test_one_step_low_score(self) -> None:
        path = TaintPath(steps=[
            TaintStep(file="/t.py", line=1, column=0, variable="x", transform="source")
        ])
        assert taint_completeness_score(path) == 30.0

    def test_no_steps_heuristic_score(self) -> None:
        path = TaintPath(steps=[])
        assert taint_completeness_score(path) == 20.0


class TestSanitizerScore:
    def test_no_sanitizer_full_score(self, partial_taint_path) -> None:
        assert sanitizer_score(partial_taint_path) == 100.0

    def test_sanitized_zero_score(self, sanitized_taint_path) -> None:
        assert sanitizer_score(sanitized_taint_path) == 0.0


class TestCWEBaselineScore:
    def test_cwe78_critical(self, make_finding, partial_taint_path) -> None:
        finding = make_finding(partial_taint_path, cwe="CWE-78", severity="critical")
        assert cwe_baseline_score(finding) == 100.0

    def test_cwe89_critical(self, make_finding, partial_taint_path) -> None:
        finding = make_finding(partial_taint_path, cwe="CWE-89", severity="critical")
        assert cwe_baseline_score(finding) == 100.0

    def test_cwe22_high(self, make_finding, partial_taint_path) -> None:
        finding = make_finding(partial_taint_path, cwe="CWE-22", severity="high")
        assert cwe_baseline_score(finding) == 75.0

    def test_unknown_cwe_falls_back_to_severity(self, make_finding, partial_taint_path) -> None:
        finding = make_finding(partial_taint_path, cwe="CWE-9999", severity="medium")
        assert cwe_baseline_score(finding) == 50.0


class TestExploitBonusScore:
    def test_no_results_zero_bonus(self) -> None:
        assert exploit_bonus_score([]) == 0.0

    def test_failed_exploit_zero_bonus(self, exploit_result_failed) -> None:
        """CRITICAL: Failed exploit MUST NOT penalize. Bonus must be 0, not negative."""
        score = exploit_bonus_score([exploit_result_failed])
        assert score == 0.0, "Failed exploit must not penalize (bonus-only model)"

    def test_successful_exploit_full_bonus(self, exploit_result_success) -> None:
        assert exploit_bonus_score([exploit_result_success]) == 100.0

    def test_mixed_results_bonus_if_any_success(
        self, exploit_result_success, exploit_result_failed
    ) -> None:
        score = exploit_bonus_score([exploit_result_failed, exploit_result_success])
        assert score == 100.0


class TestComputeConfidence:
    def test_bonus_only_failed_exploit_does_not_reduce_base(
        self, make_finding, full_taint_path, exploit_result_failed
    ) -> None:
        """CRITICAL: Failed exploit must not reduce confidence below base score."""
        finding = make_finding(full_taint_path, cwe="CWE-89")
        # Base score without exploit
        score_no_exploit, _ = compute_confidence(finding, [])
        # Score with failed exploit (should equal base, never less)
        score_failed, _ = compute_confidence(finding, [exploit_result_failed])
        assert score_failed == score_no_exploit, (
            "Failed exploit must not reduce confidence (bonus-only model)"
        )

    def test_successful_exploit_adds_bonus(
        self, make_finding, full_taint_path, exploit_result_success
    ) -> None:
        """Successful exploit adds up to 10 points bonus."""
        finding = make_finding(full_taint_path, cwe="CWE-89")
        score_no_exploit, _ = compute_confidence(finding, [])
        score_exploited, _ = compute_confidence(finding, [exploit_result_success])
        assert score_exploited >= score_no_exploit

    def test_score_capped_at_100(
        self, make_finding, full_taint_path, exploit_result_success
    ) -> None:
        finding = make_finding(full_taint_path, cwe="CWE-89")
        score, _ = compute_confidence(finding, [exploit_result_success])
        assert score <= 100

    def test_score_non_negative(self, make_finding, sanitized_taint_path) -> None:
        finding = make_finding(sanitized_taint_path, cwe="CWE-89", severity="low")
        score, _ = compute_confidence(finding, [])
        assert score >= 0


class TestConfidenceToStatus:
    def test_confirmed_75_plus(self) -> None:
        assert confidence_to_status(75) == "confirmed"
        assert confidence_to_status(100) == "confirmed"

    def test_likely_45_to_74(self) -> None:
        assert confidence_to_status(45) == "likely"
        assert confidence_to_status(74) == "likely"

    def test_unconfirmed_20_to_44(self) -> None:
        assert confidence_to_status(20) == "unconfirmed"
        assert confidence_to_status(44) == "unconfirmed"

    def test_false_positive_below_20(self) -> None:
        assert confidence_to_status(0) == "false_positive"
        assert confidence_to_status(19) == "false_positive"
