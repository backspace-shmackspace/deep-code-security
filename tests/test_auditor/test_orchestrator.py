"""Tests for the AuditorOrchestrator."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from deep_code_security.auditor.orchestrator import AuditorOrchestrator
from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath, TaintStep
from deep_code_security.shared.config import Config


def _make_finding(severity: str = "critical", raw_confidence: float = 0.7) -> RawFinding:
    return RawFinding(
        source=Source(
            file="/test.py", line=1, column=0,
            function="request.form", category="web_input", language="python",
        ),
        sink=Sink(
            file="/test.py", line=5, column=0,
            function="cursor.execute", category="sql_injection",
            cwe="CWE-89", language="python",
        ),
        taint_path=TaintPath(steps=[
            TaintStep(file="/test.py", line=1, column=0, variable="u", transform="source"),
        ]),
        vulnerability_class="CWE-89: SQL Injection",
        severity=severity,
        language="python",
        raw_confidence=raw_confidence,
    )


@pytest.fixture
def mock_sandbox():
    """Sandbox that is unavailable (no exploit runs)."""
    sandbox = MagicMock()
    sandbox.is_available.return_value = False
    return sandbox


@pytest.fixture
def orchestrator(mock_sandbox) -> AuditorOrchestrator:
    config = Config()
    orch = AuditorOrchestrator(config=config, sandbox=mock_sandbox)
    return orch


class TestAuditorOrchestratorVerify:
    """Tests for AuditorOrchestrator.verify."""

    def test_verify_empty_list_returns_empty(self, orchestrator) -> None:
        verified, stats = orchestrator.verify([], target_path="/tmp")
        assert verified == []
        assert stats.total_findings == 0
        assert stats.verified_count == 0

    def test_verify_single_finding(self, orchestrator) -> None:
        finding = _make_finding()
        verified, stats = orchestrator.verify([finding], target_path="/tmp")
        assert len(verified) == 1
        assert stats.total_findings == 1
        assert stats.verified_count == 1
        assert stats.skipped_count == 0

    def test_verify_prioritizes_critical_first(self, orchestrator) -> None:
        """Findings are sorted critical > high > medium > low."""
        low = _make_finding("low")
        high = _make_finding("high")
        critical = _make_finding("critical")
        verified, stats = orchestrator.verify(
            [low, critical, high], target_path="/tmp", max_verifications=2
        )
        # Only 2 verified (critical and high), 1 skipped (low)
        assert stats.verified_count == 2
        assert stats.skipped_count == 1

    def test_verify_skipped_findings_still_get_base_confidence(
        self, orchestrator
    ) -> None:
        """Findings beyond max_verifications get base confidence only."""
        findings = [_make_finding() for _ in range(5)]
        verified, stats = orchestrator.verify(
            findings, target_path="/tmp", max_verifications=2
        )
        # All 5 should appear in verified list (3 skipped get base confidence)
        assert len(verified) == 5
        assert stats.skipped_count == 3

    def test_verify_returns_stats_with_status_counts(self, orchestrator) -> None:
        finding = _make_finding(raw_confidence=0.9)
        verified, stats = orchestrator.verify([finding], target_path="/tmp")
        total_status = (
            stats.confirmed + stats.likely + stats.unconfirmed + stats.false_positives
        )
        assert total_status == 1

    def test_verify_stores_in_session(self, orchestrator) -> None:
        finding = _make_finding()
        verified, _ = orchestrator.verify([finding], target_path="/tmp")
        assert finding.id in orchestrator._session_verified

    def test_verify_reports_sandbox_availability(self, orchestrator) -> None:
        finding = _make_finding()
        _, stats = orchestrator.verify([finding], target_path="/tmp")
        assert stats.sandbox_available is False

    def test_get_verified_for_ids_returns_matching(self, orchestrator) -> None:
        finding = _make_finding()
        orchestrator.verify([finding], target_path="/tmp")
        results = orchestrator.get_verified_for_ids([finding.id])
        assert len(results) == 1
        assert results[0].finding.id == finding.id

    def test_get_verified_for_ids_unknown_ids_returns_empty(
        self, orchestrator
    ) -> None:
        results = orchestrator.get_verified_for_ids(["nonexistent-id"])
        assert results == []

    def test_verify_duration_recorded(self, orchestrator) -> None:
        finding = _make_finding()
        _, stats = orchestrator.verify([finding], target_path="/tmp")
        assert stats.verification_duration_ms >= 0

    def test_verify_sandbox_exception_still_produces_result(self) -> None:
        """If sandbox.run_exploit raises, the verifier falls back to base confidence."""
        mock_sandbox = MagicMock()
        mock_sandbox.is_available.return_value = True
        mock_sandbox.run_exploit.side_effect = RuntimeError("container crash")

        orch = AuditorOrchestrator(config=Config(), sandbox=mock_sandbox)
        finding = _make_finding()
        verified, stats = orch.verify([finding], target_path="/tmp")
        # Verifier catches the sandbox error internally and produces a result with base confidence
        assert stats.verified_count == 1
        assert len(verified) == 1
