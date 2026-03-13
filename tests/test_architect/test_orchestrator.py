"""Tests for the ArchitectOrchestrator."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from deep_code_security.architect.orchestrator import ArchitectOrchestrator
from deep_code_security.auditor.models import VerifiedFinding
from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath, TaintStep
from deep_code_security.shared.config import Config


def _make_verified_finding(confidence: int = 55, status: str = "likely") -> VerifiedFinding:
    finding = RawFinding(
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
        severity="high",
        language="python",
        raw_confidence=0.7,
    )
    return VerifiedFinding(
        finding=finding,
        exploit_results=[],
        confidence_score=confidence,
        verification_status=status,
    )


@pytest.fixture
def orchestrator() -> ArchitectOrchestrator:
    return ArchitectOrchestrator(config=Config())


class TestArchitectOrchestratorRemediate:
    """Tests for ArchitectOrchestrator.remediate."""

    def test_remediate_empty_list(self, orchestrator, tmp_path) -> None:
        guidance, stats = orchestrator.remediate([], target_path=str(tmp_path))
        assert guidance == []
        assert stats.total_verified == 0
        assert stats.guidance_generated == 0

    def test_remediate_single_finding(self, orchestrator, tmp_path) -> None:
        vf = _make_verified_finding()
        guidance, stats = orchestrator.remediate([vf], target_path=str(tmp_path))
        assert len(guidance) == 1
        assert stats.guidance_generated == 1
        assert stats.total_verified == 1

    def test_remediate_guidance_has_finding_id(self, orchestrator, tmp_path) -> None:
        vf = _make_verified_finding()
        guidance, _ = orchestrator.remediate([vf], target_path=str(tmp_path))
        assert guidance[0].finding_id == vf.finding.id

    def test_remediate_multiple_findings(self, orchestrator, tmp_path) -> None:
        findings = [_make_verified_finding() for _ in range(3)]
        guidance, stats = orchestrator.remediate(findings, target_path=str(tmp_path))
        assert stats.guidance_generated == 3
        assert len(guidance) == 3

    def test_remediate_records_duration(self, orchestrator, tmp_path) -> None:
        vf = _make_verified_finding()
        _, stats = orchestrator.remediate([vf], target_path=str(tmp_path))
        assert stats.remediation_duration_ms >= 0

    def test_remediate_error_in_guidance_skipped(self, tmp_path) -> None:
        """If guidance generator raises, the finding is silently skipped."""
        orch = ArchitectOrchestrator(config=Config())
        orch.guidance_generator = MagicMock()
        orch.guidance_generator.generate.side_effect = ValueError("bad finding")

        vf = _make_verified_finding()
        guidance, stats = orch.remediate([vf], target_path=str(tmp_path))
        assert guidance == []
        assert stats.guidance_generated == 0

    def test_remediate_accepts_path_object(self, orchestrator, tmp_path) -> None:
        vf = _make_verified_finding()
        # target_path as Path object
        guidance, stats = orchestrator.remediate([vf], target_path=tmp_path)
        assert stats.guidance_generated == 1
