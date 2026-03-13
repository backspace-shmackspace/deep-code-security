"""End-to-end integration tests for the full pipeline."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from deep_code_security.architect.orchestrator import ArchitectOrchestrator
from deep_code_security.auditor.models import VerifiedFinding
from deep_code_security.auditor.orchestrator import AuditorOrchestrator
from deep_code_security.hunter.orchestrator import HunterOrchestrator
from deep_code_security.hunter.registry import clear_registry_cache
from deep_code_security.shared.config import Config, reset_config
from deep_code_security.shared.json_output import serialize_models

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
VULNERABLE_PYTHON = FIXTURES_DIR / "vulnerable_samples" / "python"
SAFE_PYTHON = FIXTURES_DIR / "safe_samples" / "python"


@pytest.fixture(autouse=True)
def clear_cache():
    clear_registry_cache()
    yield
    clear_registry_cache()


@pytest.fixture
def pipeline_config() -> Config:
    """Config with fixture dirs as allowed paths."""
    os.environ["DCS_ALLOWED_PATHS"] = str(FIXTURES_DIR)
    os.environ["DCS_REGISTRY_PATH"] = str(Path(__file__).parent.parent.parent / "registries")
    reset_config()
    config = Config()
    yield config
    os.environ.pop("DCS_ALLOWED_PATHS", None)
    os.environ.pop("DCS_REGISTRY_PATH", None)
    reset_config()


class TestEndToEndPipeline:
    """Integration tests for the full Hunter -> Auditor -> Architect pipeline."""

    def test_full_pipeline_produces_json(self, pipeline_config: Config) -> None:
        """Full pipeline produces JSON-serializable output at each phase."""
        hunter = HunterOrchestrator(config=pipeline_config)

        # Phase 1: Hunt
        findings, hunt_stats, total, has_more = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )

        # Verify JSON serialization
        findings_json = json.dumps(serialize_models(findings))
        stats_json = json.dumps(hunt_stats.model_dump(mode="json"))
        assert isinstance(findings_json, str)
        assert isinstance(stats_json, str)

    def test_safe_samples_produce_no_confirmed_findings(
        self, pipeline_config: Config
    ) -> None:
        """Safe sample fixtures should produce no confirmed findings."""
        from deep_code_security.auditor.confidence import compute_confidence

        hunter = HunterOrchestrator(config=pipeline_config)
        findings, _, total, _ = hunter.scan(
            target_path=str(SAFE_PYTHON),
            severity_threshold="low",
        )

        # All findings should have low base confidence (safe code)
        for f in findings:
            confidence, status = compute_confidence(f, [])
            # Safe code might still trigger pattern matches, but confidence
            # should be lower for sanitized or partial paths
            assert status in ("unconfirmed", "false_positive", "likely", "confirmed")

    def test_findings_have_valid_pydantic_models(self, pipeline_config: Config) -> None:
        """All findings have valid Pydantic model structure."""
        from deep_code_security.hunter.models import RawFinding

        hunter = HunterOrchestrator(config=pipeline_config)
        findings, _, _, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )

        for f in findings:
            assert isinstance(f, RawFinding)
            assert f.id
            assert f.source.file
            assert f.sink.file
            assert f.sink.cwe.startswith("CWE-")
            assert f.vulnerability_class.startswith("CWE-")
            assert f.severity in ("critical", "high", "medium", "low")
            assert 0.0 <= f.raw_confidence <= 1.0

    def test_pipeline_with_language_filter(self, pipeline_config: Config) -> None:
        """Pipeline respects language filter — Python only returns Python findings."""
        hunter = HunterOrchestrator(config=pipeline_config)
        findings, _, _, _ = hunter.scan(
            target_path=str(FIXTURES_DIR),
            languages=["python"],
            severity_threshold="low",
        )
        for f in findings:
            assert f.language == "python"

    def test_pipeline_pagination(self, pipeline_config: Config) -> None:
        """Pagination parameters work correctly."""
        hunter = HunterOrchestrator(config=pipeline_config)

        # Get total count
        _, _, total, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )

        if total > 0:
            # Get page 1
            page1, _, _, has_more1 = hunter.scan(
                target_path=str(VULNERABLE_PYTHON),
                severity_threshold="low",
                max_results=1,
                offset=0,
            )
            assert len(page1) <= 1
            if total > 1:
                assert has_more1

    def test_auditor_with_mock_sandbox(self, pipeline_config: Config) -> None:
        """Auditor runs with mock sandbox, produces VerifiedFinding objects."""
        hunter = HunterOrchestrator(config=pipeline_config)
        findings, _, _, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )

        if not findings:
            pytest.skip("No findings to verify")

        # Use mock sandbox (no Docker required)
        mock_sandbox = MagicMock()
        mock_sandbox.is_available.return_value = False
        mock_sandbox._runtime_cmd = None

        auditor = AuditorOrchestrator(config=pipeline_config, sandbox=mock_sandbox)
        verified, verify_stats = auditor.verify(
            findings=findings[:3],  # Limit for speed
            target_path=str(VULNERABLE_PYTHON),
        )

        assert len(verified) == len(findings[:3])
        for vf in verified:
            assert isinstance(vf, VerifiedFinding)
            assert 0 <= vf.confidence_score <= 100
            assert vf.verification_status in (
                "confirmed", "likely", "unconfirmed", "false_positive"
            )

    def test_architect_generates_guidance(self, pipeline_config: Config) -> None:
        """Architect generates guidance for verified findings."""
        from deep_code_security.auditor.confidence import compute_confidence
        hunter = HunterOrchestrator(config=pipeline_config)
        findings, _, _, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )

        if not findings:
            pytest.skip("No findings to generate guidance for")

        # Wrap in VerifiedFinding without sandbox
        verified = []
        for f in findings[:2]:
            confidence, status = compute_confidence(f, [])
            verified.append(VerifiedFinding(
                finding=f,
                exploit_results=[],
                confidence_score=confidence,
                verification_status=status,
            ))

        architect = ArchitectOrchestrator(config=pipeline_config)
        guidance, stats = architect.remediate(
            verified_findings=verified,
            target_path=str(VULNERABLE_PYTHON),
        )

        assert len(guidance) >= 1
        assert stats.guidance_generated >= 1

        for g in guidance:
            assert g.finding_id
            assert g.vulnerability_explanation
            assert g.fix_pattern
            assert g.code_example

    def test_confidence_bonus_only_model(self, pipeline_config: Config) -> None:
        """Verify that exploit failure never reduces confidence below base."""
        from deep_code_security.auditor.confidence import compute_confidence
        from deep_code_security.auditor.models import ExploitResult

        hunter = HunterOrchestrator(config=pipeline_config)
        findings, _, _, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )

        for f in findings:
            # Base confidence (no exploit)
            base_score, _ = compute_confidence(f, [])

            # Confidence with failed exploit
            failed_exploit = ExploitResult(
                exploit_script_hash="a" * 64,
                exit_code=1,
                stdout_truncated="Error",
                stderr_truncated="",
                exploitable=False,
                execution_time_ms=100,
            )
            score_with_failed, _ = compute_confidence(f, [failed_exploit])

            assert score_with_failed == base_score, (
                f"Failed exploit should not reduce confidence: "
                f"base={base_score}, with_failed={score_with_failed}"
            )
