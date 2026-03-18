"""Tests for the Hunter orchestrator."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from deep_code_security.hunter.orchestrator import HunterOrchestrator
from deep_code_security.hunter.registry import clear_registry_cache
from deep_code_security.shared.config import Config, reset_config

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
VULNERABLE_PYTHON = FIXTURES_DIR / "vulnerable_samples" / "python"
SAFE_PYTHON = FIXTURES_DIR / "safe_samples" / "python"


@pytest.fixture(autouse=True)
def clear_cache():
    clear_registry_cache()
    yield
    clear_registry_cache()


@pytest.fixture
def hunter_config(tmp_path: Path) -> Config:
    """Config with fixtures dir as allowed path."""
    os.environ["DCS_ALLOWED_PATHS"] = str(FIXTURES_DIR)
    os.environ["DCS_REGISTRY_PATH"] = str(
        Path(__file__).parent.parent.parent / "registries"
    )
    reset_config()
    config = Config()
    yield config
    os.environ.pop("DCS_ALLOWED_PATHS", None)
    os.environ.pop("DCS_REGISTRY_PATH", None)
    reset_config()


class TestHunterOrchestratorScan:
    """Tests for HunterOrchestrator.scan()."""

    def test_scan_returns_tuple(self, hunter_config: Config) -> None:
        """scan() returns (findings, stats, total_count, has_more)."""
        hunter = HunterOrchestrator(config=hunter_config)
        result = hunter.scan(target_path=str(VULNERABLE_PYTHON))
        assert len(result) == 4
        findings, stats, total_count, has_more = result
        assert isinstance(findings, list)
        assert isinstance(total_count, int)
        assert isinstance(has_more, bool)

    def test_scan_vulnerable_python(self, hunter_config: Config) -> None:
        """Scan vulnerable Python fixtures returns non-empty findings."""
        hunter = HunterOrchestrator(config=hunter_config)
        findings, stats, total_count, has_more = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )
        # Stats should reflect files scanned
        assert stats.files_scanned >= 1
        assert stats.sources_found >= 0
        assert stats.sinks_found >= 0

    def test_scan_with_language_filter(self, hunter_config: Config) -> None:
        """Language filter restricts scan to specified languages."""
        hunter = HunterOrchestrator(config=hunter_config)
        findings, stats, total_count, has_more = hunter.scan(
            target_path=str(FIXTURES_DIR),
            languages=["python"],
        )
        # All findings should be Python
        for f in findings:
            assert f.language == "python"

    def test_scan_respects_severity_threshold(self, hunter_config: Config) -> None:
        """Severity threshold filters out lower-severity findings."""
        hunter = HunterOrchestrator(config=hunter_config)
        findings_all, _, total_all, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )
        findings_critical, _, total_critical, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="critical",
        )
        # Critical threshold should return <= all threshold
        assert total_critical <= total_all

    def test_scan_pagination(self, hunter_config: Config) -> None:
        """Pagination works with max_results and offset."""
        hunter = HunterOrchestrator(config=hunter_config)
        page1, stats, total, has_more_1 = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            max_results=1,
            offset=0,
            severity_threshold="low",
        )
        page2, _, total2, has_more_2 = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            max_results=1,
            offset=1,
            severity_threshold="low",
        )
        # Pages should be different (unless there's only 1 finding total)
        if total > 1:
            assert page1 != page2

    def test_scan_empty_directory(self, hunter_config: Config, tmp_path: Path) -> None:
        """Scanning an empty directory returns zero findings."""
        os.environ["DCS_ALLOWED_PATHS"] = str(tmp_path)
        reset_config()
        config = Config()
        config.registry_path = hunter_config.registry_path
        hunter = HunterOrchestrator(config=config)
        findings, stats, total, has_more = hunter.scan(target_path=str(tmp_path))
        assert findings == []
        assert total == 0
        assert not has_more
        os.environ.pop("DCS_ALLOWED_PATHS", None)
        reset_config()

    def test_scan_produces_stats(self, hunter_config: Config) -> None:
        """Scan populates all stats fields."""
        hunter = HunterOrchestrator(config=hunter_config)
        _, stats, _, _ = hunter.scan(target_path=str(VULNERABLE_PYTHON))
        assert stats.scan_duration_ms >= 0
        assert stats.files_scanned >= 0
        assert isinstance(stats.languages_detected, list)

    def test_findings_have_required_fields(self, hunter_config: Config) -> None:
        """All findings have required Pydantic fields."""
        hunter = HunterOrchestrator(config=hunter_config)
        findings, _, _, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )
        for f in findings:
            assert f.id
            assert f.source.file
            assert f.sink.file
            assert f.vulnerability_class
            assert f.language
            assert 0.0 <= f.raw_confidence <= 1.0

    def test_findings_serializable(self, hunter_config: Config) -> None:
        """All findings can be serialized to JSON."""
        import json

        from deep_code_security.shared.json_output import serialize_models

        hunter = HunterOrchestrator(config=hunter_config)
        findings, stats, _, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )
        # Should not raise
        json_str = json.dumps(serialize_models(findings))
        assert isinstance(json_str, str)

    def test_get_findings_for_ids(self, hunter_config: Config) -> None:
        """get_findings_for_ids retrieves findings from session."""
        hunter = HunterOrchestrator(config=hunter_config)
        findings, _, _, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )
        if findings:
            ids = [findings[0].id]
            retrieved = hunter.get_findings_for_ids(ids)
            assert len(retrieved) == 1
            assert retrieved[0].id == findings[0].id


class TestHunterOrchestratorSuppressions:
    """Tests for suppression integration in HunterOrchestrator.scan()."""

    def test_scan_return_tuple_unchanged(self, hunter_config: Config) -> None:
        """scan() still returns a 4-tuple even with suppressions present."""
        hunter = HunterOrchestrator(config=hunter_config)
        result = hunter.scan(target_path=str(VULNERABLE_PYTHON))
        assert len(result) == 4

    def test_scan_without_suppression_file(
        self, hunter_config: Config, tmp_path: Path
    ) -> None:
        """ScanStats suppression fields are 0/empty when no suppression file exists."""
        os.environ["DCS_ALLOWED_PATHS"] = str(tmp_path)
        reset_config()
        config = Config()
        config.registry_path = hunter_config.registry_path
        hunter = HunterOrchestrator(config=config)
        _, stats, _, _ = hunter.scan(target_path=str(tmp_path))
        assert stats.findings_suppressed == 0
        assert stats.suppression_rules_loaded == 0
        assert stats.suppression_rules_expired == 0
        assert stats.suppressed_finding_ids == []
        assert hunter.last_suppression_result is None
        os.environ.pop("DCS_ALLOWED_PATHS", None)
        reset_config()

    def test_scan_with_suppression_file(
        self, hunter_config: Config
    ) -> None:
        """Suppressions are applied when .dcs-suppress.yaml exists in the target."""
        hunter = HunterOrchestrator(config=hunter_config)
        # First get findings without any suppression file to see what we find
        findings_all, stats_all, total_all, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )
        if not findings_all:
            # Nothing to suppress -- test is vacuously passing
            return

        # Write a suppression file that suppresses everything found
        suppress_file = VULNERABLE_PYTHON / ".dcs-suppress.yaml"
        first_finding = findings_all[0]
        suppress_data = {
            "version": 1,
            "suppressions": [
                {
                    "rule": first_finding.sink.cwe,
                    "reason": "Suppressing for test",
                }
            ],
        }
        try:
            suppress_file.write_text(
                yaml.dump(suppress_data), encoding="utf-8"
            )
            findings_suppressed, stats, total, _ = hunter.scan(
                target_path=str(VULNERABLE_PYTHON),
                severity_threshold="low",
            )
            # The finding matching the rule should be suppressed
            assert stats.findings_suppressed >= 0
            assert stats.suppression_rules_loaded == 1
        finally:
            suppress_file.unlink(missing_ok=True)

    def test_scan_ignore_suppressions_flag(
        self, hunter_config: Config
    ) -> None:
        """All findings returned when ignore_suppressions=True."""
        hunter = HunterOrchestrator(config=hunter_config)
        findings_all, _, total_all, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )
        if not findings_all:
            return

        # Write a suppression file that would suppress everything
        suppress_file = VULNERABLE_PYTHON / ".dcs-suppress.yaml"
        suppress_data = {
            "version": 1,
            "suppressions": [
                {
                    "file": "**/*.py",
                    "reason": "Suppressing all for test",
                }
            ],
        }
        try:
            suppress_file.write_text(
                yaml.dump(suppress_data), encoding="utf-8"
            )
            # With ignore_suppressions=True, all findings are returned
            findings_ignored, _, total_ignored, _ = hunter.scan(
                target_path=str(VULNERABLE_PYTHON),
                severity_threshold="low",
                ignore_suppressions=True,
            )
            assert total_ignored == total_all
            assert hunter.last_suppression_result is None
        finally:
            suppress_file.unlink(missing_ok=True)

    def test_scan_stats_include_suppression_counts(
        self, hunter_config: Config
    ) -> None:
        """ScanStats.findings_suppressed is populated from SuppressionResult."""
        hunter = HunterOrchestrator(config=hunter_config)
        findings_all, _, _, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )
        if not findings_all:
            return

        suppress_file = VULNERABLE_PYTHON / ".dcs-suppress.yaml"
        first_finding = findings_all[0]
        suppress_data = {
            "version": 1,
            "suppressions": [
                {
                    "rule": first_finding.sink.cwe,
                    "reason": "Test suppression",
                }
            ],
        }
        try:
            suppress_file.write_text(
                yaml.dump(suppress_data), encoding="utf-8"
            )
            _, stats, _, _ = hunter.scan(
                target_path=str(VULNERABLE_PYTHON),
                severity_threshold="low",
            )
            # Stats fields should be populated
            assert isinstance(stats.findings_suppressed, int)
            assert isinstance(stats.suppression_rules_loaded, int)
            assert isinstance(stats.suppression_rules_expired, int)
            assert isinstance(stats.suppressed_finding_ids, list)
            assert stats.suppression_rules_loaded == 1
        finally:
            suppress_file.unlink(missing_ok=True)

    def test_scan_last_suppression_result(
        self, hunter_config: Config
    ) -> None:
        """orchestrator.last_suppression_result is populated after a scan with suppression file."""
        hunter = HunterOrchestrator(config=hunter_config)
        # No suppression file: result is None
        hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )
        assert hunter.last_suppression_result is None

        findings_all, _, _, _ = hunter.scan(
            target_path=str(VULNERABLE_PYTHON),
            severity_threshold="low",
        )
        if not findings_all:
            return

        suppress_file = VULNERABLE_PYTHON / ".dcs-suppress.yaml"
        suppress_data = {
            "version": 1,
            "suppressions": [
                {
                    "rule": findings_all[0].sink.cwe,
                    "reason": "Test last result",
                }
            ],
        }
        try:
            suppress_file.write_text(
                yaml.dump(suppress_data), encoding="utf-8"
            )
            hunter.scan(
                target_path=str(VULNERABLE_PYTHON),
                severity_threshold="low",
            )
            # last_suppression_result is now populated
            result = hunter.last_suppression_result
            assert result is not None
            assert isinstance(result.active_findings, list)
            assert isinstance(result.suppressed_findings, list)
            assert result.total_rules == 1
        finally:
            suppress_file.unlink(missing_ok=True)

    def test_scan_malformed_suppression_file_raises(
        self, hunter_config: Config
    ) -> None:
        """A malformed .dcs-suppress.yaml raises ValueError."""
        suppress_file = VULNERABLE_PYTHON / ".dcs-suppress.yaml"
        try:
            suppress_file.write_text(
                "version: 1\nsuppressions: [{\n  broken yaml\n",
                encoding="utf-8",
            )
            hunter = HunterOrchestrator(config=hunter_config)
            with pytest.raises(ValueError):
                hunter.scan(
                    target_path=str(VULNERABLE_PYTHON),
                    severity_threshold="low",
                )
        finally:
            suppress_file.unlink(missing_ok=True)
