"""Tests for TUI Pydantic models (RunMeta, ScanConfig)."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from deep_code_security.tui.models import RunMeta, ScanConfig


class TestRunMetaRequiredFields:
    """RunMeta requires timestamp, target_path, project_name, scan_type,
    duration_seconds, and exit_code."""

    def test_run_meta_required_fields(self) -> None:
        """Creating RunMeta without required fields raises ValidationError."""
        with pytest.raises(ValidationError):
            RunMeta()  # type: ignore[call-arg]

    def test_run_meta_missing_timestamp(self) -> None:
        with pytest.raises(ValidationError):
            RunMeta(
                target_path="/tmp/test",
                project_name="test",
                scan_type="hunt",
                duration_seconds=1.0,
                exit_code=0,
            )  # type: ignore[call-arg]

    def test_run_meta_missing_target_path(self) -> None:
        with pytest.raises(ValidationError):
            RunMeta(
                timestamp="2026-03-20T14:30:00Z",
                project_name="test",
                scan_type="hunt",
                duration_seconds=1.0,
                exit_code=0,
            )  # type: ignore[call-arg]

    def test_run_meta_missing_exit_code(self) -> None:
        with pytest.raises(ValidationError):
            RunMeta(
                timestamp="2026-03-20T14:30:00Z",
                target_path="/tmp/test",
                project_name="test",
                scan_type="hunt",
                duration_seconds=1.0,
            )  # type: ignore[call-arg]


class TestRunMetaDefaults:
    """RunMeta has sensible defaults for optional fields."""

    def test_run_meta_defaults(self) -> None:
        meta = RunMeta(
            timestamp="2026-03-20T14:30:00Z",
            target_path="/tmp/test",
            project_name="test",
            scan_type="hunt",
            duration_seconds=1.0,
            exit_code=0,
        )
        assert meta.findings_count == 0
        assert meta.backend_used == "unknown"
        assert meta.languages == []
        assert meta.severity_threshold == "medium"
        assert meta.report_files == []
        assert meta.error_message == ""
        assert meta.dcs_version == ""
        # run_id is auto-generated UUID
        assert len(meta.run_id) > 0


class TestRunMetaSerializationRoundtrip:
    """RunMeta survives a model_dump -> JSON -> model_validate roundtrip."""

    def test_run_meta_serialization_roundtrip(
        self, sample_run_meta: RunMeta
    ) -> None:
        dumped = sample_run_meta.model_dump()
        json_str = json.dumps(dumped)
        loaded = json.loads(json_str)
        restored = RunMeta.model_validate(loaded)

        assert restored.run_id == sample_run_meta.run_id
        assert restored.timestamp == sample_run_meta.timestamp
        assert restored.target_path == sample_run_meta.target_path
        assert restored.project_name == sample_run_meta.project_name
        assert restored.scan_type == sample_run_meta.scan_type
        assert restored.duration_seconds == sample_run_meta.duration_seconds
        assert restored.findings_count == sample_run_meta.findings_count
        assert restored.backend_used == sample_run_meta.backend_used
        assert restored.exit_code == sample_run_meta.exit_code
        assert restored.languages == sample_run_meta.languages
        assert restored.severity_threshold == sample_run_meta.severity_threshold
        assert restored.report_files == sample_run_meta.report_files
        assert restored.error_message == sample_run_meta.error_message
        assert restored.dcs_version == sample_run_meta.dcs_version


class TestRunMetaValidation:
    """RunMeta enforces field constraints."""

    def test_run_meta_invalid_scan_type(self) -> None:
        """Scan type must be one of the allowed literals."""
        with pytest.raises(ValidationError):
            RunMeta(
                timestamp="2026-03-20T14:30:00Z",
                target_path="/tmp/test",
                project_name="test",
                scan_type="invalid-type",
                duration_seconds=1.0,
                exit_code=0,
            )

    def test_run_meta_negative_duration(self) -> None:
        """Duration must be >= 0.0."""
        with pytest.raises(ValidationError):
            RunMeta(
                timestamp="2026-03-20T14:30:00Z",
                target_path="/tmp/test",
                project_name="test",
                scan_type="hunt",
                duration_seconds=-1.0,
                exit_code=0,
            )


class TestScanConfig:
    """ScanConfig tests for various scan types and options."""

    def test_scan_config_hunt(self, sample_scan_config: ScanConfig) -> None:
        config = ScanConfig(
            target_path="/tmp/project",
            scan_type="hunt",
        )
        assert config.scan_type == "hunt"
        assert config.languages == []
        assert config.severity_threshold == "medium"
        assert config.skip_verify is False
        assert config.ignore_suppressions is False

    def test_scan_config_full_scan(self) -> None:
        config = ScanConfig(
            target_path="/tmp/project",
            scan_type="full-scan",
            skip_verify=True,
        )
        assert config.scan_type == "full-scan"
        assert config.skip_verify is True

    def test_scan_config_hunt_fuzz(self) -> None:
        config = ScanConfig(
            target_path="/tmp/project",
            scan_type="hunt-fuzz",
            ignore_suppressions=True,
        )
        assert config.scan_type == "hunt-fuzz"
        assert config.ignore_suppressions is True

    def test_scan_config_languages_filter(self) -> None:
        config = ScanConfig(
            target_path="/tmp/project",
            scan_type="hunt",
            languages=["python", "go"],
        )
        assert config.languages == ["python", "go"]

    def test_scan_config_invalid_scan_type(self) -> None:
        """ScanConfig also uses the ScanType Literal."""
        with pytest.raises(ValidationError):
            ScanConfig(
                target_path="/tmp/project",
                scan_type="invalid",
            )

    def test_scan_config_severity_values(self) -> None:
        """ScanConfig accepts all valid severity thresholds."""
        for severity in ("critical", "high", "medium", "low"):
            config = ScanConfig(
                target_path="/tmp/project",
                scan_type="hunt",
                severity_threshold=severity,
            )
            assert config.severity_threshold == severity

    def test_scan_config_no_extra_args(self) -> None:
        """ScanConfig has no extra_args field."""
        assert not hasattr(ScanConfig, "extra_args")
        # Attempting to pass extra_args should not set it
        config = ScanConfig(
            target_path="/tmp/project",
            scan_type="hunt",
        )
        assert not hasattr(config, "extra_args")
