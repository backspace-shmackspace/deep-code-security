"""Tests for formatter protocol DTOs."""

from __future__ import annotations

from deep_code_security.shared.formatters.protocol import FullScanResult, HuntResult


class TestHuntResult:
    def test_hunt_result_construction(self, sample_finding, sample_stats):
        result = HuntResult(
            findings=[sample_finding],
            stats=sample_stats,
            total_count=1,
            has_more=False,
        )
        assert len(result.findings) == 1
        assert result.total_count == 1
        assert result.has_more is False
        assert result.stats.files_scanned == 42

    def test_hunt_result_empty_findings(self, sample_stats):
        result = HuntResult(
            findings=[],
            stats=sample_stats,
            total_count=0,
            has_more=False,
        )
        assert result.findings == []
        assert result.total_count == 0

    def test_hunt_result_no_target_path(self, sample_finding, sample_stats):
        result = HuntResult(
            findings=[sample_finding],
            stats=sample_stats,
        )
        assert not hasattr(result, "target_path")
        # Also verify it's not in model fields
        assert "target_path" not in result.model_fields


class TestFullScanResult:
    def test_full_scan_result_construction(self, sample_full_scan_result):
        result = sample_full_scan_result
        assert len(result.findings) == 1
        assert len(result.verified) == 1
        assert len(result.guidance) == 1
        assert result.verify_stats is not None
        assert result.remediate_stats is not None

    def test_full_scan_result_no_verify_stats(self, sample_finding, sample_stats):
        result = FullScanResult(
            findings=[sample_finding],
            verified=[],
            guidance=[],
            hunt_stats=sample_stats,
            verify_stats=None,
            remediate_stats=None,
            total_count=1,
            has_more=False,
        )
        assert result.verify_stats is None
        assert result.remediate_stats is None
