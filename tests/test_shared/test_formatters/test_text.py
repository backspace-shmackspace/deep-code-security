"""Tests for TextFormatter."""

from __future__ import annotations

from deep_code_security.shared.formatters.text import TextFormatter


class TestTextFormatterHunt:
    def test_format_hunt_single_finding(self, sample_hunt_result):
        fmt = TextFormatter()
        output = fmt.format_hunt(sample_hunt_result)
        assert "CRITICAL" in output
        assert "app.py" in output
        assert ":10" in output or "10" in output
        assert "SQL Injection" in output

    def test_format_hunt_empty(self, sample_stats):
        from deep_code_security.shared.formatters.protocol import HuntResult

        result = HuntResult(findings=[], stats=sample_stats, total_count=0)
        fmt = TextFormatter()
        output = fmt.format_hunt(result)
        assert "found 0 findings" in output

    def test_format_hunt_has_more(self, sample_finding, sample_stats):
        from deep_code_security.shared.formatters.protocol import HuntResult

        result = HuntResult(
            findings=[sample_finding],
            stats=sample_stats,
            total_count=5,
            has_more=True,
        )
        fmt = TextFormatter()
        output = fmt.format_hunt(result)
        assert "more" in output.lower()


class TestTextFormatterFullScan:
    def test_format_full_scan_with_verified(self, sample_full_scan_result):
        fmt = TextFormatter()
        output = fmt.format_full_scan(sample_full_scan_result)
        assert "Confirmed:" in output
        assert "Likely:" in output

    def test_format_full_scan_skip_verify(self, sample_finding, sample_stats):
        from deep_code_security.shared.formatters.protocol import FullScanResult

        result = FullScanResult(
            findings=[sample_finding],
            verified=[],
            guidance=[],
            hunt_stats=sample_stats,
            total_count=1,
        )
        fmt = TextFormatter()
        output = fmt.format_full_scan(result)
        assert "Total findings: 1" in output
        assert "Confirmed: 0" in output
