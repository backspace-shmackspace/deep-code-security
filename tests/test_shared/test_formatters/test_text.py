"""Tests for TextFormatter."""

from __future__ import annotations

import pytest

from deep_code_security.shared.formatters.text import TextFormatter


@pytest.fixture
def sample_bridge_result():
    """Minimal BridgeResult for testing format_hunt_fuzz."""
    from deep_code_security.bridge.models import BridgeResult, FuzzTarget, SASTContext

    sast_ctx = SASTContext(
        cwe_ids=["CWE-78"],
        vulnerability_classes=["CWE-78: OS Command Injection"],
        sink_functions=["os.system"],
        source_categories=["web_input"],
        severity="high",
        finding_count=1,
    )
    target = FuzzTarget(
        file_path="/tmp/project/app.py",
        function_name="process_cmd",
        sast_context=sast_ctx,
        finding_ids=["test-finding-001"],
        requires_instance=False,
        parameter_count=1,
    )
    return BridgeResult(
        fuzz_targets=[target],
        skipped_findings=0,
        skipped_reasons=[],
        total_findings=1,
        not_directly_fuzzable=0,
    )


@pytest.fixture
def sample_hunt_fuzz_result(sample_hunt_result, sample_bridge_result):
    """Minimal HuntFuzzResult for testing format_hunt_fuzz."""
    from deep_code_security.shared.formatters.protocol import HuntFuzzResult

    return HuntFuzzResult(
        hunt_result=sample_hunt_result,
        bridge_result=sample_bridge_result,
        fuzz_result=None,
        correlation=None,
    )


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

    def test_text_format_hunt_with_suppressions(self, sample_finding, sample_stats):
        """Suppression count appears in summary line when suppressions active."""
        from deep_code_security.shared.formatters.protocol import HuntResult, SuppressionSummary

        ss = SuppressionSummary(
            suppressed_count=3,
            total_rules=5,
            expired_rules=1,
            suppression_reasons={"f1": "Admin paths", "f2": "Generated code", "f3": "Admin paths"},
            suppression_file="/project/.dcs-suppress.yaml",
        )
        result = HuntResult(
            findings=[sample_finding],
            stats=sample_stats,
            total_count=1,
            has_more=False,
            suppression_summary=ss,
        )
        fmt = TextFormatter()
        output = fmt.format_hunt(result)
        assert "3 suppressed" in output
        assert "Suppressions:" in output
        assert "5 rules" in output
        assert "1 expired" in output

    def test_text_format_hunt_no_suppressions(self, sample_hunt_result):
        """Text output is unchanged when suppression_summary is None."""
        fmt = TextFormatter()
        output = fmt.format_hunt(sample_hunt_result)
        assert "suppressed" not in output.lower()
        assert "Suppressions" not in output


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


class TestTextFormatterHuntFuzz:
    def test_format_hunt_fuzz_contains_header(self, sample_hunt_fuzz_result):
        fmt = TextFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result)
        assert "HUNT+FUZZ" in output

    def test_format_hunt_fuzz_sast_section(self, sample_hunt_fuzz_result):
        fmt = TextFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result)
        assert "SAST Results" in output
        assert "findings" in output.lower()

    def test_format_hunt_fuzz_bridge_section(self, sample_hunt_fuzz_result):
        fmt = TextFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result)
        assert "Bridge Analysis" in output
        assert "process_cmd" in output
        assert "Fuzz targets found" in output

    def test_format_hunt_fuzz_no_fuzz_result(self, sample_hunt_fuzz_result):
        """When fuzz_result is None, fuzz section is absent."""
        fmt = TextFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result)
        assert "Fuzz Results" not in output

    def test_format_hunt_fuzz_with_correlation(self, sample_hunt_result, sample_bridge_result):
        from deep_code_security.bridge.models import (
            CorrelationEntry,
            CorrelationReport,
        )
        from deep_code_security.shared.formatters.protocol import HuntFuzzResult

        entry = CorrelationEntry(
            finding_id="f1",
            vulnerability_class="CWE-78: OS Command Injection",
            severity="high",
            sink_function="os.system",
            target_function="process_cmd",
            crash_in_finding_scope=True,
            crash_count=1,
            crash_signatures=["ZeroDivisionError"],
        )
        correlation = CorrelationReport(
            entries=[entry],
            total_sast_findings=1,
            crash_in_scope_count=1,
            fuzz_targets_count=1,
            total_crashes=1,
        )
        result = HuntFuzzResult(
            hunt_result=sample_hunt_result,
            bridge_result=sample_bridge_result,
            fuzz_result=None,
            correlation=correlation,
        )
        fmt = TextFormatter()
        output = fmt.format_hunt_fuzz(result)
        assert "Correlation" in output
        assert "CRASH IN SCOPE" in output
        assert "process_cmd" in output

    def test_format_hunt_fuzz_with_fuzz_result(self, sample_hunt_result, sample_bridge_result):
        from deep_code_security.shared.formatters.protocol import (
            FuzzCrashSummary,
            FuzzReportResult,
            HuntFuzzResult,
            UniqueCrashSummary,
        )

        crash = FuzzCrashSummary(
            target_function="process_cmd",
            exception="ZeroDivisionError: division by zero",
        )
        unique_crash = UniqueCrashSummary(
            signature="ZeroDivisionError|process_cmd",
            exception_type="ZeroDivisionError",
            exception_message="division by zero",
            count=1,
            target_functions=["process_cmd"],
            representative=crash,
        )
        fuzz_result = FuzzReportResult(
            targets=[],
            crashes=[crash],
            unique_crashes=[unique_crash],
            total_inputs=5,
            crash_count=1,
            unique_crash_count=1,
            total_iterations=1,
        )
        result = HuntFuzzResult(
            hunt_result=sample_hunt_result,
            bridge_result=sample_bridge_result,
            fuzz_result=fuzz_result,
            correlation=None,
        )
        fmt = TextFormatter()
        output = fmt.format_hunt_fuzz(result)
        assert "Fuzz Results" in output
        assert "ZeroDivisionError" in output
