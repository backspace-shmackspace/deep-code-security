"""Tests for JsonFormatter."""

from __future__ import annotations

import json

import pytest

from deep_code_security.shared.formatters.json import JsonFormatter


@pytest.fixture
def sample_hunt_fuzz_result(sample_hunt_result, sample_stats):
    """Minimal HuntFuzzResult for testing format_hunt_fuzz."""
    from deep_code_security.bridge.models import BridgeResult, FuzzTarget, SASTContext
    from deep_code_security.shared.formatters.protocol import HuntFuzzResult

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
    bridge = BridgeResult(
        fuzz_targets=[target],
        skipped_findings=0,
        skipped_reasons=[],
        total_findings=1,
        not_directly_fuzzable=0,
    )
    return HuntFuzzResult(
        hunt_result=sample_hunt_result,
        bridge_result=bridge,
        fuzz_result=None,
        correlation=None,
    )


class TestJsonFormatterHunt:
    def test_format_hunt_valid_json(self, sample_hunt_result):
        fmt = JsonFormatter()
        output = fmt.format_hunt(sample_hunt_result)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_format_hunt_structure(self, sample_hunt_result):
        fmt = JsonFormatter()
        output = fmt.format_hunt(sample_hunt_result)
        parsed = json.loads(output)
        assert "findings" in parsed
        assert "stats" in parsed
        assert "total_count" in parsed
        assert "has_more" in parsed

    def test_format_hunt_no_target_path(self, sample_hunt_result):
        fmt = JsonFormatter()
        output = fmt.format_hunt(sample_hunt_result)
        parsed = json.loads(output)
        assert "target_path" not in parsed

    def test_format_hunt_structurally_equivalent(self, sample_hunt_result):
        """Verify JSON output matches the structure of current --json-output."""
        fmt = JsonFormatter()
        output = fmt.format_hunt(sample_hunt_result)
        parsed = json.loads(output)

        # Must have exactly these top-level keys
        assert set(parsed.keys()) == {"findings", "stats", "total_count", "has_more"}
        assert isinstance(parsed["findings"], list)
        assert isinstance(parsed["stats"], dict)
        assert isinstance(parsed["total_count"], int)
        assert isinstance(parsed["has_more"], bool)

    def test_json_format_hunt_with_suppressions(self, sample_finding, sample_stats):
        """JSON includes suppressions key when suppression_summary is present."""
        from deep_code_security.shared.formatters.protocol import HuntResult, SuppressionSummary

        ss = SuppressionSummary(
            suppressed_count=2,
            total_rules=3,
            expired_rules=0,
            suppression_reasons={"f1": "Admin paths", "f2": "Generated code"},
            suppression_file="/project/.dcs-suppress.yaml",
        )
        result = HuntResult(
            findings=[sample_finding],
            stats=sample_stats,
            total_count=1,
            has_more=False,
            suppression_summary=ss,
        )
        fmt = JsonFormatter()
        output = fmt.format_hunt(result)
        parsed = json.loads(output)
        assert "suppressions" in parsed
        assert parsed["suppressions"]["suppressed_count"] == 2
        assert parsed["suppressions"]["total_rules"] == 3
        assert parsed["suppressions"]["expired_rules"] == 0
        assert "reasons" in parsed["suppressions"]
        assert parsed["suppressions"]["reasons"]["f1"] == "Admin paths"

    def test_json_format_hunt_no_suppressions(self, sample_hunt_result):
        """No suppressions key in JSON when suppression_summary is None."""
        fmt = JsonFormatter()
        output = fmt.format_hunt(sample_hunt_result)
        parsed = json.loads(output)
        assert "suppressions" not in parsed


class TestJsonFormatterFullScan:
    def test_format_full_scan_valid_json(self, sample_full_scan_result):
        fmt = JsonFormatter()
        output = fmt.format_full_scan(sample_full_scan_result)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_format_full_scan_structure(self, sample_full_scan_result):
        fmt = JsonFormatter()
        output = fmt.format_full_scan(sample_full_scan_result)
        parsed = json.loads(output)
        assert "findings" in parsed
        assert "verified" in parsed
        assert "guidance" in parsed
        assert "hunt_stats" in parsed
        assert "verify_stats" in parsed
        assert "remediate_stats" in parsed
        assert "total_count" in parsed
        assert "has_more" in parsed


class TestJsonFormatterHuntFuzz:
    def test_format_hunt_fuzz_valid_json(self, sample_hunt_fuzz_result):
        fmt = JsonFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_format_hunt_fuzz_schema_version(self, sample_hunt_fuzz_result):
        fmt = JsonFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result)
        parsed = json.loads(output)
        assert parsed["schema_version"] == 1

    def test_format_hunt_fuzz_top_level_keys(self, sample_hunt_fuzz_result):
        fmt = JsonFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result)
        parsed = json.loads(output)
        assert "hunt_result" in parsed
        assert "bridge_result" in parsed
        assert "fuzz_result" in parsed
        assert "correlation" in parsed
        assert "analysis_mode" in parsed

    def test_format_hunt_fuzz_bridge_result_structure(self, sample_hunt_fuzz_result):
        fmt = JsonFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result)
        parsed = json.loads(output)
        bridge = parsed["bridge_result"]
        assert "total_findings" in bridge
        assert "fuzz_targets" in bridge
        assert isinstance(bridge["fuzz_targets"], list)
        assert len(bridge["fuzz_targets"]) == 1
        target = bridge["fuzz_targets"][0]
        assert target["function_name"] == "process_cmd"
        assert "sast_context" in target

    def test_format_hunt_fuzz_no_fuzz_result(self, sample_hunt_fuzz_result):
        fmt = JsonFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result)
        parsed = json.loads(output)
        assert parsed["fuzz_result"] is None
        assert parsed["correlation"] is None

    def test_format_hunt_fuzz_with_correlation(self, sample_hunt_result):
        from deep_code_security.bridge.models import (
            BridgeResult,
            CorrelationEntry,
            CorrelationReport,
            FuzzTarget,
            SASTContext,
        )
        from deep_code_security.shared.formatters.protocol import HuntFuzzResult

        sast_ctx = SASTContext(severity="high", finding_count=1)
        target = FuzzTarget(
            file_path="/tmp/project/app.py",
            function_name="run_cmd",
            sast_context=sast_ctx,
            finding_ids=["f1"],
            parameter_count=1,
        )
        bridge = BridgeResult(fuzz_targets=[target], total_findings=1)
        entry = CorrelationEntry(
            finding_id="f1",
            vulnerability_class="CWE-78: OS Command Injection",
            severity="high",
            sink_function="os.system",
            target_function="run_cmd",
            crash_in_finding_scope=True,
            crash_count=2,
            crash_signatures=["ZeroDivisionError"],
        )
        correlation = CorrelationReport(
            entries=[entry],
            total_sast_findings=1,
            crash_in_scope_count=1,
            fuzz_targets_count=1,
            total_crashes=2,
        )
        result = HuntFuzzResult(
            hunt_result=sample_hunt_result,
            bridge_result=bridge,
            fuzz_result=None,
            correlation=correlation,
        )
        fmt = JsonFormatter()
        output = fmt.format_hunt_fuzz(result)
        parsed = json.loads(output)
        assert parsed["correlation"] is not None
        assert parsed["correlation"]["crash_in_scope_count"] == 1
        assert len(parsed["correlation"]["entries"]) == 1
        assert parsed["correlation"]["entries"][0]["crash_in_finding_scope"] is True
