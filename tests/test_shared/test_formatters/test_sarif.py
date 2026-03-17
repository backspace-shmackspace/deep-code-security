"""Tests for SarifFormatter."""

from __future__ import annotations

import json

import pytest

from deep_code_security.shared.formatters.protocol import HuntResult
from deep_code_security.shared.formatters.sarif import SarifFormatter


@pytest.fixture
def sample_hunt_fuzz_result(sample_hunt_result):
    """Minimal HuntFuzzResult for testing format_hunt_fuzz."""
    from deep_code_security.bridge.models import BridgeResult, FuzzTarget, SASTContext
    from deep_code_security.shared.formatters.protocol import HuntFuzzResult

    sast_ctx = SASTContext(
        cwe_ids=["CWE-78"],
        severity="high",
        finding_count=1,
    )
    target = FuzzTarget(
        file_path="/tmp/project/app.py",
        function_name="process_cmd",
        sast_context=sast_ctx,
        finding_ids=["test-finding-001"],
        parameter_count=1,
    )
    bridge = BridgeResult(
        fuzz_targets=[target],
        total_findings=1,
    )
    return HuntFuzzResult(
        hunt_result=sample_hunt_result,
        bridge_result=bridge,
        fuzz_result=None,
        correlation=None,
    )


class TestSarifSchema:
    def test_sarif_full_schema_validation(self, sample_hunt_result, sarif_schema):
        """Validate complete output against the official SARIF 2.1.0 JSON Schema."""
        import jsonschema

        fmt = SarifFormatter()
        output = fmt.format_hunt(sample_hunt_result, target_path="/tmp/project")
        parsed = json.loads(output)
        jsonschema.validate(parsed, sarif_schema)

    def test_sarif_schema_version(self, sample_hunt_result):
        fmt = SarifFormatter()
        output = fmt.format_hunt(sample_hunt_result, target_path="/tmp/project")
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert "$schema" in parsed


class TestSarifToolDriver:
    def test_sarif_tool_driver(self, sample_hunt_result):
        fmt = SarifFormatter()
        output = fmt.format_hunt(sample_hunt_result, target_path="/tmp/project")
        parsed = json.loads(output)
        driver = parsed["runs"][0]["tool"]["driver"]
        assert driver["name"] == "deep-code-security"
        assert "version" in driver

    def test_sarif_tool_driver_rules(self, sample_hunt_result):
        fmt = SarifFormatter()
        output = fmt.format_hunt(sample_hunt_result, target_path="/tmp/project")
        parsed = json.loads(output)
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1
        rule = rules[0]
        assert "id" in rule
        assert "shortDescription" in rule
        assert "defaultConfiguration" in rule
        assert rule["defaultConfiguration"]["level"] in ("error", "warning", "note")


class TestSarifResults:
    def test_sarif_result_count(self, sample_hunt_result):
        fmt = SarifFormatter()
        output = fmt.format_hunt(sample_hunt_result, target_path="/tmp/project")
        parsed = json.loads(output)
        results = parsed["runs"][0]["results"]
        assert len(results) == len(sample_hunt_result.findings)

    def test_sarif_severity_mapping_critical(self, sample_hunt_result):
        fmt = SarifFormatter()
        output = fmt.format_hunt(sample_hunt_result, target_path="/tmp/project")
        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_sarif_severity_mapping_medium(self, sample_finding_medium, sample_stats):
        hunt_result = HuntResult(
            findings=[sample_finding_medium],
            stats=sample_stats,
            total_count=1,
        )
        fmt = SarifFormatter()
        output = fmt.format_hunt(hunt_result, target_path="/tmp/project")
        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        assert result["level"] == "warning"

    def test_sarif_severity_mapping_low(self, sample_finding_low, sample_stats):
        hunt_result = HuntResult(
            findings=[sample_finding_low],
            stats=sample_stats,
            total_count=1,
        )
        fmt = SarifFormatter()
        output = fmt.format_hunt(hunt_result, target_path="/tmp/project")
        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        assert result["level"] == "note"

    def test_sarif_code_flows(self, sample_hunt_result):
        fmt = SarifFormatter()
        output = fmt.format_hunt(sample_hunt_result, target_path="/tmp/project")
        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        assert "codeFlows" in result
        thread_flow = result["codeFlows"][0]["threadFlows"][0]
        assert len(thread_flow["locations"]) == 2

    def test_sarif_relative_uris(self, sample_hunt_result):
        fmt = SarifFormatter()
        output = fmt.format_hunt(sample_hunt_result, target_path="/tmp/project")
        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("/")
        assert uri == "app.py"

    def test_sarif_cwe_taxa(self, sample_hunt_result):
        fmt = SarifFormatter()
        output = fmt.format_hunt(sample_hunt_result, target_path="/tmp/project")
        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        assert "taxa" in result
        assert result["taxa"][0]["id"] == "CWE-89"


class TestSarifFullScan:
    def test_sarif_valid_json(self, sample_full_scan_result):
        fmt = SarifFormatter()
        output = fmt.format_full_scan(sample_full_scan_result, target_path="/tmp/project")
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_sarif_full_scan_includes_confidence(self, sample_full_scan_result):
        fmt = SarifFormatter()
        output = fmt.format_full_scan(sample_full_scan_result, target_path="/tmp/project")
        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        assert "confidence_score" in result["properties"]
        assert result["properties"]["confidence_score"] == 75

    def test_sarif_full_scan_remediation_in_properties(self, sample_full_scan_result):
        fmt = SarifFormatter()
        output = fmt.format_full_scan(sample_full_scan_result, target_path="/tmp/project")
        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        assert "remediation_guidance" in result["properties"]
        guidance = result["properties"]["remediation_guidance"]
        assert "fix_pattern" in guidance
        assert "code_example" in guidance
        # Must NOT be in fixes[]
        assert "fixes" not in result

    def test_sarif_full_schema_validation_full_scan(
        self, sample_full_scan_result, sarif_schema
    ):
        import jsonschema

        fmt = SarifFormatter()
        output = fmt.format_full_scan(sample_full_scan_result, target_path="/tmp/project")
        parsed = json.loads(output)
        jsonschema.validate(parsed, sarif_schema)


class TestSarifEmpty:
    def test_sarif_empty_findings(self, sample_stats, sarif_schema):
        import jsonschema

        hunt_result = HuntResult(
            findings=[],
            stats=sample_stats,
            total_count=0,
        )
        fmt = SarifFormatter()
        output = fmt.format_hunt(hunt_result, target_path="/tmp/project")
        parsed = json.loads(output)
        assert parsed["runs"][0]["results"] == []
        jsonschema.validate(parsed, sarif_schema)

    def test_sarif_empty_findings_has_rules(self, sample_stats):
        hunt_result = HuntResult(
            findings=[],
            stats=sample_stats,
            total_count=0,
        )
        fmt = SarifFormatter()
        output = fmt.format_hunt(hunt_result, target_path="/tmp/project")
        parsed = json.loads(output)
        assert parsed["runs"][0]["tool"]["driver"]["rules"] == []


class TestSarifHuntFuzz:
    def test_format_hunt_fuzz_valid_json(self, sample_hunt_fuzz_result):
        fmt = SarifFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result, target_path="/tmp/project")
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_format_hunt_fuzz_sarif_version(self, sample_hunt_fuzz_result):
        fmt = SarifFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result, target_path="/tmp/project")
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert "$schema" in parsed

    def test_format_hunt_fuzz_two_runs(self, sample_hunt_fuzz_result):
        """format_hunt_fuzz produces exactly two runs: SAST + fuzz."""
        fmt = SarifFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result, target_path="/tmp/project")
        parsed = json.loads(output)
        assert len(parsed["runs"]) == 2

    def test_format_hunt_fuzz_sast_run_has_findings(self, sample_hunt_fuzz_result):
        fmt = SarifFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result, target_path="/tmp/project")
        parsed = json.loads(output)
        sast_run = parsed["runs"][0]
        assert len(sast_run["results"]) == 1
        assert sast_run["results"][0]["ruleId"] == "CWE-89"

    def test_format_hunt_fuzz_fuzz_run_empty_when_no_crashes(self, sample_hunt_fuzz_result):
        """When fuzz_result is None, the fuzz run has empty results."""
        fmt = SarifFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result, target_path="/tmp/project")
        parsed = json.loads(output)
        fuzz_run = parsed["runs"][1]
        assert fuzz_run["results"] == []

    def test_format_hunt_fuzz_with_crashes(self, sample_hunt_result):
        """When fuzz_result contains unique crashes, they appear in the fuzz run."""
        from deep_code_security.bridge.models import BridgeResult, FuzzTarget, SASTContext
        from deep_code_security.shared.formatters.protocol import (
            FuzzCrashSummary,
            FuzzReportResult,
            HuntFuzzResult,
            UniqueCrashSummary,
        )

        bridge = BridgeResult(total_findings=1)
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
            crash_count=1,
            unique_crash_count=1,
            total_iterations=1,
        )
        result = HuntFuzzResult(
            hunt_result=sample_hunt_result,
            bridge_result=bridge,
            fuzz_result=fuzz_result,
            correlation=None,
        )
        fmt = SarifFormatter()
        output = fmt.format_hunt_fuzz(result, target_path="/tmp/project")
        parsed = json.loads(output)
        fuzz_run = parsed["runs"][1]
        assert len(fuzz_run["results"]) == 1
        assert "ZeroDivisionError" in fuzz_run["results"][0]["ruleId"]

    def test_format_hunt_fuzz_sast_run_has_uri_base(self, sample_hunt_fuzz_result):
        """When target_path is given, SAST run has originalUriBaseIds."""
        fmt = SarifFormatter()
        output = fmt.format_hunt_fuzz(sample_hunt_fuzz_result, target_path="/tmp/project")
        parsed = json.loads(output)
        sast_run = parsed["runs"][0]
        assert "originalUriBaseIds" in sast_run
