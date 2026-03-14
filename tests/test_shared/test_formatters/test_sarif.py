"""Tests for SarifFormatter."""

from __future__ import annotations

import json

from deep_code_security.shared.formatters.protocol import HuntResult
from deep_code_security.shared.formatters.sarif import SarifFormatter


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
