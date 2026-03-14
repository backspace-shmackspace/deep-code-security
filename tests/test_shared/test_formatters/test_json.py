"""Tests for JsonFormatter."""

from __future__ import annotations

import json

from deep_code_security.shared.formatters.json import JsonFormatter


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
