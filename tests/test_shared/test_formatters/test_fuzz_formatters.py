"""Tests for format_fuzz() on all four formatters."""

from __future__ import annotations

import json

import pytest

from deep_code_security.shared.formatters import get_formatter, supports_fuzz
from deep_code_security.shared.formatters.protocol import (
    FuzzConfigSummary,
    FuzzCrashSummary,
    FuzzReportResult,
    FuzzTargetInfo,
    UniqueCrashSummary,
)


@pytest.fixture
def fuzz_data() -> FuzzReportResult:
    return FuzzReportResult(
        config_summary=FuzzConfigSummary(
            target_path="/tmp/test.py",
            plugin="python",
            model="claude-sonnet-4-6",
        ),
        targets=[
            FuzzTargetInfo(
                qualified_name="my_func",
                signature="my_func(x: int)",
                module_path="/tmp/test.py",
                complexity=3,
            )
        ],
        crashes=[
            FuzzCrashSummary(
                target_function="my_func",
                exception="ZeroDivisionError: division by zero",
                args=["0"],
            )
        ],
        unique_crashes=[
            UniqueCrashSummary(
                signature="ZeroDivisionError|test.py:10",
                exception_type="ZeroDivisionError",
                exception_message="division by zero",
                location='File "test.py", line 10',
                count=1,
                target_functions=["my_func"],
                representative=FuzzCrashSummary(
                    target_function="my_func",
                    exception="ZeroDivisionError: division by zero",
                    args=["0"],
                ),
            )
        ],
        total_inputs=10,
        crash_count=1,
        unique_crash_count=1,
        timeout_count=0,
        total_iterations=2,
        coverage_percent=50.0,
        api_cost_usd=0.01,
        timestamp=1700000000.0,
    )


class TestTextFuzzOutput:
    def test_format_fuzz(self, fuzz_data: FuzzReportResult) -> None:
        formatter = get_formatter("text")
        output = formatter.format_fuzz(fuzz_data)
        assert "FUZZING REPORT" in output
        assert "my_func" in output
        assert "ZeroDivisionError" in output
        assert "50.0%" in output


class TestJsonFuzzOutput:
    def test_format_fuzz(self, fuzz_data: FuzzReportResult) -> None:
        formatter = get_formatter("json")
        output = formatter.format_fuzz(fuzz_data)
        data = json.loads(output)
        assert data["schema_version"] == 2
        assert data["summary"]["crash_count"] == 1
        assert data["analysis_mode"] == "dynamic"

    def test_json_fuzz_schema(self, fuzz_data: FuzzReportResult) -> None:
        formatter = get_formatter("json")
        output = formatter.format_fuzz(fuzz_data)
        data = json.loads(output)
        assert "config" in data
        assert "targets" in data
        assert "crashes" in data
        assert "unique_crashes" in data


class TestSarifFuzzOutput:
    def test_format_fuzz(self, fuzz_data: FuzzReportResult) -> None:
        formatter = get_formatter("sarif")
        output = formatter.format_fuzz(fuzz_data, target_path="/tmp/test.py")
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["tool"]["driver"]["name"] == "deep-code-security"

    def test_sarif_fuzz_analysis_mode(self, fuzz_data: FuzzReportResult) -> None:
        formatter = get_formatter("sarif")
        output = formatter.format_fuzz(fuzz_data, target_path="/tmp/test.py")
        data = json.loads(output)
        if data["runs"][0]["results"]:
            result = data["runs"][0]["results"][0]
            assert result["properties"]["analysis_mode"] == "dynamic"

    def test_sarif_fuzz_fingerprint(self, fuzz_data: FuzzReportResult) -> None:
        formatter = get_formatter("sarif")
        output = formatter.format_fuzz(fuzz_data, target_path="/tmp/test.py")
        data = json.loads(output)
        if data["runs"][0]["results"]:
            result = data["runs"][0]["results"][0]
            assert "fuzzyWuzzyCrashSignature/v1" in result["fingerprints"]


class TestHtmlFuzzOutput:
    def test_format_fuzz(self, fuzz_data: FuzzReportResult) -> None:
        formatter = get_formatter("html")
        output = formatter.format_fuzz(fuzz_data)
        assert "Fuzz Results" in output
        assert "ZeroDivisionError" in output
        assert "my_func" in output


class TestSupportsFuzz:
    def test_all_builtins_support_fuzz(self) -> None:
        for name in ("text", "json", "sarif", "html"):
            formatter = get_formatter(name)
            assert supports_fuzz(formatter), f"{name} should support fuzz"

    def test_formatter_only_class(self) -> None:
        """A class with only format_hunt/format_full_scan should not support fuzz."""

        class SastOnly:
            def format_hunt(self, data, target_path=""):
                return ""

            def format_full_scan(self, data, target_path=""):
                return ""

        assert supports_fuzz(SastOnly()) is False
