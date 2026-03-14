"""Tests for coverage collector."""

from __future__ import annotations

from deep_code_security.fuzzer.coverage_tracking.collector import (
    aggregate_coverage,
    parse_coverage_json,
)


class TestParseCoverageJson:
    def test_empty(self) -> None:
        result = parse_coverage_json({})
        assert result["totals"]["covered_lines"] == 0

    def test_error(self) -> None:
        result = parse_coverage_json({"error": "no data"})
        assert result["files"] == {}

    def test_valid(self) -> None:
        data = {
            "files": {
                "test.py": {
                    "executed_lines": [1, 2],
                    "missing_lines": [3],
                }
            },
            "totals": {"covered_lines": 2, "num_statements": 3, "percent_covered": 66.7},
        }
        result = parse_coverage_json(data)
        assert result["totals"]["covered_lines"] == 2
        assert len(result["files"]["test.py"]["executed_lines"]) == 2


class TestAggregateCoverage:
    def test_merge(self) -> None:
        data1 = {
            "files": {"a.py": {"executed_lines": [1, 2], "missing_lines": [3]}},
            "totals": {},
        }
        data2 = {
            "files": {"a.py": {"executed_lines": [2, 3], "missing_lines": [1]}},
            "totals": {},
        }
        result = aggregate_coverage([data1, data2])
        assert result["a.py"] == {1, 2, 3}
