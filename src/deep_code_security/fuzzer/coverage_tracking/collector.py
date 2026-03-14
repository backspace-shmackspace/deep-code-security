"""Coverage.py integration for the fuzzer."""

from __future__ import annotations

import logging

__all__ = ["aggregate_coverage", "get_covered_lines", "parse_coverage_json"]

logger = logging.getLogger(__name__)


def parse_coverage_json(coverage_data: dict) -> dict:
    """Parse raw coverage.py JSON output into a structured format."""
    if not coverage_data or "error" in coverage_data:
        return {
            "files": {},
            "totals": {"covered_lines": 0, "num_statements": 0, "percent_covered": 0.0},
        }

    files = coverage_data.get("files", {})
    totals = coverage_data.get("totals", {})

    parsed_files = {}
    for filepath, file_data in files.items():
        executed_lines = set(file_data.get("executed_lines", []))
        missing_lines = set(file_data.get("missing_lines", []))
        all_lines = executed_lines | missing_lines

        parsed_files[filepath] = {
            "executed_lines": sorted(executed_lines),
            "missing_lines": sorted(missing_lines),
            "all_lines": sorted(all_lines),
            "executed_branches": file_data.get("executed_branches", []),
            "missing_branches": file_data.get("missing_branches", []),
        }

    return {
        "files": parsed_files,
        "totals": {
            "covered_lines": totals.get("covered_lines", 0),
            "num_statements": totals.get("num_statements", 0),
            "percent_covered": totals.get("percent_covered", 0.0),
        },
    }


def get_covered_lines(coverage_data: dict) -> dict[str, set[int]]:
    result: dict[str, set[int]] = {}
    for filepath, file_data in coverage_data.get("files", {}).items():
        result[filepath] = set(file_data.get("executed_lines", []))
    return result


def aggregate_coverage(coverage_results: list[dict]) -> dict[str, set[int]]:
    aggregated: dict[str, set[int]] = {}
    for raw_data in coverage_results:
        parsed = parse_coverage_json(raw_data)
        file_coverage = get_covered_lines(parsed)
        for filepath, lines in file_coverage.items():
            if filepath not in aggregated:
                aggregated[filepath] = set()
            aggregated[filepath].update(lines)
    return aggregated
