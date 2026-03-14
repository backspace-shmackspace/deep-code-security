"""Tests for coverage delta tracking."""

from __future__ import annotations

from deep_code_security.fuzzer.coverage_tracking.delta import DeltaTracker


class TestDeltaTracker:
    def test_initial_update(self) -> None:
        dt = DeltaTracker()
        coverage = [
            {
                "files": {
                    "test.py": {
                        "executed_lines": [1, 2, 3],
                        "missing_lines": [4, 5],
                    }
                },
                "totals": {"covered_lines": 3, "num_statements": 5, "percent_covered": 60.0},
            }
        ]
        delta = dt.update(coverage)
        assert delta.has_new_coverage is True
        assert delta.total_new_lines == 3

    def test_no_new_coverage(self) -> None:
        dt = DeltaTracker()
        coverage = [
            {
                "files": {"test.py": {"executed_lines": [1, 2], "missing_lines": [3]}},
                "totals": {},
            }
        ]
        dt.update(coverage)
        delta = dt.update(coverage)  # Same coverage again
        assert delta.has_new_coverage is False
        assert delta.total_new_lines == 0

    def test_reset(self) -> None:
        dt = DeltaTracker()
        coverage = [
            {
                "files": {"test.py": {"executed_lines": [1], "missing_lines": []}},
                "totals": {},
            }
        ]
        dt.update(coverage)
        dt.reset()
        assert dt.get_total_coverage() == {}
