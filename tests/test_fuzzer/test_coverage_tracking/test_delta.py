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

    def test_get_coverage_percent_zero_total(self) -> None:
        """get_coverage_percent returns 0.0 when total_lines is empty."""
        dt = DeltaTracker()
        assert dt.get_coverage_percent({}) == 0.0

    def test_get_coverage_percent_nonzero(self) -> None:
        """get_coverage_percent computes correctly for non-zero totals."""
        dt = DeltaTracker()
        coverage = [
            {
                "files": {"foo.py": {"executed_lines": [1, 2], "missing_lines": [3]}},
                "totals": {},
            }
        ]
        dt.update(coverage)
        pct = dt.get_coverage_percent({"foo.py": 4})
        assert pct == 50.0

    def test_get_total_coverage_returns_sets(self) -> None:
        """get_total_coverage returns dict of sets."""
        dt = DeltaTracker()
        coverage = [
            {
                "files": {"foo.py": {"executed_lines": [1, 2], "missing_lines": []}},
                "totals": {},
            }
        ]
        dt.update(coverage)
        total = dt.get_total_coverage()
        assert total == {"foo.py": {1, 2}}
