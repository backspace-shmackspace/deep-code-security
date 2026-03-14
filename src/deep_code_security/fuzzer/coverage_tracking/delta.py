"""Coverage delta computation between fuzzing iterations."""

from __future__ import annotations

import logging

from pydantic import BaseModel, Field

from deep_code_security.fuzzer.coverage_tracking.collector import aggregate_coverage

__all__ = ["CoverageDelta", "DeltaTracker"]

logger = logging.getLogger(__name__)


class CoverageDelta(BaseModel):
    """Coverage change between iterations."""

    new_lines: dict[str, list[int]] = Field(default_factory=dict)
    total_new_lines: int = 0
    # These use dict[str, list[int]] for Pydantic compatibility (sets not JSON-serializable)
    previous_covered: dict[str, list[int]] = Field(default_factory=dict)
    current_covered: dict[str, list[int]] = Field(default_factory=dict)

    @property
    def has_new_coverage(self) -> bool:
        return self.total_new_lines > 0


class DeltaTracker:
    """Tracks coverage deltas across fuzzing iterations."""

    def __init__(self) -> None:
        self._covered: dict[str, set[int]] = {}
        self._iteration_count = 0

    def update(self, coverage_data_list: list[dict]) -> CoverageDelta:
        previous = {k: set(v) for k, v in self._covered.items()}

        new_aggregate = aggregate_coverage(coverage_data_list)

        new_lines: dict[str, list[int]] = {}
        total_new = 0

        for filepath, lines in new_aggregate.items():
            existing = self._covered.get(filepath, set())
            newly_covered = lines - existing
            if newly_covered:
                new_lines[filepath] = sorted(newly_covered)
                total_new += len(newly_covered)
            if filepath not in self._covered:
                self._covered[filepath] = set()
            self._covered[filepath].update(lines)

        self._iteration_count += 1
        logger.debug(
            "Iteration %d: %d new lines covered across %d files",
            self._iteration_count,
            total_new,
            len(new_lines),
        )

        return CoverageDelta(
            new_lines=new_lines,
            total_new_lines=total_new,
            previous_covered={k: sorted(v) for k, v in previous.items()},
            current_covered={k: sorted(v) for k, v in self._covered.items()},
        )

    def get_total_coverage(self) -> dict[str, set[int]]:
        return {k: set(v) for k, v in self._covered.items()}

    def get_coverage_percent(self, total_lines: dict[str, int]) -> float:
        total = sum(total_lines.values())
        if total == 0:
            return 0.0
        covered = sum(len(self._covered.get(fp, set())) for fp in total_lines)
        return (covered / total) * 100.0

    def reset(self) -> None:
        self._covered = {}
        self._iteration_count = 0
