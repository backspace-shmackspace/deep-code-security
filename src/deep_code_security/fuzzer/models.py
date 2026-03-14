"""Pydantic v2 models for the fuzzer phase.

All models previously dataclasses in fuzzy-wuzzy are converted to
Pydantic BaseModel per CLAUDE.md rules. FuzzInput is NOT frozen.
FuzzReport.unique_crashes uses @property (not cached_property).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

__all__ = [
    "CoverageReport",
    "FuzzInput",
    "FuzzReport",
    "FuzzResult",
    "ReplayResultModel",
    "TargetInfo",
    "UniqueCrash",
]


class FuzzInput(BaseModel):
    """A single fuzz input to be executed against a target.

    Args and kwargs contain Python expression strings (e.g., "float('nan')",
    "b'\\x00\\xff'"), not raw Python objects. These are evaluated in a
    restricted namespace before execution.

    NOT frozen -- attribute reassignment is allowed.
    """

    target_function: str = Field(..., description="Qualified function name")
    args: tuple[str, ...] = Field(
        default_factory=tuple, description="Positional args as expression strings"
    )
    kwargs: dict[str, str] = Field(
        default_factory=dict, description="Keyword args as expression strings"
    )
    metadata: dict[str, str] = Field(
        default_factory=dict, description="AI rationale, generation context"
    )


class FuzzResult(BaseModel):
    """Result of executing a single fuzz input."""

    input: FuzzInput
    success: bool
    exception: str | None = None
    traceback: str | None = None
    duration_ms: float = 0.0
    coverage_data: dict = Field(default_factory=dict)
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


class CoverageReport(BaseModel):
    """Coverage information for AI feedback."""

    total_lines: int = 0
    covered_lines: int = 0
    coverage_percent: float = 0.0
    uncovered_regions: list[dict] = Field(default_factory=list)
    branch_coverage: dict = Field(default_factory=dict)
    new_lines_covered: list[dict] = Field(default_factory=list)


class TargetInfo(BaseModel):
    """Information about a fuzz target."""

    module_path: str = ""
    function_name: str = ""
    qualified_name: str = ""
    signature: str = ""
    parameters: list[dict] = Field(default_factory=list)
    docstring: str | None = None
    source_code: str = ""
    decorators: list[str] = Field(default_factory=list)
    complexity: int = 0
    is_static_method: bool = False
    has_side_effects: bool = False


class UniqueCrash(BaseModel):
    """A deduplicated crash group."""

    signature: str = ""
    exception_type: str = ""
    exception_message: str = ""
    location: str = ""
    representative: FuzzResult
    count: int = 1
    target_functions: list[str] = Field(default_factory=list)
    severity: str | None = None  # Post-merge extension point


class FuzzReport(BaseModel):
    """Complete report from a fuzzing run."""

    targets: list[TargetInfo] = Field(default_factory=list)
    all_results: list[FuzzResult] = Field(default_factory=list)
    crashes: list[FuzzResult] = Field(default_factory=list)
    total_iterations: int = 0
    api_usage: Any | None = None  # Serialized APIUsage (not Pydantic -- internal class)
    final_coverage: CoverageReport | None = None
    timestamp: float = 0.0
    config_summary: dict = Field(default_factory=dict)

    @property
    def unique_crashes(self) -> list[UniqueCrash]:
        """Compute deduplicated crashes.

        Uses a plain @property (not cached_property, which is incompatible
        with Pydantic BaseModel). Callers that need the result multiple times
        should store it locally. The FuzzReportResult DTO pre-computes this
        in the orchestrator to avoid redundant work in formatters.
        """
        from deep_code_security.fuzzer.reporting.dedup import deduplicate_crashes

        return deduplicate_crashes(self.crashes)

    @property
    def total_inputs(self) -> int:
        return len(self.all_results)

    @property
    def crash_count(self) -> int:
        return len(self.crashes)

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.all_results if r.success)

    @property
    def timeout_count(self) -> int:
        return sum(1 for r in self.all_results if r.timed_out)


class ReplayResultModel(BaseModel):
    """Outcome of replaying a single crash input."""

    original: FuzzResult
    replayed: FuzzResult
    status: str  # "fixed", "still_failing", "error"
    original_exception: str = ""
    replayed_exception: str | None = None
