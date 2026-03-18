"""Formatter protocol and data transfer objects."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from deep_code_security.architect.models import RemediateStats, RemediationGuidance
from deep_code_security.auditor.models import VerifiedFinding, VerifyStats
from deep_code_security.bridge.models import BridgeResult, CorrelationReport
from deep_code_security.hunter.models import RawFinding, ScanStats

__all__ = [
    "Formatter",
    "FuzzConfigSummary",
    "FuzzCrashSummary",
    "FuzzFormatter",
    "FuzzReportResult",
    "FuzzTargetInfo",
    "FullScanResult",
    "HuntFuzzResult",
    "HuntResult",
    "HybridFormatter",
    "ReplayResultDTO",
    "ReplayResultEntry",
    "SuppressionSummary",
    "UniqueCrashSummary",
    "supports_hybrid",
]


class SuppressionSummary(BaseModel):
    """Summary of applied suppressions for formatter output."""

    suppressed_count: int = 0
    total_rules: int = 0
    expired_rules: int = 0
    suppression_reasons: dict[str, str] = Field(default_factory=dict)
    suppression_file: str = ""


class HuntResult(BaseModel):
    """Aggregated results from the hunt command."""

    findings: list[RawFinding] = Field(default_factory=list)
    stats: ScanStats
    total_count: int = 0
    has_more: bool = False
    suppression_summary: SuppressionSummary | None = None
    suppressed_finding_ids: list[str] = Field(default_factory=list)
    # Full suppressed finding objects — populated by CLI/MCP for SARIF output.
    # Defaults to empty; formatters that do not need them (text, json, html)
    # simply ignore this field.
    suppressed_findings: list[RawFinding] = Field(default_factory=list)


class FullScanResult(BaseModel):
    """Aggregated results from the full-scan command."""

    findings: list[RawFinding] = Field(default_factory=list)
    verified: list[VerifiedFinding] = Field(default_factory=list)
    guidance: list[RemediationGuidance] = Field(default_factory=list)
    hunt_stats: ScanStats
    verify_stats: VerifyStats | None = None
    remediate_stats: RemediateStats | None = None
    total_count: int = 0
    has_more: bool = False
    suppression_summary: SuppressionSummary | None = None
    suppressed_finding_ids: list[str] = Field(default_factory=list)
    # Full suppressed finding objects — populated by CLI/MCP for SARIF output.
    suppressed_findings: list[RawFinding] = Field(default_factory=list)


# ---------- Fuzz-related DTOs ----------


class FuzzConfigSummary(BaseModel):
    """Typed summary of fuzzer configuration for formatter consumption."""

    target_path: str = ""
    plugin: str = "python"
    model: str = "claude-sonnet-4-6"
    max_iterations: int = 10
    inputs_per_iteration: int = 10
    timeout_ms: int = 5000


class FuzzTargetInfo(BaseModel):
    """Summary of a fuzz target for formatter output."""

    qualified_name: str
    signature: str
    module_path: str = ""
    complexity: int = 0


class FuzzCrashSummary(BaseModel):
    """Summary of a raw crash for formatter output."""

    target_function: str
    exception: str | None = None
    args: list[str] = Field(default_factory=list)
    kwargs: dict[str, str] = Field(default_factory=dict)
    traceback: str | None = None
    timed_out: bool = False


class UniqueCrashSummary(BaseModel):
    """Summary of a deduplicated crash for formatter output."""

    signature: str
    exception_type: str
    exception_message: str = ""
    location: str = ""
    count: int = 1
    target_functions: list[str] = Field(default_factory=list)
    representative: FuzzCrashSummary
    severity: str | None = None  # Post-merge extension point


class FuzzReportResult(BaseModel):
    """Aggregated results from a fuzz run (formatter DTO)."""

    config_summary: FuzzConfigSummary = Field(default_factory=FuzzConfigSummary)
    targets: list[FuzzTargetInfo] = Field(default_factory=list)
    crashes: list[FuzzCrashSummary] = Field(default_factory=list)
    unique_crashes: list[UniqueCrashSummary] = Field(default_factory=list)
    total_inputs: int = 0
    crash_count: int = 0
    unique_crash_count: int = 0
    timeout_count: int = 0
    total_iterations: int = 0
    coverage_percent: float | None = None
    api_cost_usd: float | None = None
    timestamp: float = 0.0
    analysis_mode: str = "dynamic"


class ReplayResultEntry(BaseModel):
    """Single replay result for formatter output."""

    status: str  # "fixed", "still_failing", "error"
    target_function: str
    original_exception: str = ""
    replayed_exception: str | None = None
    args: list[str] = Field(default_factory=list)
    kwargs: dict[str, str] = Field(default_factory=dict)


class ReplayResultDTO(BaseModel):
    """Aggregated results from a replay run (formatter DTO)."""

    results: list[ReplayResultEntry] = Field(default_factory=list)
    fixed_count: int = 0
    still_failing_count: int = 0
    error_count: int = 0
    total_count: int = 0
    target_path: str = ""


# ---------- Protocols ----------


class HuntFuzzResult(BaseModel):
    """Results from the hunt-fuzz combined pipeline."""

    hunt_result: HuntResult
    bridge_result: BridgeResult
    fuzz_result: FuzzReportResult | None = None
    correlation: CorrelationReport | None = None
    analysis_mode: str = "hybrid"

    model_config = {"arbitrary_types_allowed": True}


class Formatter(Protocol):
    """Protocol for output formatters.

    Every formatter must implement both format_hunt (for the hunt command)
    and format_full_scan (for the full-scan command). Each returns a string
    ready to be written to stdout or a file.

    Note on memory: formatters return a single `str`. For v1, this is
    acceptable given DCS_MAX_RESULTS=100 (typical output is under 5 MB
    for SARIF, under 10 MB for HTML). Streaming output is deferred to a
    future version if real-world usage reveals memory pressure.
    """

    def format_hunt(self, data: HuntResult, target_path: str = "") -> str:
        """Format hunt phase results."""
        ...

    def format_full_scan(self, data: FullScanResult, target_path: str = "") -> str:
        """Format full-scan (all three phases) results."""
        ...


@runtime_checkable
class FuzzFormatter(Protocol):
    """Protocol for formatters that support fuzz/replay output.

    This is a separate protocol from Formatter. A class can implement both
    by having all four methods. The registry checks for FuzzFormatter
    support separately from Formatter support.
    """

    def format_fuzz(self, data: FuzzReportResult, target_path: str = "") -> str:
        """Format fuzz run results."""
        ...

    def format_replay(self, data: ReplayResultDTO, target_path: str = "") -> str:
        """Format replay results."""
        ...


@runtime_checkable
class HybridFormatter(Protocol):
    """Protocol for formatters that support the combined hunt-fuzz output.

    This is a separate protocol from FuzzFormatter to avoid breaking
    backward compatibility. Adding format_hunt_fuzz() to FuzzFormatter
    would cause existing formatters that implement only format_fuzz()
    and format_replay() to fail isinstance(formatter, FuzzFormatter)
    checks, breaking dcs fuzz --format html and dcs replay --format html.

    This follows the same separation principle used when FuzzFormatter
    was created as a separate protocol from Formatter in the
    merge-fuzzy-wuzzy plan.
    """

    def format_hunt_fuzz(self, data: HuntFuzzResult, target_path: str = "") -> str:
        """Format combined hunt-fuzz pipeline results."""
        ...


def supports_hybrid(formatter: object) -> bool:
    """Check if a formatter supports hunt-fuzz combined output.

    Args:
        formatter: A formatter instance.

    Returns:
        True if the formatter has a format_hunt_fuzz() method.
    """
    return isinstance(formatter, HybridFormatter)
