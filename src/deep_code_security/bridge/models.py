"""Pydantic models for the SAST-to-Fuzz bridge."""

from __future__ import annotations

from pydantic import BaseModel, Field

__all__ = [
    "BridgeConfig",
    "BridgeResult",
    "CorrelationEntry",
    "CorrelationReport",
    "FuzzTarget",
    "SASTContext",
]


class SASTContext(BaseModel):
    """SAST context for a single function, passed to the AI prompt builder.

    Contains the vulnerability information discovered by the Hunter phase
    for use in generating more targeted fuzz inputs.
    """

    cwe_ids: list[str] = Field(default_factory=list, description="CWE IDs found in this function")
    vulnerability_classes: list[str] = Field(
        default_factory=list, description="e.g., 'CWE-78: OS Command Injection'"
    )
    sink_functions: list[str] = Field(
        default_factory=list, description="Dangerous functions called, e.g., 'os.system'"
    )
    source_categories: list[str] = Field(
        default_factory=list, description="Input source categories, e.g., 'web_input'"
    )
    severity: str = Field(default="medium", description="Highest severity among findings")
    finding_count: int = Field(default=0, ge=0)


class FuzzTarget(BaseModel):
    """A function identified as a fuzz target from SAST findings."""

    file_path: str = Field(..., description="Absolute path to the Python file")
    function_name: str = Field(..., description="Function name (or Class.method)")
    sast_context: SASTContext = Field(
        default_factory=SASTContext,
        description="Aggregated SAST context for this function",
    )
    finding_ids: list[str] = Field(
        default_factory=list,
        description="IDs of RawFindings that identified this target",
    )
    requires_instance: bool = Field(
        default=False,
        description=(
            "True if the function is an instance method (first param is `self`). "
            "The fuzzer MVP cannot auto-construct `self`, so these targets may "
            "require a manual harness. Included for visibility rather than silently dropped."
        ),
    )
    parameter_count: int = Field(
        default=0,
        ge=0,
        description="Number of fuzzable parameters (excluding self/cls)",
    )


class BridgeConfig(BaseModel):
    """Configuration for the bridge resolver."""

    max_targets: int = Field(
        default=10,
        ge=1,
        description=(
            "Maximum number of fuzz targets to pass to the fuzzer. "
            "When more targets are available, the top N by SAST severity are selected. "
            "Configurable via DCS_BRIDGE_MAX_TARGETS environment variable."
        ),
    )


class BridgeResult(BaseModel):
    """Result of the SAST-to-Fuzz bridge analysis."""

    fuzz_targets: list[FuzzTarget] = Field(default_factory=list)
    skipped_findings: int = Field(default=0, ge=0, description="Findings that could not be mapped")
    skipped_reasons: list[str] = Field(
        default_factory=list,
        description="Reasons findings were skipped (for diagnostics)",
    )
    total_findings: int = Field(default=0, ge=0)
    not_directly_fuzzable: int = Field(
        default=0,
        ge=0,
        description=(
            "Findings in functions with no fuzzable parameters (e.g., route handlers "
            "where taint source is a framework global like request.form). "
            "These are excluded because the fuzzer cannot inject data through "
            "function arguments for these functions."
        ),
    )


class CorrelationEntry(BaseModel):
    """Correlates a single SAST finding with fuzz results."""

    finding_id: str
    vulnerability_class: str
    severity: str
    sink_function: str
    target_function: str
    crash_in_finding_scope: bool = Field(
        default=False,
        description=(
            "True if any crash occurred in the same function as a SAST finding. "
            "Does NOT imply the SAST vulnerability was exploited -- the crash "
            "may be unrelated (e.g., TypeError, missing context). Inspect "
            "crash_signatures for relevance."
        ),
    )
    crash_count: int = Field(default=0, ge=0)
    crash_signatures: list[str] = Field(default_factory=list)


class CorrelationReport(BaseModel):
    """Report correlating SAST findings with fuzz results."""

    entries: list[CorrelationEntry] = Field(default_factory=list)
    total_sast_findings: int = 0
    crash_in_scope_count: int = Field(
        default=0,
        description="Number of findings with crash_in_finding_scope=True",
    )
    fuzz_targets_count: int = 0
    total_crashes: int = 0
