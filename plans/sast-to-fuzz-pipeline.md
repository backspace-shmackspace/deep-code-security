# Plan: SAST-to-Fuzz Pipeline

## Status: DRAFT

## Goals

1. **Build a bridge module** (`src/deep_code_security/bridge/`) that converts Hunter-phase `RawFinding[]` into fuzzer-compatible target specifications, enabling automated fuzz target selection based on SAST taint analysis results.
2. **Add a new CLI command** `dcs hunt-fuzz <path>` that runs the Hunter phase, identifies fuzzable functions from findings, and pipes them into the fuzzer in a single orchestrated workflow.
3. **Add a new MCP tool** `deep_scan_hunt_fuzz` that runs the Hunt-then-Fuzz pipeline with session management, returning a fuzz_run_id for polling.
4. **Enrich fuzzer AI prompts** with SAST context (CWE, taint path, source/sink info) so the AI generates inputs specifically targeting the discovered vulnerability patterns.
5. **Produce a unified report** that correlates SAST findings with fuzz results, showing which static findings had dynamic crash activity in the same function scope.

## Non-Goals

- **Go fuzzing targets.** The fuzzer's only production plugin is `python`. Go/C fuzz plugins are deferred. The bridge will only produce fuzz targets for Python SAST findings in v1.
- **Automatic patch generation.** Consistent with CLAUDE.md: the Architect phase produces guidance, not apply-ready patches. This plan does not change that.
- **Interprocedural taint tracking.** Still deferred to v1.1 per existing constraint.
- **Cross-language taint.** Python calling C via FFI is not analyzed.
- **Modifying the existing `dcs hunt` or `dcs fuzz` commands.** They remain unchanged. The new `dcs hunt-fuzz` is additive.
- **Modifying the existing `deep_scan_hunt` or `deep_scan_fuzz` MCP tools.** They remain unchanged.
- **Changing the fuzzer's execution backend selection.** CLI uses SubprocessBackend; MCP uses ContainerBackend. This plan follows the same pattern.
- **Adding new CWE-specific prompt strategies.** The plan enriches prompts with SAST context generically. CWE-specific prompt engineering (e.g., special SQL injection input patterns) is a follow-up optimization.
- **Framework harness generation for route handlers.** This pipeline does NOT generate framework harnesses for route handlers (Flask views, Django views, etc.) that receive tainted input via framework globals (e.g., `request.form`, `request.args`). The fuzzer can only inject data through function parameters, so functions whose taint source is a framework global are excluded from fuzzing targets. This pipeline targets utility, parsing, and validation functions where tainted data flows through function parameters.

## Value Proposition

The SAST Hunter identifies functions containing dangerous sinks fed by tainted input. Many of these findings involve framework globals (e.g., Flask `request.form`) as the taint source, and the fuzzer cannot exercise these because it calls functions with direct arguments. However, a meaningful subset of findings -- particularly in utility, parsing, data processing, and validation layers -- involve functions that accept tainted data as parameters. These are the functions the bridge targets. For these functions, the pipeline provides:

1. **Automated target selection**: The fuzzer is pointed at exactly the functions the SAST identified as containing dangerous sinks, rather than requiring manual target selection.
2. **SAST-guided input generation**: The AI receives CWE and sink information to generate more targeted fuzz inputs for the first iteration.
3. **Correlation reporting**: Users see which SAST findings had dynamic crash activity in the same function scope, with clear labeling that a crash does not necessarily confirm the specific SAST vulnerability.

The pipeline will not produce fuzz targets for the majority of findings in web-framework-heavy codebases (where most vulnerabilities are in route handlers receiving input via framework globals). This is an inherent limitation of fuzzing at the function-call level without framework harness generation, and is honestly documented.

## Assumptions

1. A `RawFinding` contains `source.file`, `source.function` (the source API/attribute, e.g., `request.form`, NOT the enclosing function name), `source.line`, `sink.file`, `sink.function` (the dangerous API call, e.g., `os.system`), `sink.line` (used to resolve the containing Python function via AST), `sink.cwe`, `taint_path`, `vulnerability_class`, and `language`. The enclosing function is derived from `sink.line` via AST parsing.
2. The fuzzer operates at the Python function level. A finding is "fuzzable" if and only if: (a) the language is Python, (b) the sink file is a `.py` file, (c) the containing function can be discovered by the fuzzer's `signature_extractor`, and (d) the containing function has at least one non-`self`/`cls` parameter (i.e., the fuzzer can inject data through function arguments).
3. A single Python file may contain multiple SAST findings across different functions. The bridge groups findings by file, then resolves each finding to the containing function.
4. The fuzzer already accepts `--function` to scope fuzzing to specific functions (via `FuzzerConfig.target_functions`). The bridge produces a list of function names derived from findings.
5. The Anthropic SDK is an optional dependency. The `hunt-fuzz` CLI command will fail with a clear error if the `[fuzz]` extras are not installed.
6. The SAST-to-fuzz pipeline is purely additive. No existing behavior changes.

## Proposed Design

### Architecture Overview

```
RawFinding[]  --+
                |
         +--------------------+
         |    Bridge Module    |  src/deep_code_security/bridge/
         |                    |
         |  1. Filter         |  Python-only, sink has function context
         |  2. Resolve        |  Map sink location to function name
         |                    |  (via signature_extractor.py)
         |  3. Fuzzability    |  Check function has fuzzable parameters
         |     check          |  (exclude zero-param and framework-global-only)
         |  4. Enrich         |  Build SAST context for AI prompts
         |  5. Deduplicate    |  One fuzz target per unique function
         |  6. Cap            |  Limit to max_targets by severity
         |                    |
         +--------------------+
                |
    +-----------+-----------+
    |                       |
    v                       v
FuzzerConfig             SASTContext
(target_functions)       (per-function SAST metadata
                          injected into AI prompts)
    |                       |
    +-----------+-----------+
                |
         +--------------------+
         |  FuzzOrchestrator  |  Existing fuzzer
         |  (enhanced)        |
         |                    |
         |  AI prompts now    |
         |  include SAST      |
         |  context on iter 1 |
         |  (seed + diversity)|
         +--------------------+
                |
                v
         FuzzReport + SASTCorrelation
```

### Component 1: Bridge Module (`src/deep_code_security/bridge/`)

The bridge module is responsible for converting SAST findings into fuzz targets.

#### Models (`bridge/models.py`)

```python
"""Pydantic models for the SAST-to-Fuzz bridge."""

from __future__ import annotations

from pydantic import BaseModel, Field

from deep_code_security.hunter.models import RawFinding

__all__ = [
    "FuzzTarget",
    "SASTContext",
    "BridgeResult",
    "BridgeConfig",
    "CorrelationEntry",
    "CorrelationReport",
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
```

#### Resolver (`bridge/resolver.py`)

The resolver maps a `RawFinding` to the Python function that contains the sink. It reuses the fuzzer's `FunctionSignatureExtractor` (`fuzzer/analyzer/signature_extractor.py`) to parse the file and find which function spans the sink's line number, ensuring function name resolution is consistent with the fuzzer's target discovery.

```python
"""Resolve SAST findings to fuzzable function targets."""

from __future__ import annotations

import logging
from pathlib import Path

from deep_code_security.bridge.models import (
    BridgeConfig,
    BridgeResult,
    FuzzTarget,
    SASTContext,
)
from deep_code_security.fuzzer.analyzer.signature_extractor import (
    extract_targets_from_file,
)
from deep_code_security.hunter.models import RawFinding

__all__ = ["resolve_findings_to_targets"]

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def resolve_findings_to_targets(
    findings: list[RawFinding],
    config: BridgeConfig | None = None,
) -> BridgeResult:
    """Convert SAST findings into fuzz targets.

    Groups findings by file, uses signature_extractor to identify function
    boundaries, maps each sink to its containing function, checks for
    fuzzable parameters, then aggregates SAST context per function.

    Args:
        findings: RawFinding list from the Hunter phase.
        config: Optional bridge configuration (max_targets, etc.).

    Returns:
        BridgeResult with fuzz targets and skip diagnostics.
    """
    ...
```

**Resolution algorithm:**

1. **Filter**: Only `language == "python"` findings. Non-Python findings are skipped with reason `"unsupported language: {lang}"`.
2. **Group**: Group findings by `sink.file`.
3. **Parse**: For each unique file, call `extract_targets_from_file(path, allow_side_effects=True, include_instance_methods=True)` from `signature_extractor.py` to get all function targets with their line ranges, parameter info, and qualified names. This reuses the same function that the `FuzzOrchestrator` uses to discover targets, ensuring that function names produced by the bridge exactly match those the fuzzer will filter against. The `allow_side_effects=True` flag is used because SAST-identified functions may have side effects by nature (they call dangerous sinks). The `include_instance_methods=True` flag is used because SAST findings frequently occur in instance methods and classmethods; the bridge needs these in the target set even though the fuzzer's default discovery path skips them (see step 6 and the `extract_targets_from_source()` modification in Task 1.3).
4. **Map**: For each finding's `sink.line`, find the function whose `lineno..end_lineno` range contains it by matching against the `TargetInfo.lineno` and `TargetInfo.end_lineno` fields on the objects returned by the extractor. These fields are populated from `func_node.lineno` and `func_node.end_lineno` in `_make_target_info()` (see `TargetInfo` modification in Task 1.3). If no function contains the sink line (e.g., module-level code), skip with reason `"sink at line {n} is not inside a function"`. Both `ast.FunctionDef` and `ast.AsyncFunctionDef` are handled by the extractor.
5. **Fuzzability check**: For each resolved function, check its parameter list (from `TargetInfo.parameters`). If the function has zero fuzzable parameters (after excluding `self`/`cls`), skip with reason `"function {name} has no fuzzable parameters (taint source is likely a framework global, not a function argument)"` and increment the `not_directly_fuzzable` counter. This is the core filter that addresses the impedance mismatch between SAST findings (which often identify framework route handlers) and fuzzer capabilities (which require function parameters).
6. **Instance method handling**: If the containing function is an instance method or classmethod, the `TargetInfo` returned by the extractor (when called with `include_instance_methods=True`) will have `is_instance_method=True` (see `TargetInfo` modification in Task 1.3). The bridge sets `requires_instance=True` on the `FuzzTarget` for these targets. The correlation report will note "may require manual harness" for these targets. This avoids silently dropping findings in class-based views, which represent a significant fraction of real-world SAST findings. Note: the extractor's default behavior (`include_instance_methods=False`) continues to skip instance methods and classmethods for the fuzzer's normal discovery path; only the bridge passes `include_instance_methods=True`.
7. **Aggregate**: Group targets by `(file_path, function_name)`. Merge SAST contexts: collect all CWE IDs, vulnerability classes, sink functions, source categories. Use the highest severity.
8. **Cap**: If more targets exist than `config.max_targets` (default: 10), sort by SAST severity descending (critical > high > medium > low), then by `finding_count` descending, and take the top N. Log a warning: `"Capped fuzz targets from {total} to {max_targets}; increase DCS_BRIDGE_MAX_TARGETS to include more."`.
9. **Return**: `BridgeResult` with deduplicated, capped `FuzzTarget` list.

**Why reuse `signature_extractor` directly?** The bridge's function boundary detection must agree with the fuzzer's target discovery. The bridge maps `sink.line` to a function name, and that function name is then passed as `target_functions` to `FuzzerConfig`, which the `FuzzOrchestrator` uses to filter `plugin.discover_targets()` results. If the bridge produced different function names (due to nested function handling, async function handling, decorator handling, or qualified name construction), the filter would silently match nothing and fall back to fuzzing all discovered targets. Importing `signature_extractor` directly eliminates this divergence risk. The cost is a dependency on `fuzzer.analyzer.signature_extractor` (and transitively on `fuzzer.analyzer.source_reader` and `fuzzer.models`), but these are stable internal modules and the bridge already depends on `fuzzer.config` and `fuzzer.models`.

#### Orchestrator (`bridge/orchestrator.py`)

```python
"""Orchestrates the SAST-to-Fuzz pipeline."""

from __future__ import annotations

import logging
from pathlib import Path

from deep_code_security.bridge.models import (
    BridgeConfig,
    BridgeResult,
    CorrelationEntry,
    CorrelationReport,
    FuzzTarget,
)
from deep_code_security.bridge.resolver import resolve_findings_to_targets
from deep_code_security.fuzzer.config import FuzzerConfig
from deep_code_security.fuzzer.models import FuzzReport
from deep_code_security.hunter.models import RawFinding

__all__ = ["BridgeOrchestrator"]

logger = logging.getLogger(__name__)


class BridgeOrchestrator:
    """Orchestrates the Hunt -> Resolve -> Fuzz -> Correlate pipeline."""

    def run_bridge(
        self,
        findings: list[RawFinding],
        config: BridgeConfig | None = None,
    ) -> BridgeResult:
        """Convert SAST findings to fuzz targets."""
        ...

    def correlate(
        self,
        bridge_result: BridgeResult,
        fuzz_report: FuzzReport,
    ) -> CorrelationReport:
        """Correlate SAST findings with fuzz results.

        For each fuzz target derived from SAST findings, check if the
        fuzzer found crashes in the same function. A crash in a function
        that has a SAST finding indicates dynamic crash activity in the
        same scope, but does NOT confirm that the specific SAST
        vulnerability was exploited.
        """
        ...
```

**Correlation algorithm:**

1. For each `FuzzTarget` in the `BridgeResult`, check if any crash in `FuzzReport.crashes` has `input.target_function == target.function_name`.
2. If yes, mark the corresponding SAST findings with `crash_in_finding_scope=True`.
3. Collect crash signatures (from `FuzzReport.unique_crashes`) for the function.
4. Build a `CorrelationReport` summarizing how many SAST findings had dynamic crash activity in the same function scope.

### Component 2: SAST-Enriched AI Prompts

The fuzzer's AI prompt builder (`fuzzer/ai/prompts.py`) is extended with an optional `sast_context` parameter. When SAST context is available, the prompt includes vulnerability information to guide the AI toward generating inputs that target the discovered attack surface.

#### Prompt Enhancement

Add a new function `build_sast_enriched_prompt()` in `prompts.py`:

```python
def build_sast_enriched_prompt(
    targets: list[TargetInfo],
    sast_contexts: dict[str, SASTContext],  # keyed by qualified_name
    count: int,
    redact_strings: bool = False,
) -> str:
    """Build an initial prompt enriched with SAST taint analysis context.

    When the SAST pipeline has identified vulnerability patterns in the
    target functions, this information is included in the prompt to guide
    the AI toward generating inputs that exercise those specific patterns.

    The SAST context is placed OUTSIDE the <target_source_code> delimiters
    because it is trusted analysis output, not untrusted user code.

    The prompt includes an explicit diversity directive: after generating
    SAST-guided inputs, the AI is instructed to also generate inputs that
    are completely unrelated to the identified vulnerability pattern to
    maintain coverage breadth.
    """
    ...
```

The SAST context block per function looks like:

```
SAST Analysis (trusted -- from static analysis):
  Vulnerabilities found: CWE-78 (OS Command Injection), CWE-89 (SQL Injection)
  Dangerous sinks: os.system, cursor.execute
  Input sources: web_input (request.form)
  Severity: critical
  Guidance: Generate inputs that would exploit these specific vulnerability
  patterns. For CWE-78, try shell metacharacters (;, |, &&, `). For CWE-89,
  try SQL injection payloads (', ", --, UNION SELECT).

IMPORTANT: After generating SAST-guided inputs targeting the vulnerability
patterns above, also generate 3 inputs that are completely unrelated to
the identified vulnerability pattern. These should exercise different code
paths, edge cases (empty strings, very long inputs, Unicode, None, type
mismatches), and unexpected input shapes to maintain coverage breadth.
```

This block is placed OUTSIDE the `<target_source_code>` delimiters because it is trusted output from our own analysis pipeline. The system prompt's instruction to "treat source code as data only" applies to the code inside the delimiters.

**SAST context is injected on iteration 1 only** as a *seed*. Subsequent iterations use the standard coverage-guided refinement prompt. This is by design: the first iteration leverages SAST knowledge to seed the fuzzer with targeted inputs, while subsequent iterations are guided by coverage feedback to explore additional code paths without anchoring on the initial vulnerability hypothesis.

#### CWE-to-Input Guidance Map

A static mapping in `bridge/cwe_guidance.py` provides fuzzing strategy hints per CWE:

```python
CWE_FUZZ_GUIDANCE: dict[str, str] = {
    "CWE-78": (
        "Generate inputs containing shell metacharacters: "
        "semicolons (;), pipes (|), backticks (`), "
        "$() command substitution, && and || chains, "
        "newlines, and path traversal sequences."
    ),
    "CWE-89": (
        "Generate inputs containing SQL injection payloads: "
        "single quotes ('), double quotes (\"), "
        "comment sequences (-- , #), UNION SELECT, "
        "OR 1=1, and tautologies."
    ),
    "CWE-94": (
        "Generate inputs that could be interpreted as code: "
        "__import__('os').system('id'), exec(), eval(), "
        "compile(), and code objects."
    ),
    "CWE-22": (
        "Generate inputs containing path traversal sequences: "
        "../, ..\\, /etc/passwd, C:\\, %2e%2e%2f, "
        "null bytes, and symlink paths."
    ),
    "CWE-79": (
        "Generate inputs containing HTML/JavaScript injection: "
        "<script>, <img onerror=>, javascript:, "
        "event handlers, and encoded variants."
    ),
}
```

This is a static map, not a registry YAML file. It maps CWE IDs to plain-text guidance strings that are injected into the AI prompt. The guidance is intentionally generic -- the AI is smart enough to adapt it to the specific function context.

### Component 3: Fuzzer Integration

The `FuzzOrchestrator` gains an optional `sast_contexts` parameter. When provided, it passes the contexts through to the `AIEngine`, which uses them in `build_sast_enriched_prompt()` instead of `build_initial_prompt()` for the first iteration only.

#### FuzzerConfig Extension

Add an optional field to `FuzzerConfig`:

```python
# In FuzzerConfig
sast_contexts: dict[str, SASTContext] | None = Field(
    default=None,
    exclude=True,
    description=(
        "SAST context per function (keyed by qualified name). "
        "Bridge internal -- not CLI-configurable. "
        "Injected programmatically by the BridgeOrchestrator."
    ),
)
```

This field is `exclude=True` because it is not a CLI-configurable setting. It is injected programmatically by the `BridgeOrchestrator`. The type is `dict[str, SASTContext] | None` -- using the `SASTContext` Pydantic model directly (imported from `bridge.models`). This avoids a serialization/deserialization step and keeps the type consistent with the `AIEngine` method signatures.

#### FuzzOrchestrator Enhancement

```python
# In FuzzOrchestrator.run():
if iteration == 1 and self._sast_contexts:
    inputs = ai_engine.generate_sast_guided_inputs(
        targets=targets,
        sast_contexts=self._sast_contexts,
        count=config.inputs_per_iteration,
    )
else:
    inputs = ai_engine.generate_initial_inputs(...)
```

The `_sast_contexts` attribute is set by the `BridgeOrchestrator` before calling `run()`. Subsequent iterations use the standard refinement prompt (coverage-guided), not the SAST prompt. This is by design: the first iteration leverages SAST knowledge to "seed" the fuzzer, and subsequent iterations are coverage-guided to find additional bugs. The diversity directive in the SAST-enriched prompt ensures that even iteration 1 generates a mix of SAST-targeted and broadly exploratory inputs.

#### AIEngine Extension

Add one method to `AIEngine`:

```python
def generate_sast_guided_inputs(
    self,
    targets: list[TargetInfo],
    sast_contexts: dict[str, SASTContext],
    count: int = 10,
) -> list[FuzzInput]:
    """Generate initial inputs guided by SAST analysis context.

    Uses build_sast_enriched_prompt() instead of build_initial_prompt().
    """
    self._check_cost_budget()
    valid_targets = {t.qualified_name for t in targets}
    prompt = build_sast_enriched_prompt(
        targets, sast_contexts, count, redact_strings=self.redact_strings
    )
    return self._call_with_retry(prompt, valid_targets)
```

### Component 4: CLI Integration

#### New Command: `dcs hunt-fuzz`

```python
@cli.command("hunt-fuzz")
@click.argument("path")
@click.option("--language", "-l", multiple=True, ...)
@click.option("--severity", default="medium", ...)
@click.option("--max-findings", default=100, ...)
@click.option("--max-fuzz-targets", default=10, type=int, help="Max fuzz targets (default: 10, env: DCS_BRIDGE_MAX_TARGETS)")
@click.option("--iterations", "-n", default=5, ...)
@click.option("--inputs-per-iter", default=10, ...)
@click.option("--timeout", default=5000, metavar="MS", ...)
@click.option("--model", default="claude-sonnet-4-6", ...)
@click.option("--output-dir", default="./fuzzy-output", ...)
@click.option("--format", "-f", "output_format", ...)
@click.option("--output-file", "-o", ...)
@click.option("--force", is_flag=True, ...)
@click.option("--max-cost", default=5.00, ...)
@click.option("--consent", "consent_flag", is_flag=True, ...)
@click.option("--dry-run", is_flag=True, ...)
@click.option("--verbose", is_flag=True, ...)
def hunt_fuzz(path, ...):
    """Run SAST analysis then fuzz the identified vulnerable functions."""
```

Workflow:
1. Run Hunter scan on `path`.
2. Run bridge resolver on findings with `BridgeConfig(max_targets=max_fuzz_targets)`.
3. If no fuzz targets found, report bridge diagnostics (including `not_directly_fuzzable` count) and exit.
4. Report bridge results to stderr (N findings -> M fuzz targets, K skipped, J not directly fuzzable).
5. If any targets have `requires_instance=True`, log a warning: `"N targets are instance methods and may require a manual harness for full coverage."`.
6. Run fuzzer with `target_functions` and `sast_contexts` from bridge.
7. Run correlation.
8. Format and output the `HuntFuzzResult` DTO.

#### New Formatter DTO

```python
class HuntFuzzResult(BaseModel):
    """Results from the hunt-fuzz combined pipeline."""

    hunt_result: HuntResult
    bridge_result: BridgeResult  # from bridge.models
    fuzz_result: FuzzReportResult | None = None
    correlation: CorrelationReport | None = None
    analysis_mode: str = "hybrid"  # distinguishes from pure "static" or "dynamic"
```

#### Formatter Extension

Create a new `HybridFormatter` protocol separate from `FuzzFormatter`:

```python
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

    def format_hunt_fuzz(self, data: HuntFuzzResult, target_path: str = "") -> str: ...
```

Add a `supports_hybrid()` helper:

```python
def supports_hybrid(formatter: object) -> bool:
    """Check if a formatter supports hunt-fuzz combined output."""
    return isinstance(formatter, HybridFormatter)
```

The existing `FuzzFormatter` protocol is NOT modified. The text, JSON, and SARIF formatters will implement both `FuzzFormatter` and `HybridFormatter`. The HTML formatter, which currently implements only `FuzzFormatter`, is unaffected. HTML implementation of `format_hunt_fuzz()` is deferred.

### Component 5: MCP Integration

#### New Tool: `deep_scan_hunt_fuzz`

Registered conditionally: requires both the Anthropic SDK and `ContainerBackend.is_available()`.

```python
self.register_tool(
    name="deep_scan_hunt_fuzz",
    description=(
        "Run SAST analysis followed by AI-powered fuzzing of the vulnerable "
        "functions identified. Requires consent=true. Returns a fuzz_run_id."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Target codebase path"},
            "languages": {"type": "array", "items": {"type": "string"}},
            "severity_threshold": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low"],
            },
            "consent": {"type": "boolean"},
            "max_iterations": {"type": "integer", "default": 5},
            "max_findings": {"type": "integer", "default": 100},
            "max_fuzz_targets": {"type": "integer", "default": 10},
        },
        "required": ["path", "consent"],
    },
    handler=self._handle_hunt_fuzz,
)
```

The handler:
1. Validates path and consent.
2. Runs Hunter synchronously (fast).
3. Runs bridge resolver synchronously (fast).
4. If no fuzz targets, returns the hunt results + bridge diagnostics immediately.
5. Launches fuzz in a background thread (same pattern as `_handle_fuzz`).
6. Stores bridge result and finding IDs in the `FuzzRunState` for correlation when polling completes.
7. Returns `fuzz_run_id` for polling via `deep_scan_fuzz_status`.

When `deep_scan_fuzz_status` retrieves a completed hunt-fuzz run, the result includes the correlation report in addition to the standard fuzz report summary.

**MCP correlation response validation:** All crash-derived data in the correlation report (`crash_signatures`, `crash_count`, error strings) originates from untrusted target code execution. Before inclusion in any MCP response, `CorrelationEntry.crash_signatures` must be sanitized through `validate_crash_data()` from `mcp/input_validator.py`. Specifically:
- Each crash signature string is validated/truncated by `validate_crash_data()`.
- The handler calls `validate_crash_data(exception=sig, traceback_str=None, target_function=entry.target_function)` for each crash signature before storing it in `FuzzRunState`.
- This is consistent with the existing `deep_scan_fuzz` handler, which deliberately avoids returning raw crash data through the MCP response without validation.

## Interfaces / Schema Changes

### New Public API

| Module | Symbol | Type | Description |
|---|---|---|---|
| `bridge.models` | `FuzzTarget` | Pydantic model | A function identified as a fuzz target from SAST |
| `bridge.models` | `SASTContext` | Pydantic model | SAST vulnerability context for a function |
| `bridge.models` | `BridgeConfig` | Pydantic model | Bridge configuration (max_targets) |
| `bridge.models` | `BridgeResult` | Pydantic model | Bridge analysis result |
| `bridge.models` | `CorrelationEntry` | Pydantic model | Single SAST-fuzz correlation |
| `bridge.models` | `CorrelationReport` | Pydantic model | Full correlation report |
| `bridge.resolver` | `resolve_findings_to_targets()` | function | Convert findings to fuzz targets |
| `bridge.cwe_guidance` | `CWE_FUZZ_GUIDANCE` | dict | CWE-to-fuzzing-guidance map |
| `bridge.cwe_guidance` | `get_guidance_for_cwes()` | function | Look up guidance for CWE list |
| `bridge.orchestrator` | `BridgeOrchestrator` | class | Pipeline orchestrator |
| `shared.formatters.protocol` | `HuntFuzzResult` | Pydantic model | Combined pipeline DTO |
| `shared.formatters.protocol` | `HybridFormatter` | Protocol | Formatter protocol for hunt-fuzz output |
| `shared.formatters.protocol` | `supports_hybrid()` | function | Check if formatter supports hunt-fuzz |
| `fuzzer.ai.prompts` | `build_sast_enriched_prompt()` | function | SAST-enriched prompt builder |
| `fuzzer.ai.engine` | `AIEngine.generate_sast_guided_inputs()` | method | SAST-guided input generation |

### CLI Changes

| Command | Type | Description |
|---|---|---|
| `dcs hunt-fuzz <path>` | New | Run Hunt + Bridge + Fuzz + Correlate pipeline |

### MCP Tool Changes

| Tool | Type | Description |
|---|---|---|
| `deep_scan_hunt_fuzz` | New (conditional) | Hunt + Fuzz pipeline via MCP |

### Formatter Protocol Changes

| Protocol | Method | Type | Description |
|---|---|---|---|
| `HybridFormatter` (new) | `format_hunt_fuzz()` | New protocol + method | Format combined pipeline results |

Note: `FuzzFormatter` is NOT modified. The new `HybridFormatter` protocol is separate. Existing `FuzzFormatter` implementations are unaffected.

## Data Migration

None. No persistent state is affected. The bridge is stateless; correlation is computed at report time.

## Rollout Plan

This is a single-release feature addition.

1. **Implement** bridge module, CLI command, and MCP tool in a single branch.
2. **Test** with `make test` (unit + coverage).
3. **Manual validation**: run `dcs hunt-fuzz tests/fixtures/vulnerable_samples/python/` to verify end-to-end on the existing vulnerable samples.
4. **Release** as part of the next version bump.

### Backward Compatibility

- All existing commands (`hunt`, `fuzz`, `full-scan`) are unchanged.
- All existing MCP tools are unchanged.
- The `FuzzFormatter` protocol is NOT modified. A new `HybridFormatter` protocol is introduced for the `format_hunt_fuzz()` method. Existing custom formatters that do not implement `HybridFormatter` will not be usable with the `hunt-fuzz` command but will continue to work with all existing commands. The HTML formatter is unaffected and continues to satisfy `FuzzFormatter`.
- `FuzzerConfig` gains a new optional field with `exclude=True`, which does not affect serialization.
- The AI prompt changes are additive (new function, existing function unchanged).

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Most SAST findings target framework route handlers with no fuzzable parameters, producing zero fuzz targets for web-framework-heavy codebases | High | Medium | Honestly documented in Non-Goals and Value Proposition. The `not_directly_fuzzable` counter in `BridgeResult` makes this visible to users. The pipeline is still valuable for utility/parsing/validation functions. |
| Instance method targets (`requires_instance=True`) crash on invocation because `self` cannot be auto-constructed | Medium | Low | Included for visibility with clear annotation. The correlation report notes "may require manual harness." Users can inspect these targets and decide whether to create a manual harness. |
| Function boundary resolution fails for complex Python (decorators, nested functions) | Medium | Low | Uses `signature_extractor.py` directly, which already handles decorators, nested functions, async functions, and class context. Same code path as the fuzzer itself. |
| SAST-enriched prompts anchor AI on CWE-specific inputs, reducing diversity | Medium | Low | The prompt includes an explicit diversity directive: "also generate 3 inputs that are completely unrelated to the identified vulnerability pattern." SAST context is injected on iteration 1 only; subsequent iterations are coverage-guided. |
| Correlation produces false associations (crash in function != confirming the SAST finding) | Low | Medium | The field is named `crash_in_finding_scope` (not `fuzz_confirmed`) with an explicit docstring disclaiming exploitation confirmation. The correlation report includes crash signatures for human review. |
| Fuzz target count exceeds reasonable limit, inflating API costs | Medium | Medium | Capped by `BridgeConfig.max_targets` (default: 10, configurable via `DCS_BRIDGE_MAX_TARGETS`). Targets prioritized by SAST severity. |
| Adding `HybridFormatter` protocol creates proliferation of protocol types | Low | Low | Follows the established pattern from merge-fuzzy-wuzzy. Only one new method. The `supports_hybrid()` helper follows the same pattern as `supports_fuzz()`. |
| Bridge module adds import-time overhead to CLI startup | Low | Low | Bridge is imported lazily (only in `hunt-fuzz` command and `_handle_hunt_fuzz`). No top-level imports. |
| AST parsing in resolver disagrees with tree-sitter parsing in Hunter about function boundaries | Low | Low | Eliminated by reusing `signature_extractor.py` which already handles all Python AST edge cases. tree-sitter's line numbers are 0-based (converted to 1-based in findings); the extractor uses 1-based throughout, matching the `RawFinding.sink.line` field. |

## Trust Boundary Analysis

### Bridge Module

The bridge module processes `RawFinding` objects that were generated by the Hunter phase (trusted internal output). The findings contain file paths and line numbers from the user's codebase, which are already validated by the Hunter. The bridge:

- **Reads source files** to parse function boundaries via `signature_extractor.py`. These are the same files the Hunter already parsed. File paths come from `RawFinding.sink.file`, which originated from `FileDiscovery` (trusted).
- **Produces function names** via `signature_extractor.py` on user code. Function names are used as `target_functions` in `FuzzerConfig`, which are already validated by `validate_function_name()` in the MCP path.
- **Generates prompt text** from CWE IDs and vulnerability classes. These are string constants from the registry YAML (trusted). The `CWE_FUZZ_GUIDANCE` map contains hardcoded strings (trusted).

**Trust boundary conclusion:** The bridge sits between two trusted components (Hunter output and Fuzzer input). The only external data it processes is source file content for AST parsing, which is the same trust level as the fuzzer's existing `signature_extractor`. No new trust boundaries are introduced.

### MCP Tool

The `deep_scan_hunt_fuzz` tool follows the same trust boundary pattern as the existing `deep_scan_fuzz`:
- Path validated through `PathValidator`.
- Function names validated through `validate_function_name()`.
- Consent required.
- Fuzz execution uses `ContainerBackend` with full security policy.
- No new attack surface beyond what `deep_scan_hunt` + `deep_scan_fuzz` already expose individually.

### MCP Correlation Response

Crash-derived data in the correlation report (`crash_signatures`) originates from untrusted target code execution and is validated through `validate_crash_data()` from `mcp/input_validator.py` before inclusion in any MCP response. This prevents untrusted exception messages or tracebacks from being returned unsanitized through the MCP protocol.

## Input Validation Specification

### `dcs hunt-fuzz` CLI

| Input | Validation | Same as |
|---|---|---|
| `path` argument | `validate_path()` against `DCS_ALLOWED_PATHS` | `dcs hunt` |
| `--output-dir` | `_validate_write_path()` rejects protected dirs | `dcs fuzz` |
| `--output-file` | `validate_path()` + overwrite protection | `dcs hunt` |
| `--max-fuzz-targets` | `int`, must be >= 1, capped at 100 | New |

### `deep_scan_hunt_fuzz` MCP Tool

| Input | Validation | Same as |
|---|---|---|
| `path` | `validate_path()` | `deep_scan_hunt` |
| `consent` | Must be `True` | `deep_scan_fuzz` |
| `max_iterations` | `int`, capped at reasonable maximum | `deep_scan_fuzz` |
| `max_findings` | `int`, capped at 1000 | `deep_scan_hunt` |
| `max_fuzz_targets` | `int`, capped at 100, default 10 | New |
| `severity_threshold` | enum validation | `deep_scan_hunt` |

### MCP Correlation Response Data

| Output | Validation |
|---|---|
| `CorrelationEntry.crash_signatures` | Each signature sanitized via `validate_crash_data()` before storage in `FuzzRunState`. Crash signatures contain exception type + message from untrusted code execution. |
| `CorrelationEntry.target_function` | Validated through `validate_function_name()` (already validated at bridge resolution time). |
| `CorrelationEntry.sink_function` | From `RawFinding.sink.function` (already validated by Hunter). |

### Bridge Internal

| Input | Validation |
|---|---|
| `RawFinding.sink.file` | Already validated by Hunter; bridge verifies file exists before calling `extract_targets_from_file()` |
| Function names from signature_extractor | Passed through `validate_function_name()` before use in `FuzzerConfig.target_functions` |
| `SASTContext` fields | All derived from registry constants (CWE IDs, vulnerability classes) -- trusted |

## Container Security Policy

No new container operations. The MCP tool uses the existing `ContainerBackend` with the same security policy:
- `--network=none`
- `--read-only`
- `--cap-drop=ALL`
- `--security-opt=no-new-privileges`
- Seccomp profile (`seccomp-fuzz-python.json`)
- `--pids-limit`, `--memory`, `--cpus`
- `--user=65534:65534`
- Noexec tmpfs

## Supply Chain Assessment

No new dependencies. The bridge module uses only:
- `ast` (stdlib) -- transitively via `signature_extractor`
- `pathlib` (stdlib)
- `pydantic` (existing dependency)
- Internal modules from `hunter.models`, `fuzzer.config`, `fuzzer.models`, and `fuzzer.analyzer.signature_extractor`

## Test Plan

### Test Command

```bash
make test
```

This runs `pytest tests/ -v --cov=src/deep_code_security --cov-report=term-missing --cov-fail-under=90 --ignore=tests/test_integration`.

Additionally, bridge-specific tests can be run with:

```bash
pytest tests/test_bridge -v --cov=src/deep_code_security/bridge --cov-report=term-missing
```

### Test Structure

```
tests/test_bridge/
    __init__.py
    conftest.py            # Bridge-specific fixtures (findings with known functions)
    test_models.py         # Pydantic model validation
    test_resolver.py       # Finding-to-function resolution
    test_cwe_guidance.py   # CWE guidance map
    test_orchestrator.py   # End-to-end bridge orchestration
    test_correlation.py    # SAST-fuzz correlation logic
tests/test_fuzzer/
    test_prompts_sast.py   # SAST-enriched prompt building
    test_engine_sast.py    # generate_sast_guided_inputs (mocked API)
```

### Test Cases

**Models (`test_models.py`):**
- `test_sast_context_defaults` -- empty SASTContext is valid
- `test_sast_context_with_data` -- populated SASTContext round-trips
- `test_fuzz_target_construction` -- FuzzTarget with all fields
- `test_fuzz_target_requires_instance` -- FuzzTarget with requires_instance=True
- `test_bridge_result_empty` -- empty bridge result is valid
- `test_bridge_result_with_skips` -- skipped findings counted
- `test_bridge_result_not_directly_fuzzable` -- not_directly_fuzzable counter
- `test_correlation_entry_defaults` -- CorrelationEntry defaults
- `test_correlation_entry_crash_in_finding_scope` -- field semantics
- `test_correlation_report_counts` -- report aggregation
- `test_bridge_config_defaults` -- max_targets defaults to 10
- `test_bridge_config_custom` -- max_targets can be overridden

**Resolver (`test_resolver.py`):**
- `test_resolve_single_finding_to_function` -- finding in a function maps correctly
- `test_resolve_finding_at_exact_function_boundary` -- sink on first/last line of function
- `test_resolve_finding_not_in_function` -- module-level sink is skipped
- `test_resolve_finding_non_python` -- Go/C finding is skipped with reason
- `test_resolve_finding_in_instance_method` -- included with `requires_instance=True`
- `test_resolve_finding_in_classmethod` -- included with `requires_instance=True`
- `test_resolve_finding_in_static_method` -- included (staticmethod is fuzzable)
- `test_resolve_finding_no_fuzzable_params` -- zero-param function skipped with reason, increments `not_directly_fuzzable`
- `test_resolve_finding_in_async_function` -- async function resolved correctly
- `test_resolve_finding_in_nested_function` -- nested function resolved to outermost enclosing function
- `test_resolve_multiple_findings_same_function` -- merged into one FuzzTarget
- `test_resolve_multiple_findings_different_functions` -- two FuzzTargets
- `test_resolve_finding_file_not_found` -- skipped with reason (file deleted since scan)
- `test_resolve_finding_syntax_error` -- skipped with reason (file has syntax errors)
- `test_sast_context_aggregation` -- multiple CWEs merged, highest severity kept
- `test_finding_ids_preserved` -- FuzzTarget.finding_ids contains source finding IDs
- `test_resolve_uses_signature_extractor` -- verify that `extract_targets_from_file` is called (mock-based)
- `test_resolve_function_names_match_fuzzer` -- function names from bridge match what the fuzzer would use (integration-style)
- `test_resolve_capped_by_max_targets` -- more targets than max_targets are capped
- `test_resolve_capped_by_severity_priority` -- capping selects highest-severity targets first

**CWE Guidance (`test_cwe_guidance.py`):**
- `test_known_cwe_returns_guidance` -- CWE-78 returns shell metacharacter guidance
- `test_unknown_cwe_returns_empty` -- CWE-999 returns empty string
- `test_multiple_cwes` -- returns combined guidance for multiple CWEs
- `test_all_registered_cwes_have_nonempty_guidance` -- sanity check

**Orchestrator (`test_orchestrator.py`):**
- `test_run_bridge_with_findings` -- produces FuzzTargets from fixture findings
- `test_run_bridge_no_findings` -- empty findings produce empty result
- `test_correlate_with_crashes` -- crash in target function sets `crash_in_finding_scope=True`
- `test_correlate_no_crashes` -- no crashes means no scope matches
- `test_correlate_crash_in_different_function` -- crash in non-SAST function not correlated

**SAST Prompts (`test_prompts_sast.py`):**
- `test_sast_enriched_prompt_includes_cwe` -- prompt contains CWE ID
- `test_sast_enriched_prompt_includes_guidance` -- prompt contains fuzzing guidance
- `test_sast_enriched_prompt_includes_source_code` -- source code in delimiters
- `test_sast_enriched_prompt_context_outside_delimiters` -- SAST context not in delimiters
- `test_sast_enriched_prompt_empty_context` -- falls back to standard prompt structure
- `test_sast_enriched_prompt_redact_strings` -- string redaction still works
- `test_sast_enriched_prompt_diversity_directive` -- prompt includes diversity directive text ("also generate 3 inputs that are completely unrelated")

**AI Engine (`test_engine_sast.py`):**
- `test_generate_sast_guided_inputs_calls_enriched_prompt` -- uses enriched prompt
- `test_generate_sast_guided_inputs_validates_targets` -- invalid targets rejected
- `test_generate_sast_guided_inputs_cost_budget` -- respects cost budget

**MCP Integration (`test_mcp/test_hunt_fuzz.py`):**
- `test_hunt_fuzz_tool_registration_conditions` -- registered only when ContainerBackend + Anthropic SDK available
- `test_hunt_fuzz_handler_with_mocked_pipeline` -- handler with mocked Hunter and Fuzzer
- `test_hunt_fuzz_correlation_in_status_polling` -- correlation included in completed run
- `test_hunt_fuzz_correlation_crash_data_sanitized` -- crash signatures in correlation report pass through `validate_crash_data()` before inclusion in MCP response

### Coverage Exemptions

The bridge module is fully testable without external dependencies (no API calls, no containers, no subprocess). All code in `bridge/` should be covered by unit tests. The following files are added to `tool.coverage.run.omit`:

- None. The bridge module has no coverage exemptions.

The modified fuzzer files (`prompts.py`, `engine.py`) already have coverage exemptions for the engine (it requires a live API client). The new `generate_sast_guided_inputs` method is tested via mocks in `test_engine_sast.py`.

## Acceptance Criteria

1. `dcs hunt-fuzz tests/fixtures/vulnerable_samples/python/` runs the Hunter, identifies vulnerable functions, and invokes the fuzzer on those functions (with `--consent --dry-run` for CI).
2. The bridge correctly resolves findings to functions: a finding whose sink is the `os.system` call in `command_injection.py` maps to the function `ping_host_vulnerable`.
3. Functions with zero fuzzable parameters (e.g., `ping_host_vulnerable`, which has no parameters and reads from `request.form`) are excluded from fuzz targets with reason `"no fuzzable parameters"` and counted in `not_directly_fuzzable`.
4. Instance methods are included in the target set with `requires_instance=True`, not silently dropped.
5. SAST-enriched prompts contain CWE IDs, sink function names, fuzzing guidance from `CWE_FUZZ_GUIDANCE`, and the diversity directive ("also generate 3 inputs that are completely unrelated").
6. The correlation report correctly identifies which SAST findings had crashes in their target functions using `crash_in_finding_scope` (not `fuzz_confirmed`).
7. `dcs hunt-fuzz` with `--format json` produces a JSON object containing `hunt_result`, `bridge_result`, `fuzz_result`, and `correlation`.
8. `deep_scan_hunt_fuzz` MCP tool is registered when both ContainerBackend and Anthropic SDK are available.
9. `deep_scan_hunt_fuzz` returns a `fuzz_run_id` that can be polled with `deep_scan_fuzz_status`, and the completed result includes the correlation report.
10. Non-Python findings are skipped with diagnostic reasons.
11. Fuzz targets are capped at `max_targets` (default: 10) with highest-severity targets prioritized.
12. Crash signatures in MCP correlation responses are sanitized through `validate_crash_data()`.
13. `make test` passes with 90%+ coverage.
14. `make lint` passes.
15. No new runtime dependencies added.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DCS_BRIDGE_MAX_TARGETS` | `10` | Maximum number of fuzz targets the bridge passes to the fuzzer. When more targets are available, the top N by SAST severity are selected. |

## Task Breakdown

### Phase 1: Bridge Models and Resolver (Foundation)

**Task 1.1: Create bridge module structure**
- Create: `src/deep_code_security/bridge/__init__.py`
- Create: `src/deep_code_security/bridge/models.py`
- Contents: `SASTContext`, `FuzzTarget`, `BridgeConfig`, `BridgeResult`, `CorrelationEntry`, `CorrelationReport` Pydantic models with `__all__` exports.
- The `FuzzTarget` model includes `requires_instance: bool` and `parameter_count: int` fields.
- The `BridgeResult` model includes `not_directly_fuzzable: int` counter.
- The `CorrelationEntry` model uses `crash_in_finding_scope: bool` (not `fuzz_confirmed`).

**Task 1.2: Implement CWE guidance map**
- Create: `src/deep_code_security/bridge/cwe_guidance.py`
- Contents: `CWE_FUZZ_GUIDANCE` dict mapping CWE IDs to fuzzing guidance strings. `get_guidance_for_cwes(cwes: list[str]) -> str` helper function.
- Create: `tests/test_bridge/__init__.py`
- Create: `tests/test_bridge/test_cwe_guidance.py`

**Task 1.3: Extend `TargetInfo` and `extract_targets_from_source()` for bridge requirements**
- Modify: `src/deep_code_security/fuzzer/models.py`
  - Add `lineno: int | None = None` and `end_lineno: int | None = None` fields to `TargetInfo`. These store the 1-based start and end line numbers of the function definition in the source file. They are `None` by default so existing call sites that construct `TargetInfo` without line info (e.g., in tests) are unaffected.
  - Add `is_instance_method: bool = False` field to `TargetInfo`. Set to `True` when the function is an instance method or classmethod inside a class (first param is `self` or `cls`, and no `@staticmethod` decorator). This metadata allows the bridge to set `requires_instance=True` on the resulting `FuzzTarget`.
- Modify: `src/deep_code_security/fuzzer/analyzer/signature_extractor.py`
  - In `_make_target_info()`: populate `lineno` from `func_node.lineno` and `end_lineno` from `func_node.end_lineno`. These values are already available on the AST node (the function currently uses them to extract `source_code` but does not store them).
  - Add `include_instance_methods: bool = False` parameter to `extract_targets_from_source()`. When `False` (default), instance methods and classmethods continue to be skipped with warning logs, preserving existing behavior for the fuzzer's normal discovery path. When `True`, instance methods and classmethods are included in the returned `TargetInfo` list with `is_instance_method=True`. The `_make_target_info()` call for these methods sets `is_instance_method=True`.
  - Add `include_instance_methods: bool = False` parameter to `extract_targets_from_file()`, which passes it through to `extract_targets_from_source()`.
- Add test cases in `tests/test_fuzzer/`:
  - `test_target_info_lineno_fields` -- verify `lineno` and `end_lineno` are populated by `_make_target_info()`.
  - `test_target_info_lineno_defaults_none` -- verify default `None` when not provided.
  - `test_extract_targets_include_instance_methods_false` -- default behavior unchanged (instance methods skipped).
  - `test_extract_targets_include_instance_methods_true` -- instance methods and classmethods included with `is_instance_method=True`.
  - `test_extract_targets_static_method_not_instance` -- static methods have `is_instance_method=False` regardless of flag.

**Task 1.4: Implement finding-to-function resolver**
- Create: `src/deep_code_security/bridge/resolver.py`
- Contents: `resolve_findings_to_targets()` function. Uses `extract_targets_from_file(path, allow_side_effects=True, include_instance_methods=True)` from `signature_extractor.py` for function boundary detection. Language filter. Fuzzability check (parameter count). Instance method inclusion with `requires_instance=True` annotation (derived from `TargetInfo.is_instance_method`). SAST context aggregation. Target cap enforcement.
- Create: `tests/test_bridge/conftest.py` -- fixtures with sample RawFinding objects mapped to known fixture files.
- Create: `tests/test_bridge/test_resolver.py` -- all resolver test cases.

**Task 1.5: Implement bridge models tests**
- Create: `tests/test_bridge/test_models.py`

### Phase 2: Bridge Orchestrator and Correlation

**Task 2.1: Implement bridge orchestrator**
- Create: `src/deep_code_security/bridge/orchestrator.py`
- Contents: `BridgeOrchestrator` class with `run_bridge()` and `correlate()` methods.
- Correlation uses `crash_in_finding_scope` field name.
- Create: `tests/test_bridge/test_orchestrator.py`

**Task 2.2: Implement correlation logic**
- Create: `tests/test_bridge/test_correlation.py`
- The correlation logic lives in `BridgeOrchestrator.correlate()`. This task tests it separately with constructed `BridgeResult` and `FuzzReport` fixtures.

### Phase 3: SAST-Enriched AI Prompts

**Task 3.1: Add SAST-enriched prompt builder**
- Modify: `src/deep_code_security/fuzzer/ai/prompts.py`
  - Add `build_sast_enriched_prompt()` function.
  - Import `SASTContext` from `bridge.models`.
  - Import `get_guidance_for_cwes` from `bridge.cwe_guidance`.
  - Include diversity directive in the prompt: "After generating SAST-guided inputs, also generate 3 inputs that are completely unrelated to the identified vulnerability pattern to maintain coverage breadth."
- Create: `tests/test_fuzzer/test_prompts_sast.py`

**Task 3.2: Add SAST-guided input generation to AIEngine**
- Modify: `src/deep_code_security/fuzzer/ai/engine.py`
  - Add `generate_sast_guided_inputs()` method.
  - Import `SASTContext` from `bridge.models`.
  - Method signature: `sast_contexts: dict[str, SASTContext]` (consistent with `FuzzerConfig` type).
- Create: `tests/test_fuzzer/test_engine_sast.py`

### Phase 4: Fuzzer Integration

**Task 4.1: Extend FuzzerConfig with SAST context field**
- Modify: `src/deep_code_security/fuzzer/config.py`
  - Add `sast_contexts: dict[str, SASTContext] | None = Field(default=None, exclude=True)` field.
  - Import `SASTContext` from `bridge.models`.

**Task 4.2: Extend FuzzOrchestrator to use SAST context**
- Modify: `src/deep_code_security/fuzzer/orchestrator.py`
  - Accept optional `sast_contexts` parameter (dict keyed by qualified function name).
  - On iteration 1 only, if `sast_contexts` is set, call `ai_engine.generate_sast_guided_inputs()` instead of `generate_initial_inputs()`.

### Phase 5: CLI and Formatter Integration

**Task 5.1: Add HuntFuzzResult DTO and HybridFormatter protocol**
- Modify: `src/deep_code_security/shared/formatters/protocol.py`
  - Add `HuntFuzzResult` Pydantic model.
  - Add `HybridFormatter` protocol (separate from `FuzzFormatter`).
  - Add `supports_hybrid()` helper function.
  - Update `__all__`.
  - Do NOT modify the existing `FuzzFormatter` protocol.

**Task 5.2: Implement `format_hunt_fuzz()` in formatters**
- Modify: `src/deep_code_security/shared/formatters/text.py` -- add `format_hunt_fuzz()`.
- Modify: `src/deep_code_security/shared/formatters/json.py` -- add `format_hunt_fuzz()`.
- Modify: `src/deep_code_security/shared/formatters/sarif.py` -- add `format_hunt_fuzz()`. The SARIF output includes both SAST results and fuzz crash results as separate `run` entries.
- Do NOT modify `src/deep_code_security/shared/formatters/html.py`. HTML is deferred.

**Task 5.3: Add `dcs hunt-fuzz` CLI command**
- Modify: `src/deep_code_security/cli.py`
  - Add `hunt_fuzz` command with all options including `--max-fuzz-targets`.
  - Import bridge orchestrator lazily.
  - Build `HuntFuzzResult` DTO.
  - Use `supports_hybrid()` to check formatter compatibility.
  - Format and write output.

### Phase 6: MCP Integration

**Task 6.1: Add `deep_scan_hunt_fuzz` MCP tool**
- Modify: `src/deep_code_security/mcp/server.py`
  - Add `_handle_hunt_fuzz()` handler.
  - Register tool conditionally (ContainerBackend available + Anthropic importable).
  - Input schema includes `max_fuzz_targets` parameter.
  - Extend `FuzzRunState` with optional bridge/correlation data.
  - Update `_handle_fuzz_status()` to include correlation in completed hunt-fuzz results.
  - **Sanitize crash-derived data in correlation responses**: call `validate_crash_data()` on each `CorrelationEntry.crash_signatures` entry before storing in `FuzzRunState`.

**Task 6.2: Add MCP tests**
- Create: `tests/test_mcp/test_hunt_fuzz.py`
  - Test tool registration conditions.
  - Test handler with mocked Hunter and Fuzzer.
  - Test correlation in fuzz_status polling.
  - `test_hunt_fuzz_correlation_crash_data_sanitized` -- verify that crash signatures are sanitized through `validate_crash_data()` before inclusion in MCP responses.

### Phase 7: Documentation and Cleanup

**Task 7.1: Update CLAUDE.md**
- Modify: `CLAUDE.md`
  - Add `bridge/` to Architecture section.
  - Add `dcs hunt-fuzz` to CLI Commands table.
  - Add `deep_scan_hunt_fuzz` to MCP tools description. Update from "6 tools always + deep_scan_fuzz when Podman available" to "6 tools always + deep_scan_fuzz, deep_scan_hunt_fuzz when Podman available."
  - Add `DCS_BRIDGE_MAX_TARGETS` to Environment Variables table.

**Task 7.2: Update pyproject.toml coverage config**
- Modify: `pyproject.toml`
  - Add `tests/test_bridge` to test paths (already covered by `tests/`).
  - Add bridge module `__init__.py` to coverage omit if it is a pure re-export.

**Task 7.3: Add Makefile target**
- Modify: `Makefile`
  - Add `test-bridge` target.
  - Update `.PHONY`.

**Task 7.4: Run full test suite**
- Run: `make test` and `make lint`.
- Fix any coverage gaps.

### Files Summary

| Action | File |
|---|---|
| Create | `src/deep_code_security/bridge/__init__.py` |
| Create | `src/deep_code_security/bridge/models.py` |
| Create | `src/deep_code_security/bridge/cwe_guidance.py` |
| Create | `src/deep_code_security/bridge/resolver.py` |
| Create | `src/deep_code_security/bridge/orchestrator.py` |
| Create | `tests/test_bridge/__init__.py` |
| Create | `tests/test_bridge/conftest.py` |
| Create | `tests/test_bridge/test_models.py` |
| Create | `tests/test_bridge/test_cwe_guidance.py` |
| Create | `tests/test_bridge/test_resolver.py` |
| Create | `tests/test_bridge/test_orchestrator.py` |
| Create | `tests/test_bridge/test_correlation.py` |
| Create | `tests/test_fuzzer/test_prompts_sast.py` |
| Create | `tests/test_fuzzer/test_engine_sast.py` |
| Create | `tests/test_mcp/test_hunt_fuzz.py` |
| Modify | `src/deep_code_security/fuzzer/models.py` |
| Modify | `src/deep_code_security/fuzzer/analyzer/signature_extractor.py` |
| Modify | `src/deep_code_security/fuzzer/ai/prompts.py` |
| Modify | `src/deep_code_security/fuzzer/ai/engine.py` |
| Modify | `src/deep_code_security/fuzzer/config.py` |
| Modify | `src/deep_code_security/fuzzer/orchestrator.py` |
| Modify | `src/deep_code_security/shared/formatters/protocol.py` |
| Modify | `src/deep_code_security/shared/formatters/text.py` |
| Modify | `src/deep_code_security/shared/formatters/json.py` |
| Modify | `src/deep_code_security/shared/formatters/sarif.py` |
| Modify | `src/deep_code_security/cli.py` |
| Modify | `src/deep_code_security/mcp/server.py` |
| Modify | `CLAUDE.md` |
| Modify | `pyproject.toml` |
| Modify | `Makefile` |

No files are deleted.

## Known Limitations

1. **Framework route handlers are not fuzzable.** Functions whose taint source is a framework global (e.g., Flask `request.form`, Django `request.GET`, `sys.argv`, `input()`) are excluded from fuzzing targets because the fuzzer calls functions with direct arguments and cannot provide framework context. For web-framework-heavy codebases, the majority of SAST findings will be in this category. The `BridgeResult.not_directly_fuzzable` counter makes this visible.
2. **Instance methods are included but may not work.** Instance methods are included in the target set with `requires_instance=True`, but the fuzzer MVP cannot auto-construct `self`. These targets may crash with attribute errors rather than exercising the vulnerability. They are included for visibility and future harness support.
3. **Crash correlation is scope-based, not vulnerability-specific.** A crash in a function that has a SAST finding does not confirm the specific SAST vulnerability was exploited. The crash may be from a `TypeError`, missing context, or an unrelated code path. The `crash_in_finding_scope` field name reflects this limited claim.
4. **Intraprocedural taint only.** Inherited from the Hunter phase. A function that calls a vulnerable helper will not have a SAST finding unless the source and sink are in the same function body.

## Context Alignment

### CLAUDE.md Patterns Followed

- **Pydantic v2 for all data-crossing models**: All new models (`SASTContext`, `FuzzTarget`, `BridgeConfig`, `BridgeResult`, `CorrelationEntry`, `CorrelationReport`, `HuntFuzzResult`) are Pydantic `BaseModel` subclasses.
- **Type hints on all public functions**: All bridge functions, orchestrator methods, and prompt builders are fully typed.
- **`__all__` in `__init__.py` files**: Bridge `__init__.py` exports all public symbols.
- **`pathlib.Path` over `os.path`**: Bridge resolver uses `Path` for all file operations.
- **No mutable default arguments**: All list/dict fields use `Field(default_factory=...)`.
- **`models.py` per phase**: Bridge models in `bridge/models.py`.
- **`orchestrator.py` per phase**: Bridge orchestrator in `bridge/orchestrator.py`.
- **Security rules**: No `eval()`, `exec()`, `shell=True`, `yaml.load()`. File paths validated through `PathValidator`. CWE guidance is hardcoded strings (not user input). Crash data in MCP responses sanitized through `validate_crash_data()`.
- **Never `yaml.load()`**: Not applicable (no YAML in bridge).
- **All file paths validated through `mcp/path_validator.py`**: MCP handler validates target path. CLI validates via `validate_path()`.
- **Container security policy non-negotiable**: MCP tool uses existing `ContainerBackend` with full policy.
- **90%+ test coverage required**: Comprehensive test plan covering all bridge code.
- **Formatter architecture**: New DTO follows `HuntResult`/`FullScanResult`/`FuzzReportResult` pattern. New `HybridFormatter` protocol follows the protocol-separation principle established by `FuzzFormatter` in merge-fuzzy-wuzzy.

### Prior Plans This Builds Upon

- **`plans/merge-fuzzy-wuzzy.md` (APPROVED)**: This plan realizes the "cross-engine finding correlation" feature listed as Non-Goal #22 and deferred with "architectural hooks only." The bridge module is the implementation of those hooks. The `HybridFormatter` protocol follows the same protocol-separation principle used when `FuzzFormatter` was created as a separate protocol from `Formatter`.
- **`plans/fuzzer-container-backend.md` (APPROVED)**: The MCP tool follows the same conditional registration pattern (`ContainerBackend.is_available()`). The background thread + `FuzzRunState` pattern is reused.
- **`plans/output-formats.md` (APPROVED)**: The new `HuntFuzzResult` DTO follows the same Pydantic DTO pattern as `HuntResult`, `FullScanResult`, and `FuzzReportResult`. SARIF output for hunt-fuzz uses the same `tool.driver.rules[]` and `result.properties` patterns.
- **`plans/deep-code-security.md` (APPROVED)**: The bridge maintains the v1 constraint of intraprocedural taint tracking only. The pipeline is purely additive to the existing three-phase architecture.

### Deviations from Established Patterns

- **Bridge module imports `signature_extractor` from the fuzzer.** The bridge depends on `fuzzer.analyzer.signature_extractor` for function boundary detection. This creates a cross-module dependency (bridge -> fuzzer.analyzer). This is accepted because: (a) function name agreement between the bridge and the fuzzer is a correctness requirement, not just a convenience, and (b) the alternative (reimplementing function boundary detection) creates a silent divergence risk that is worse than the coupling. The dependency direction is clean: `bridge` imports from `fuzzer.analyzer`, but `fuzzer` does not import from `bridge`.
- **Bridge module is a new top-level directory (`bridge/`) rather than a subdirectory of `hunter/` or `fuzzer/`.** The bridge crosses the boundary between two phases. Placing it inside either phase would create a circular dependency (hunter depends on fuzzer models or vice versa). A top-level module makes the dependency direction clear: `bridge` imports from both `hunter.models` and `fuzzer.config`/`fuzzer.models`, but neither `hunter` nor `fuzzer` imports from `bridge`.
- **`HybridFormatter` is a new protocol separate from `FuzzFormatter`.** Adding `format_hunt_fuzz()` to `FuzzFormatter` would break existing formatters (HTML) that implement `FuzzFormatter` but not the new method, because `FuzzFormatter` is `@runtime_checkable` and Python checks all protocol methods. The `HybridFormatter` protocol follows the same separation principle used when `FuzzFormatter` was created separately from `Formatter`.

<!-- Context Metadata
discovered_at: 2026-03-17T00:39:00Z
claude_md_exists: true
recent_plans_consulted: fuzzer-container-backend.md, merge-fuzzy-wuzzy.md, output-formats.md, deep-code-security.md
archived_plans_consulted: none
-->

## Status: APPROVED
