# Plan: Merge fuzzy-wuzzy into deep-code-security as Dynamic Analysis Backend

## Status: APPROVED

## Goals

1. Merge the fuzzy-wuzzy AI-powered Python fuzzer into deep-code-security as a dynamic analysis backend, creating a unified product with two analysis modes: static (tree-sitter taint tracking) and dynamic (LLM-guided fuzzing).
2. Unify the CLI under the single `dcs` entry point with subcommands for both analysis backends (`dcs hunt`, `dcs fuzz`, `dcs full-scan`, `dcs replay`, etc.).
3. Unify output formatting by merging fuzzy-wuzzy's text/JSON/SARIF formatters into DCS's existing formatter registry, eliminating duplicate SARIF implementation.
4. Convert all fuzzy-wuzzy dataclass models to Pydantic v2 per CLAUDE.md rules.
5. Share infrastructure: file discovery, path validation, configuration, and output file handling.
6. Expose fuzzing capabilities through new MCP server tools (`deep_scan_fuzz`, `deep_scan_fuzz_status`).
7. Preserve fuzzy-wuzzy's consent model, cost tracking, Vertex AI integration, corpus management, and replay capabilities.
8. Lay the architectural foundation for post-merge features: input minimization, severity classification, cross-engine finding correlation, and actionable guidance generation for fuzz findings.

## Non-Goals

- Merging fuzzy-wuzzy's git history into deep-code-security (code is copied, not git-subtree'd).
- Making the `anthropic` dependency mandatory (it becomes an optional dependency like `dcs-verification`).
- Adding new language plugins for fuzzy-wuzzy beyond Python in this plan (Go/C fuzzing is a separate future effort).
- Implementing interprocedural taint tracking (v1.1, per existing constraint).
- Cross-engine finding correlation in this plan (listed as post-merge feature with architectural hooks only).
- Input minimization in this plan (post-merge feature).
- Severity classification for fuzz crashes in this plan (post-merge feature).
- Extending the Architect phase to generate guidance for fuzz findings in this plan (post-merge feature).
- Changing how the private `dcs-verification` plugin works.
- Adding HTML output for fuzzy-wuzzy (currently raises `NotImplementedError`; the merged product uses DCS's `HtmlFormatter` which will be extended for fuzz results in a later phase).
- Renaming the `fuzzy-wuzzy-ai` PyPI package (it ceases to exist as a separate package; its functionality is absorbed into `deep-code-security`).
- Implementing the `ContainerBackend` for the fuzzer sandbox in this plan (deferred; see Security Deviation SD-01).

## Assumptions

1. fuzzy-wuzzy at `~/projects/fuzzy-wuzzy` is the canonical source. All code will be copied (not submoduled) into the deep-code-security repository under `src/deep_code_security/fuzzer/`.
2. The `anthropic` package is available on the target machine (required for fuzzing, but not for SAST). It is declared as an optional dependency: `pip install deep-code-security[fuzz]`.
3. Vertex AI is the preferred backend per user requirement. The direct Anthropic API key path remains as a fallback.
4. The fuzzy-wuzzy test suite (currently in `~/projects/fuzzy-wuzzy/tests/`) will be migrated into `tests/test_fuzzer/` and adapted to import from the new package structure.
5. All tests pass via `make test` after the merge (90%+ coverage maintained).
6. The `rich` dependency is acceptable to add to the optional `[fuzz]` group (not a core dependency). When not installed, the fuzzer falls back to `logging.StreamHandler` with basic formatting.
7. The `coverage` (Python coverage.py) dependency is acceptable to add to the optional `[fuzz]` group.
8. The consent model (`~/.config/fuzzy-wuzzy/consent.json`) will be migrated to `~/.config/deep-code-security/consent.json`.

## Proposed Design

### Architecture Overview

After the merge, the product has five analysis backends under a shared foundation:

```
src/deep_code_security/
    shared/                     # SHARED INFRASTRUCTURE (expanded)
        __init__.py
        config.py               # Extended: adds fuzz-related config (DCS_FUZZ_*)
        file_discovery.py       # Reused by fuzzer for .py file discovery
        language.py             # Reused
        json_output.py          # Reused
        formatters/             # UNIFIED FORMATTER REGISTRY
            __init__.py         # Registry: register_formatter() warns (not errors)
                                #   on missing format_fuzz/format_replay
            protocol.py         # Extended: adds FuzzFormatter protocol,
                                #   FuzzReportResult DTO, ReplayResult DTO
            text.py             # Extended: format_fuzz(), format_replay()
            json.py             # Extended: format_fuzz(), format_replay()
            sarif.py            # Extended: format_fuzz(), format_replay()
            html.py             # Extended: format_fuzz() (post-merge)

    hunter/                     # STATIC ANALYSIS (unchanged)
        ...

    auditor/                    # EXPLOIT VERIFICATION (unchanged)
        ...

    architect/                  # REMEDIATION GUIDANCE (unchanged, future extension point)
        ...

    fuzzer/                     # DYNAMIC ANALYSIS (NEW - from fuzzy-wuzzy)
        __init__.py
        models.py               # Pydantic v2 conversions of FuzzInput, FuzzResult, etc.
        orchestrator.py         # Adapted FuzzOrchestrator (signal handlers optional)
        config.py               # FuzzerConfig as Pydantic model (merged with DCS Config)
        exceptions.py           # Exception hierarchy (namespaced under DCS)
        consent.py              # Consent management (extracted from orchestrator)
        ai/
            __init__.py
            engine.py           # AIEngine (Vertex AI + direct API)
            prompts.py          # Prompt templates
            response_parser.py  # Strict AST validation
            context_manager.py  # Token budget management
        execution/
            __init__.py
            sandbox.py          # SandboxManager with rlimits (CLI only, see SD-01)
            runner.py           # FuzzRunner with JSON IPC
            _worker.py          # Fixed subprocess worker (AST validation before eval)
        analyzer/
            __init__.py
            source_reader.py    # Side-effect detection
            signature_extractor.py  # Function discovery
        corpus/
            __init__.py
            manager.py          # CorpusManager (dedup by hash + crash signature)
            serialization.py    # JSON persistence (preserves manual serialization)
        coverage_tracking/
            __init__.py
            collector.py        # coverage.py integration
            delta.py            # DeltaTracker, plateau detection
        plugins/
            __init__.py
            base.py             # TargetPlugin ABC (Pydantic models)
            registry.py         # Lazy entry-point discovery, DCS_FUZZ_ALLOWED_PLUGINS
            python_target.py    # MVP Python plugin
        reporting/
            __init__.py
            dedup.py            # Crash deduplication (Pydantic UniqueCrash)
        replay/
            __init__.py
            runner.py           # ReplayRunner (re-validates expressions before eval)

    mcp/                        # MCP SERVER (extended: 5 -> 7 tools)
        __init__.py
        __main__.py
        server.py               # Extended: adds deep_scan_fuzz, deep_scan_fuzz_status
        shared/                 # Vendored BaseMCPServer
        path_validator.py
        input_validator.py      # Extended: validates fuzz crash data in MCP responses

    cli.py                      # UNIFIED CLI (extended)
```

### How fuzzy-wuzzy Becomes the "fuzzer" Phase

fuzzy-wuzzy is restructured into `src/deep_code_security/fuzzer/`, becoming a peer of `hunter/`, `auditor/`, and `architect/`. Key changes:

1. **All imports change** from `fuzzy_wuzzy.X` to `deep_code_security.fuzzer.X`.
2. **All dataclasses become Pydantic v2 BaseModel** (see Models section).
3. **FuzzerConfig** is converted to a Pydantic model using `@model_validator(mode='after')` to replicate `__post_init__` behavior, and merged into the DCS `Config` class as a nested `fuzz` attribute. Environment variables change from implicit to explicit `DCS_FUZZ_*` prefix.
4. **Consent management** is extracted from the orchestrator into a standalone `consent.py` module under `fuzzer/`, using `~/.config/deep-code-security/consent.json` as the storage path.
5. **The fuzzer/reporting/formatters.py and fuzzer/replay/formatters.py are deleted.** All formatting goes through the unified `shared/formatters/` registry.
6. **The fuzzer/reporting/reporter.py `FuzzReport` dataclass** becomes a Pydantic model in `fuzzer/models.py` and serves as input to the unified formatters.
7. **The fuzzer's SARIF output** is reimplemented as methods on the existing `SarifFormatter` class, eliminating duplicate SARIF generation code.
8. **`_worker.py` gains AST validation at the `eval()` call site**, independent of `response_parser.py` (see Security Deviation SD-02).
9. **Signal handler installation is made conditional** via `install_signal_handlers` parameter on `FuzzOrchestrator`.
10. **Plugin registry uses lazy loading** with a `DCS_FUZZ_ALLOWED_PLUGINS` allowlist.

### Unified CLI

The `dcs` CLI group gains new subcommands:

```
dcs hunt <path>            # Static analysis (unchanged)
dcs full-scan <path>       # Static + verify + remediate (unchanged)
dcs verify ...             # Audit phase stub (unchanged)
dcs status                 # Server status (extended for fuzzer info)

dcs fuzz <target>          # NEW: Run AI-powered fuzzer
dcs replay <corpus_dir>    # NEW: Re-execute saved crash inputs
dcs corpus <corpus_dir>    # NEW: Inspect corpus contents
dcs fuzz-plugins           # NEW: List available fuzzer plugins

dcs report <output_dir>    # NEW: View saved fuzz reports
```

All subcommands that produce output support `--format` (text|json|sarif|html) and `--output-file` + `--force`, reusing the existing `_write_output()` and `_resolve_format()` infrastructure.

The `fuzz` command inherits fuzzy-wuzzy's options:

```python
@cli.command()
@click.argument("target")
@click.option("--function", "-F", multiple=True, help="Specific function(s) to fuzz.")
@click.option("--iterations", "-n", default=10, help="Maximum fuzzing iterations.")
@click.option("--inputs-per-iter", default=10, help="Inputs per iteration.")
@click.option("--timeout", default=5000, metavar="MS", help="Per-input timeout in ms.")
@click.option("--model", default="claude-sonnet-4-6", help="Claude model to use.")
@click.option("--output-dir", default="./fuzzy-output", metavar="PATH", help="Output directory.")
@click.option("--format", "-f", "output_format", type=click.Choice(["text", "json", "sarif", "html"]), default="text")
@click.option("--output-file", "-o", default=None, metavar="PATH", help="Write output to file.")
@click.option("--max-cost", default=5.00, metavar="USD", help="API cost budget.")
@click.option("--consent", is_flag=True, help="Consent to API transmission.")
@click.option("--dry-run", is_flag=True, help="Preview what would be sent.")
@click.option("--vertex", is_flag=True, help="Use Vertex AI backend.")
@click.option("--gcp-project", default=None, help="GCP project ID.")
@click.option("--gcp-region", default="us-east5", help="GCP region.")
# ... other options preserved
def fuzz(target, ...):
    """Run AI-powered fuzzer against a Python target."""
```

**CLI flag resolution:** `--function` uses `-F` (capital) as its short flag. `-f` is reserved for `--format`, consistent with the existing `hunt` and `full-scan` commands per the output-formats plan. The `--output` flag is renamed to `--output-dir` to distinguish it from `--output-file` (which writes formatted output to a file, consistent with `hunt`).

**Path validation:** The `fuzz` command validates `target` through `PathValidator` using `DCS_ALLOWED_PATHS`, consistent with how `hunt` validates its path argument. The `--output-dir` directory for corpus/reports is also validated via `PathValidator`, with an additional write-path check that rejects paths inside `src/`, `registries/`, and `.git/` (see Task 4.1).

### Unified MCP Server

Two new MCP tools are added to `DeepCodeSecurityMCPServer`, bringing the total tool count from 5 to 7. CLAUDE.md must be updated (Task 7.1) to reflect this.

**`deep_scan_fuzz`** -- Start a fuzz run (async-start pattern):

The `deep_scan_fuzz` tool is a **CLI-only feature in this plan**. It is NOT exposed as an MCP tool until the container-based sandbox backend is implemented. See Security Deviation SD-01 for full rationale. The MCP tool definition below is preserved as the target design for post-container-backend implementation.

**Deferred MCP tool design (blocked on container backend):**

```python
input_schema = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "description": "Path to Python file/module to fuzz"},
        "functions": {"type": "array", "items": {"type": "string"}, "description": "Specific functions to fuzz"},
        "iterations": {"type": "integer", "default": 3, "description": "Max fuzzing iterations (MCP default: 3)"},
        "inputs_per_iteration": {"type": "integer", "default": 5, "description": "Inputs per iteration (MCP default: 5)"},
        "model": {"type": "string", "default": "claude-sonnet-4-6"},
        "max_cost_usd": {"type": "number", "default": 2.00},
        "timeout_ms": {"type": "integer", "default": 5000},
        "consent": {"type": "boolean", "default": False, "description": "Consent to API code transmission AND code execution"},
    },
    "required": ["path", "consent"],
}
```

When the container backend is implemented and this tool is unblocked, the handler will:
1. Start the fuzz run in a background thread, returning immediately with `{"status": "running", "fuzz_run_id": "..."}`.
2. The client polls `deep_scan_fuzz_status` with the `fuzz_run_id` to get progress and final results.
3. A hard wall-clock timeout (`DCS_FUZZ_MCP_TIMEOUT`, default 120 seconds) caps execution time. The fuzzer saves partial results when the timeout expires.
4. The `FuzzOrchestrator` is instantiated with `install_signal_handlers=False` to avoid overriding the MCP server's signal handlers.
5. All crash data (exception messages, tracebacks, function names) in the MCP response is validated through `input_validator.py` to sanitize untrusted content from target code execution.
6. MCP-triggered fuzz runs use the container backend exclusively (rlimit-only backend is rejected).

**`deep_scan_fuzz_status`** -- Check fuzzer availability and poll running fuzz operations:

```python
input_schema = {
    "type": "object",
    "properties": {
        "fuzz_run_id": {"type": "string", "description": "Poll a specific fuzz run (optional)"},
    },
}
```

Returns: `anthropic_available`, `vertex_configured`, `consent_stored`, `available_plugins`, `container_backend_available`. When `fuzz_run_id` is provided, returns progress (current iteration, crashes found so far, estimated cost) or final results if the run has completed.

**Note:** `deep_scan_fuzz_status` is implemented immediately (Phase 5) since it performs no code execution. `deep_scan_fuzz` registration is deferred until the container backend is available.

### Shared Formatters

The existing `Formatter` protocol is **not modified**. Instead, a new `FuzzFormatter` protocol is introduced:

```python
# shared/formatters/protocol.py (additions)

class FuzzReportResult(BaseModel):
    """Aggregated results from a fuzz run."""
    config_summary: FuzzConfigSummary
    targets: list[FuzzTargetInfo]
    crashes: list[FuzzCrashSummary]
    unique_crashes: list[UniqueCrashSummary]
    total_inputs: int = 0
    crash_count: int = 0
    unique_crash_count: int = 0
    timeout_count: int = 0
    total_iterations: int = 0
    coverage_percent: float | None = None
    api_cost_usd: float | None = None
    timestamp: float = 0.0

class ReplayResult(BaseModel):
    """Aggregated results from a replay run."""
    results: list[ReplayResultEntry]
    fixed_count: int = 0
    still_failing_count: int = 0
    error_count: int = 0
    total_count: int = 0

class Formatter(Protocol):
    """Protocol for output formatters (SAST results).

    This protocol is unchanged from the output-formats plan. Formatters
    that support only SAST output implement this protocol alone.
    """

    def format_hunt(self, data: HuntResult, target_path: str = "") -> str: ...
    def format_full_scan(self, data: FullScanResult, target_path: str = "") -> str: ...

class FuzzFormatter(Protocol):
    """Protocol for formatters that support fuzz/replay output.

    This is a separate protocol from Formatter. A class can implement both
    by having all four methods. The registry checks for FuzzFormatter
    support separately from Formatter support.
    """

    def format_fuzz(self, data: FuzzReportResult, target_path: str = "") -> str: ...
    def format_replay(self, data: ReplayResult, target_path: str = "") -> str: ...
```

**Backward compatibility:** The `Formatter` protocol retains exactly two methods (`format_hunt`, `format_full_scan`). Existing third-party formatters are not broken. The `register_formatter()` function continues to validate only `format_hunt` and `format_full_scan`. A new `register_fuzz_formatter()` function (or an optional check in `register_formatter()`) validates `format_fuzz` and `format_replay` when present. The built-in formatters (text, json, sarif, html) implement both protocols.

**Rationale for separate protocols:** `typing.Protocol` uses structural subtyping. Adding methods to an existing Protocol breaks all classes that previously satisfied it but lack the new methods. A separate `FuzzFormatter` protocol avoids this. The CLI and MCP code checks `isinstance(formatter, FuzzFormatter)` (using `runtime_checkable`) before calling `format_fuzz()` or `format_replay()`.

**`format_hunt()` signature note:** The `target_path: str = ""` parameter already exists in the current codebase (`shared/formatters/protocol.py` line 55). This is not a new addition by this plan.

**SARIF unification:** The `SarifFormatter.format_fuzz()` method produces SARIF results from fuzz crashes using the same envelope structure as `format_hunt()`. Key mapping:

| Fuzz Concept | SARIF Concept |
|---|---|
| `UniqueCrash` | `result` |
| `exception_type` | `result.ruleId` (e.g., `FW/ZeroDivisionError/001`) |
| Crash location from traceback | `result.locations[].physicalLocation` |
| Crash signature SHA-256 | `result.fingerprints.fuzzyWuzzyCrashSignature/v1` |
| `tool.driver` | name="deep-code-security", version from package |

The `tool.driver.name` in SARIF changes from `"fuzzy-wuzzy"` to `"deep-code-security"` for unified tool identity. A `properties.analysis_mode` field distinguishes `"static"` from `"dynamic"` results.

### Shared Finding Models

The two analysis backends produce **distinct finding types**. This is by design -- a taint-tracked dataflow vulnerability (RawFinding) is fundamentally different from a crash discovered by fuzzing (FuzzCrashSummary). Attempting to unify them into a generic "Finding" would lose precision.

However, the **formatter DTOs** provide a common reporting layer. Both backends produce DTO models that the formatters consume:

```
SAST Pipeline: RawFinding -> VerifiedFinding -> HuntResult/FullScanResult -> Formatter
Fuzz Pipeline: FuzzResult -> UniqueCrash    -> FuzzReportResult            -> FuzzFormatter
```

**Post-merge extension point:** A `CorrelatedFinding` model can be introduced later that pairs a `RawFinding` with an `UniqueCrash` when both refer to the same code location. This is explicitly deferred.

### Model Conversions (dataclass -> Pydantic v2)

All fuzzy-wuzzy models are converted from `@dataclass` to `pydantic.BaseModel`. This is required by CLAUDE.md ("Pydantic v2 for all data-crossing models"). The models live in `fuzzer/models.py` and `fuzzer/plugins/base.py`.

```python
# fuzzer/models.py
from pydantic import BaseModel, Field

class FuzzInput(BaseModel):
    """A single fuzz input."""
    target_function: str = Field(..., description="Qualified function name")
    args: tuple[str, ...] = Field(default_factory=tuple, description="Positional args as expression strings")
    kwargs: dict[str, str] = Field(default_factory=dict, description="Keyword args as expression strings")
    metadata: dict[str, str] = Field(default_factory=dict, description="AI rationale, generation context")

class FuzzResult(BaseModel):
    """Result of executing a single fuzz input."""
    input: FuzzInput
    success: bool
    exception: str | None = None
    traceback: str | None = None
    duration_ms: float
    coverage_data: dict = Field(default_factory=dict)
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

class CoverageReport(BaseModel):
    """Coverage information for AI feedback."""
    total_lines: int
    covered_lines: int
    coverage_percent: float
    uncovered_regions: list[dict] = Field(default_factory=list)
    branch_coverage: dict = Field(default_factory=dict)
    new_lines_covered: list[dict] = Field(default_factory=list)

class TargetInfo(BaseModel):
    """Information about a fuzz target."""
    module_path: str
    function_name: str
    qualified_name: str
    signature: str
    parameters: list[dict] = Field(default_factory=list)
    docstring: str | None = None
    source_code: str = ""
    decorators: list[str] = Field(default_factory=list)
    complexity: int = 0
    is_static_method: bool = False
    has_side_effects: bool = False

class UniqueCrash(BaseModel):
    """A deduplicated crash group."""
    signature: str
    exception_type: str
    exception_message: str = ""
    location: str = ""
    representative: FuzzResult
    count: int
    target_functions: list[str] = Field(default_factory=list)

class FuzzReport(BaseModel):
    """Complete report from a fuzzing run."""
    targets: list[TargetInfo] = Field(default_factory=list)
    all_results: list[FuzzResult] = Field(default_factory=list)
    crashes: list[FuzzResult] = Field(default_factory=list)
    total_iterations: int = 0
    api_usage: dict | None = None  # Serialized APIUsage
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
```

**FuzzInput frozen policy:** The original fuzzy-wuzzy `FuzzInput` is a mutable dataclass. The Pydantic conversion does NOT use `frozen=True`. Rationale: `frozen=True` on a Pydantic model prevents attribute reassignment (`fuzz_input.metadata = new_dict` would raise `ValidationError`), but does not prevent dict mutation (`fuzz_input.metadata["key"] = "value"` still works). This asymmetry provides no meaningful immutability guarantee while breaking any downstream code that reassigns attributes. The `FuzzInput` Pydantic model is mutable, matching the original behavior.

**FuzzReport.unique_crashes:** The original dataclass uses `@functools.cached_property`, which is incompatible with Pydantic `BaseModel`. The Pydantic model uses a plain `@property` instead. Deduplication is computed once in the orchestrator when constructing the `FuzzReportResult` DTO for formatters, avoiding redundant computation.

**FuzzReport.config_summary:** Typed as `dict`. Access sites that previously used `report.config.target_path` must be updated to use `report.config_summary["target_path"]`. A `FuzzConfigSummary` Pydantic model is defined in `shared/formatters/protocol.py` for the formatter DTO layer, providing typed access for formatters.

**Corpus serialization:** The `serialize_fuzz_result()` function in `corpus/serialization.py` must preserve its manual serialization logic (truncating `stdout[:1000]`, omitting `coverage_data` in favor of `coverage_summary`, adding `schema_version`). It must NOT be naively replaced with Pydantic's `model_dump()`. The `deserialize_fuzz_result()` function works correctly with Pydantic's constructor since Pydantic accepts the same kwargs as the original dataclass. Pydantic v2 coerces `list` to `tuple` for `FuzzInput.args` by default, which is correct behavior. Tests must cover this coercion path.

**Note on FuzzReport.config:** The `FuzzerConfig` is serialized to a summary dict (target_path, plugin, model, iterations, etc.) rather than embedding the full config object. This avoids storing the API key in the model.

### AI Engine Integration

The AI engine (`fuzzer/ai/engine.py`) is preserved largely unchanged, with these adjustments:

1. **Vertex AI is the preferred backend.** The engine auto-detects `GOOGLE_CLOUD_PROJECT` as before. No change needed.
2. **The `anthropic` import is guarded** with a try/except. If `anthropic` is not installed, the fuzzer raises a clear error directing the user to `pip install deep-code-security[fuzz]`.
3. **Cost tracking** (`APIUsage` class) is preserved. It remains a plain class (not Pydantic) since it's internal to the AI engine and not a data-crossing boundary.
4. **Circuit breaker** (3 consecutive failures) is preserved unchanged.

### Plugin Architecture Alignment

fuzzy-wuzzy and DCS have **different plugin systems** that serve different purposes:

| Aspect | DCS Plugin (auditor) | fuzzy-wuzzy Plugin (target) |
|---|---|---|
| Purpose | Exploit generation + sandbox | Language-specific fuzz target execution |
| Interface | Protocol (runtime_checkable) | ABC (abstract base class) |
| Discovery | `import dcs_verification` | `entry_points("deep_code_security.fuzzer_plugins")` |
| Scope | Private, single implementation | Public, extensible |

These remain separate systems. The fuzzer plugin system is preserved under `fuzzer/plugins/` with the entry point group renamed from `fuzzy_wuzzy.plugins` to `deep_code_security.fuzzer_plugins`. The `PythonTargetPlugin` is registered as a built-in (no entry point needed) and as an entry point for backward compatibility during transition.

**Plugin security hardening:**
- Plugins are **lazy-loaded**: `list_plugins()` returns registered names without instantiating plugin classes. Only `get_plugin(name)` instantiates a plugin.
- A `DCS_FUZZ_ALLOWED_PLUGINS` environment variable (default: `"python"`) restricts which plugin names can be loaded. Plugins not in the allowlist are logged and skipped.
- The source package of each loaded plugin is logged for audit purposes.
- The old `fuzzy_wuzzy.plugins` entry point group is supported during transition, with a deprecation warning. It will be removed in v2.0.0 or 6 months after merge, whichever comes first.

### Configuration Merge

DCS uses `Config` class with `DCS_*` environment variables. fuzzy-wuzzy uses `FuzzerConfig` dataclass. After the merge:

```python
# shared/config.py (extended)
class Config:
    def __init__(self) -> None:
        # ... existing DCS config ...

        # Fuzzer configuration
        self.fuzz_model: str = os.environ.get("DCS_FUZZ_MODEL", "claude-sonnet-4-6")
        self.fuzz_max_iterations: int = int(os.environ.get("DCS_FUZZ_MAX_ITERATIONS", "10"))
        self.fuzz_inputs_per_iteration: int = int(os.environ.get("DCS_FUZZ_INPUTS_PER_ITER", "10"))
        self.fuzz_timeout_ms: int = int(os.environ.get("DCS_FUZZ_TIMEOUT_MS", "5000"))
        self.fuzz_max_cost_usd: float = float(os.environ.get("DCS_FUZZ_MAX_COST_USD", "5.0"))
        self.fuzz_output_dir: str = os.environ.get("DCS_FUZZ_OUTPUT_DIR", "./fuzzy-output")
        self.fuzz_consent: bool = os.environ.get("DCS_FUZZ_CONSENT", "").lower() in ("1", "true", "yes")
        self.fuzz_use_vertex: bool = bool(
            os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("CLOUD_ML_PROJECT_NUMBER")
            or os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID")
        )
        self.fuzz_gcp_project: str = (
            os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("CLOUD_ML_PROJECT_NUMBER")
            or ""
        )
        self.fuzz_gcp_region: str = os.environ.get("DCS_FUZZ_GCP_REGION", "us-east5")
```

CLI options override environment variables. This preserves fuzzy-wuzzy's behavior where the CLI constructs a `FuzzerConfig` from flags. The `FuzzerConfig` remains as an internal intermediary that the orchestrator uses, constructed from `Config` + CLI overrides.

**`FuzzerConfig` Pydantic migration:** The original `FuzzerConfig.__post_init__` performs side-effectful initialization: loading the API key from environment or config file, auto-detecting Vertex AI, and auto-detecting GCP project. In the Pydantic model, this logic moves to a `@model_validator(mode='after')` method. The `api_key` field uses `Field(default="", repr=False, exclude=True)` to prevent accidental serialization or logging. The custom `__repr__` is replaced by Pydantic's `repr=False` on sensitive fields.

**API key config file path:** The fuzzy-wuzzy config reads from `~/.config/fuzzy-wuzzy/config.toml`. After merge, the primary path is `~/.config/deep-code-security/config.toml`. The old path is checked as a fallback with a deprecation warning. File permission checks are preserved on the new path.

**`DCS_FUZZ_CONSENT` behavior:** When consent is granted via this environment variable, a warning is logged: "Consent granted via DCS_FUZZ_CONSENT environment variable. Source code will be transmitted to the Anthropic API." The DCS config loader does not read `.env` files; this is a security invariant that must be preserved.

**`tomli` fallback:** fuzzy-wuzzy includes a `tomli` fallback for Python 3.10. Since DCS requires Python 3.11+ (`requires-python = ">=3.11"`), this fallback is dead code and will be removed during migration.

### Consent Model

The consent system is extracted into `fuzzer/consent.py`:

```python
# fuzzer/consent.py
CONSENT_DIR = Path.home() / ".config" / "deep-code-security"
CONSENT_FILE = CONSENT_DIR / "consent.json"

def verify_consent(consent_flag: bool) -> None: ...
def record_consent() -> None: ...
def revoke_consent() -> None: ...
def has_stored_consent() -> bool: ...
```

**Consent scope:** The `consent` flag gates **API data transmission** (sending source code to the Anthropic API). It does NOT gate code execution -- the fuzzer executes the user's own code on the host regardless of the consent flag. This is an important distinction: the fuzzer is always executing user-provided code (the fuzz target), similar to how `pytest` executes test code. The consent model prevents the secondary action of transmitting that code to an external API.

**Migration:** On first access, if `~/.config/fuzzy-wuzzy/consent.json` exists but `~/.config/deep-code-security/consent.json` does not, the consent is copied (not moved) to the new path with an informational message suggesting manual removal of the old file. The copy uses a temporary file + rename pattern to avoid race conditions if two processes attempt migration simultaneously.

### Shared File Discovery

fuzzy-wuzzy uses `fuzzer/analyzer/signature_extractor.py` which calls `extract_targets_from_path()` to find Python files. DCS uses `shared/file_discovery.py` which respects `.gitignore` and symlink safety.

After the merge, the fuzzer's target discovery pipeline can optionally use DCS's `FileDiscovery` for finding `.py` files, but the actual function extraction (`signature_extractor.py`) remains fuzzer-specific since it needs AST-level function signature analysis that `FileDiscovery` does not provide.

The integration point is in the `PythonTargetPlugin.discover_targets()` method, which can use `FileDiscovery` for directory scanning and then apply its own extraction logic per file.

### Post-Merge Features (Architectural Hooks)

These features are **not implemented in this plan** but the architecture includes extension points:

1. **Input Minimization:** The `FuzzOrchestrator` gains a `minimize_crash(crash: FuzzResult) -> FuzzResult` method stub that returns the input unchanged. Post-merge work implements binary search / delta debugging on the args tuple.

2. **Severity Classification:** The `UniqueCrash` model includes an optional `severity: str | None = None` field. Post-merge work adds a `classify_severity(crash: UniqueCrash) -> str` function that maps exception types to severity levels (e.g., `MemoryError` -> `high`, `ValueError` -> `low`).

3. **Cross-Engine Finding Correlation:** The formatter DTOs include `analysis_mode: Literal["static", "dynamic"]` metadata. Post-merge work adds a `CorrelatedFinding` model that pairs a `RawFinding` with an `UniqueCrash` when they share a code location (same file + overlapping line ranges).

4. **Actionable Guidance for Fuzz Findings:** The `Architect` phase currently only processes `VerifiedFinding` objects. Post-merge work adds an adapter that wraps `UniqueCrash` objects into a form the `GuidanceGenerator` can process, producing `RemediationGuidance` for crash bugs.

5. **Container Backend for Fuzzer Sandbox:** Post-merge work implements the `ContainerBackend` in `execution/sandbox.py`, reusing the DCS auditor's container security policy (seccomp, no-new-privileges, cap-drop=ALL, --network=none, non-root user). This unblocks the `deep_scan_fuzz` MCP tool.

## Interfaces / Schema Changes

### New Pydantic Models

| Module | Model | Type | Description |
|---|---|---|---|
| `fuzzer.models` | `FuzzInput` | BaseModel | Single fuzz input (expression strings) |
| `fuzzer.models` | `FuzzResult` | BaseModel | Execution result for one input |
| `fuzzer.models` | `TargetInfo` | BaseModel | Fuzz target function metadata |
| `fuzzer.models` | `CoverageReport` | BaseModel | Coverage data for AI feedback |
| `fuzzer.models` | `UniqueCrash` | BaseModel | Deduplicated crash group |
| `fuzzer.models` | `FuzzReport` | BaseModel | Complete fuzz run report |
| `fuzzer.models` | `ReplayResult` | BaseModel | Outcome of replaying one crash |
| `shared.formatters.protocol` | `FuzzReportResult` | BaseModel | Formatter DTO for fuzz results |
| `shared.formatters.protocol` | `ReplayResultDTO` | BaseModel | Formatter DTO for replay results |

### New CLI Commands

| Command | Arguments | Key Options | Description |
|---|---|---|---|
| `dcs fuzz` | `<target>` | `--function` (`-F`), `--iterations`, `--model`, `--consent`, `--vertex`, `--format` (`-f`), `--output-file` (`-o`), `--output-dir` | Run AI fuzzer |
| `dcs replay` | `<corpus_dir>` | `--target`, `--timeout`, `--format`, `--output-file` | Replay crash inputs |
| `dcs corpus` | `<corpus_dir>` | `--crashes-only` | Inspect corpus |
| `dcs fuzz-plugins` | (none) | (none) | List fuzzer plugins |
| `dcs report` | `<output_dir>` | `--format` | View saved fuzz report |

### New MCP Tools

| Tool | Status | Required Params | Optional Params | Description |
|---|---|---|---|---|
| `deep_scan_fuzz` | **Deferred** (blocked on container backend) | `path`, `consent` | `functions`, `iterations`, `inputs_per_iteration`, `model`, `max_cost_usd`, `timeout_ms` | Run AI fuzzer |
| `deep_scan_fuzz_status` | **Active** | (none) | `fuzz_run_id` | Check fuzzer availability / poll fuzz run |

### New Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DCS_FUZZ_MODEL` | `claude-sonnet-4-6` | Claude model for input generation |
| `DCS_FUZZ_MAX_ITERATIONS` | `10` | Max fuzzing iterations |
| `DCS_FUZZ_INPUTS_PER_ITER` | `10` | Inputs generated per iteration |
| `DCS_FUZZ_TIMEOUT_MS` | `5000` | Per-input execution timeout |
| `DCS_FUZZ_MAX_COST_USD` | `5.0` | API cost budget |
| `DCS_FUZZ_OUTPUT_DIR` | `./fuzzy-output` | Corpus and report output directory |
| `DCS_FUZZ_CONSENT` | `false` | Pre-configured consent for CI (API transmission only) |
| `DCS_FUZZ_GCP_REGION` | `us-east5` | GCP region for Vertex AI |
| `DCS_FUZZ_ALLOWED_PLUGINS` | `python` | Comma-separated allowlist of fuzzer plugin names |
| `DCS_FUZZ_MCP_TIMEOUT` | `120` | Hard wall-clock timeout (seconds) for MCP fuzz invocations |

### Dependency Changes (`pyproject.toml`)

```toml
[project.optional-dependencies]
fuzz = [
    "anthropic>=0.25.0",
    "coverage>=7.0.0",
    "rich>=13.0.0",
]
vertex = [
    "deep-code-security[fuzz]",
    "anthropic[vertex]>=0.25.0",
    "google-auth>=2.0.0",
]
dev = [
    # ... existing dev deps ...
    "pytest-mock>=3.12.0",  # needed for fuzzer tests
]

[project.entry-points."deep_code_security.fuzzer_plugins"]
python = "deep_code_security.fuzzer.plugins.python_target:PythonTargetPlugin"
```

The `[vertex]` group extends `[fuzz]` so that `pip install deep-code-security[vertex]` installs everything needed for Vertex AI fuzzing. The `click` dependency is already shared between both projects.

## Data Migration

### Corpus Files

Existing fuzzy-wuzzy corpus directories (`./fuzzy-output/corpus/`) use a JSON schema (schema_version: 1) defined in `corpus/serialization.py`. These files are forward-compatible with the merged product because:

1. The serialization format is plain JSON with a schema version field.
2. The `CorpusManager` loads files via `load_from_file()` which deserializes `FuzzInput` + `FuzzResult` -- these will be Pydantic models after conversion but accept the same JSON keys.
3. The `add_crash()` / `add_interesting()` methods write files in the same format.

**No migration script is needed.** Existing corpus directories work as-is with the merged CLI:

```bash
# Before merge
fuzzy-wuzzy replay --target ./my_module.py ./fuzzy-output/corpus

# After merge
dcs replay --target ./my_module.py ./fuzzy-output/corpus
```

**Expression re-validation on replay:** When loading corpus files for replay (via `dcs replay` or `deserialize_fuzz_result()`), all expression strings in `FuzzInput.args` and `FuzzInput.kwargs` are re-validated through the AST allowlist (`_validate_expression()`) before execution. This closes the TOCTOU gap where tampered corpus files could bypass the response parser's validation.

### Saved Reports

Existing `report.txt`, `report.json`, and `report.sarif` files in `./fuzzy-output/` remain readable. The `dcs report` command reads them unchanged. New reports are generated through the unified formatter registry, so their structure may differ slightly (e.g., SARIF `tool.driver.name` changes from `"fuzzy-wuzzy"` to `"deep-code-security"`).

### Consent File

On first use after merge, if `~/.config/fuzzy-wuzzy/consent.json` exists and `~/.config/deep-code-security/consent.json` does not, consent is auto-migrated (copied, not moved) with a log message: `"Migrated consent from fuzzy-wuzzy to deep-code-security. You may remove ~/.config/fuzzy-wuzzy/consent.json manually."`.

## Rollout Plan

### Phase 1: Foundation (Shared Infrastructure Extensions)

**Goal:** Extend shared config, add fuzz-related env vars, extend formatter protocol.

1. Extend `shared/config.py` with `fuzz_*` attributes.
2. Add `FuzzReportResult` and `ReplayResultDTO` Pydantic models to `shared/formatters/protocol.py`.
3. Add `FuzzFormatter` protocol (separate from `Formatter`) with `format_fuzz()` and `format_replay()` methods.
4. Update `register_formatter()` to log a warning (not error) when a class lacks `format_fuzz`/`format_replay`. Add a helper `supports_fuzz(formatter) -> bool` that checks `isinstance(formatter, FuzzFormatter)`.
5. Add `anthropic`, `coverage`, `rich` to `[project.optional-dependencies] fuzz` in `pyproject.toml`.
6. Add `[vertex]` group that extends `[fuzz]` with `anthropic[vertex]` and `google-auth`.
7. Add `pytest-mock` to dev dependencies.

**Dependencies:** None. This phase modifies only shared infrastructure.

### Phase 2: Core Fuzzer Module (Code Migration + Model Conversion)

**Goal:** Copy fuzzy-wuzzy code into `src/deep_code_security/fuzzer/`, convert all models to Pydantic v2, fix all imports.

1. Create `src/deep_code_security/fuzzer/` directory structure.
2. Copy and adapt all fuzzy-wuzzy source files:
   - `models.py`: Convert all dataclasses to Pydantic BaseModel. `FuzzInput` is NOT frozen. `FuzzReport.unique_crashes` uses `@property` (not `cached_property`).
   - `orchestrator.py`: Change imports, use DCS Config. **Add `install_signal_handlers: bool = True` parameter.** When `False`, skip `_setup_signal_handlers()`.
   - `exceptions.py`: Preserve hierarchy, add `FuzzerError` as base (subclass of `Exception`, not DCS-specific).
   - `consent.py`: Extract from orchestrator, update paths. Use copy-then-rename for migration atomicity.
   - `ai/`: Copy, update imports. Guard `import anthropic` with try/except.
   - `execution/sandbox.py`: Copy, update imports. **No container backend in this plan** (see SD-01).
   - `execution/runner.py`: Copy, update imports. **Update `WORKER_MODULE` constant from `'fuzzy_wuzzy.execution._worker'` to `'deep_code_security.fuzzer.execution._worker'`.** Add `PYTHONDONTWRITEBYTECODE=1` and `PYTHONSAFEPATH=1` to the subprocess environment.
   - `execution/_worker.py`: Copy, update imports. **Add AST validation before `eval()` call** (see SD-02). Update usage string from `fuzzy_wuzzy.execution._worker` to `deep_code_security.fuzzer.execution._worker`.
   - `analyzer/`: Copy verbatim, update imports.
   - `corpus/serialization.py`: Copy, adapt to Pydantic models. **Preserve manual serialization logic** (truncation, schema_version). Do NOT replace with `model_dump()`. **Add expression re-validation in `deserialize_fuzz_result()`** before returning `FuzzInput` objects.
   - `coverage_tracking/`: Copy verbatim, update imports.
   - `plugins/registry.py`: Copy, update imports. **Change to lazy-load pattern**: `list_plugins()` returns names without instantiation; `get_plugin(name)` instantiates. **Add `DCS_FUZZ_ALLOWED_PLUGINS` check.** Log source package of each loaded plugin. Support both entry point groups with deprecation warning for old group (removal: v2.0.0 or 6 months post-merge).
   - `plugins/base.py`: Copy, convert `TargetPlugin` ABC to use Pydantic models.
   - `plugins/python_target.py`: Copy, update imports.
   - `reporting/dedup.py`: Convert `UniqueCrash` to Pydantic, update imports.
   - `replay/runner.py`: Copy, adapt `ReplayResult` to Pydantic. **Add expression re-validation** when loading corpus inputs for replay.
   - `config.py`: Convert `FuzzerConfig` to Pydantic model with `@model_validator(mode='after')`. Use `Field(default="", repr=False, exclude=True)` for `api_key`. Read config from `~/.config/deep-code-security/config.toml` with fallback to old path.
3. Delete `fuzzer/reporting/formatters.py` and `fuzzer/replay/formatters.py` (formatting moves to Phase 3).
4. Update `pyproject.toml` entry points from `fuzzy_wuzzy.plugins` to `deep_code_security.fuzzer_plugins`.
5. Ensure `__all__` is defined in every `__init__.py`.
6. Remove `tomli` fallback code (dead code on Python 3.11+).

**Dependencies:** Phase 1 (needs extended Config and protocol).

### Phase 3: Formatter Unification

**Goal:** Implement `format_fuzz()` and `format_replay()` on all four built-in formatters.

1. **TextFormatter:** Port `format_text()` from `fuzzy_wuzzy/reporting/formatters.py` and `format_replay_text()` from `fuzzy_wuzzy/replay/formatters.py`. Add both `Formatter` and `FuzzFormatter` protocol compliance.
2. **JsonFormatter:** Port `format_json()` and `format_replay_json()`.
3. **SarifFormatter:** Port `format_sarif()` and `format_replay_sarif()`, changing `tool.driver.name` to `"deep-code-security"` and adding `properties.analysis_mode: "dynamic"`.
4. **HtmlFormatter:** Implement `format_fuzz()` with crash table and details. `format_replay()` can raise `NotImplementedError` for now (or produce minimal HTML).

**Dependencies:** Phase 2 (needs Pydantic fuzz models for formatter DTOs).

### Phase 4: CLI Integration

**Goal:** Add `dcs fuzz`, `dcs replay`, `dcs corpus`, `dcs fuzz-plugins`, `dcs report` commands.

1. Add `fuzz` command to `cli.py` with all options. **Use `-F` for `--function`, `-f` for `--format`, `-o` for `--output-file`.** Rename `--output` to `--output-dir` (no short flag). Add write-path validation for `--output-dir` that rejects paths inside `src/`, `registries/`, `.git/`, and other protected directories. Instantiate `FuzzOrchestrator` with `install_signal_handlers=True`.
2. Add `replay` command with `--target`, `--timeout`, `--format`, `--output-file`.
3. Add `corpus` command with `--crashes-only`.
4. Add `fuzz-plugins` command (list available plugins).
5. Add `report` command (view saved reports by format).
6. Extend `status` command to include fuzzer availability info.
7. Apply path validation to all new commands that accept file paths.
8. All new commands use `_write_output()` for consistent output handling.
9. For `format_fuzz`/`format_replay` calls, check `supports_fuzz(formatter)` before calling. If not supported, raise a clear error.

**Dependencies:** Phase 3 (needs formatters for output).

### Phase 5: MCP Server Extension

**Goal:** Add `deep_scan_fuzz_status` tool. Register `deep_scan_fuzz` as deferred (blocked on container backend).

1. Register `deep_scan_fuzz_status` tool in `server.py` with schema and handler.
2. The `_handle_fuzz_status()` handler:
   - Checks if `anthropic` is importable.
   - Checks Vertex AI configuration.
   - Reports consent status, available plugins, and container backend availability.
   - If `fuzz_run_id` is provided, returns progress or final results for that run.
3. **Do NOT register `deep_scan_fuzz` tool.** Add a code comment with the full tool schema and handler design (preserved from the Deferred MCP tool design section above) for implementation when the container backend is ready.
4. Add a `_handle_fuzz()` stub method with the async-start/poll-status implementation pattern, gated on `container_backend_available` check. This method raises `ToolError("deep_scan_fuzz requires container-based sandboxing, which is not yet implemented")` if called.
5. Audit-log all fuzz-related tool invocations.

**Dependencies:** Phase 4 (needs fuzzer orchestrator fully integrated).

### Phase 6: Test Migration + Coverage

**Goal:** Migrate fuzzy-wuzzy tests, achieve 90%+ coverage.

Tests are written alongside Phases 2-5 (test-concurrent), not deferred to the end. Phase 6 covers cross-cutting integration tests and coverage gap-filling.

1. Copy `~/projects/fuzzy-wuzzy/tests/` to `tests/test_fuzzer/`.
2. Update all imports from `fuzzy_wuzzy` to `deep_code_security.fuzzer`.
3. Update test fixtures and conftest.
4. Add new tests for:
   - Pydantic model conversions (serialization/deserialization roundtrip, including `list -> tuple` coercion for `FuzzInput.args`).
   - Formatter `format_fuzz()` and `format_replay()` methods.
   - CLI `fuzz`, `replay`, `corpus`, `fuzz-plugins`, `report` commands.
   - MCP `deep_scan_fuzz_status` tool.
   - Consent migration from old to new path (including concurrent migration race).
   - Path validation on fuzz target and output directory (including write-path rejection).
   - `_worker.py` AST validation before `eval()` (including bypass attempts).
   - Expression re-validation on corpus replay.
   - Plugin allowlist (`DCS_FUZZ_ALLOWED_PLUGINS`) enforcement.
   - Signal handler installation is skipped when `install_signal_handlers=False`.
   - `FuzzerConfig` Pydantic model with `@model_validator` (API key loading, Vertex auto-detect).
   - Prompt injection test fixtures with adversarial docstrings and comments.
5. Add `make test-fuzzer` target to Makefile.
6. Ensure `make test` passes with 90%+ coverage (fuzzer source added to `[tool.coverage.run] source`).
7. Update `[tool.coverage.run] omit` if needed for stubs.

**Dependencies:** Phases 1-5 (all code must be in place for integration tests).

### Phase 7: Cleanup + Documentation

**Goal:** Remove dead code, update CLAUDE.md, update README.

1. Remove fuzzy-wuzzy's standalone `cli.py` entry point references.
2. Update CLAUDE.md:
   - Add fuzzer to architecture diagram.
   - Update MCP server description: "5 tools" -> "6 tools (deep_scan_fuzz deferred)".
   - Add new environment variables table.
   - Add CLI commands table.
   - Add test targets.
   - Add `_worker.py` `eval()` to Known Limitations with justification.
3. Update README.md with unified tool description.
4. Verify `make lint` and `make sast` pass.
5. Final `make test` verification.

**Dependencies:** Phase 6.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `anthropic` dependency conflicts with DCS's existing deps | Low | Medium | Declared as optional `[fuzz]` extra; isolated in `fuzzer/` module with guarded imports. |
| Pydantic v2 conversion breaks corpus serialization | Medium | Medium | Corpus files use plain JSON. Pydantic's `model_validate()` accepts dicts. Manual serialization logic preserved. Add roundtrip serialization tests including `list -> tuple` coercion. |
| Coverage threshold drops below 90% after adding fuzzer code | Medium | Low | Tests written alongside each phase (not deferred). Add fuzzer to coverage omit list temporarily if needed while tests are being migrated. |
| AI engine makes unexpected API calls during testing | Low | High | All tests mock the Anthropic client. No real API calls in unit/integration tests (established pattern from fuzzy-wuzzy). |
| Consent model migration fails on systems without old config | Low | Low | Migration is optional -- if old file doesn't exist, fresh consent is required. Copy-then-rename for atomicity. |
| MCP `deep_scan_fuzz` exposure before container backend | N/A | N/A | **Mitigated by design:** MCP tool is deferred until container backend is implemented. CLI-only exposure is acceptable because the user explicitly controls what gets executed. |
| Path validation breaks fuzzer target resolution | Medium | Medium | Ensure `DCS_ALLOWED_PATHS` includes the fuzz target's parent directory. Document this in environment variable table. |
| Two SARIF `tool.driver.name` values in existing reports | Low | Low | Old fuzzy-wuzzy reports keep `"fuzzy-wuzzy"`. New reports use `"deep-code-security"`. SARIF consumers handle this via `automationDetails.id`. |
| Fuzzer plugin entry point group rename breaks existing installs | Medium | Low | Support both `fuzzy_wuzzy.plugins` and `deep_code_security.fuzzer_plugins` during transition. Log deprecation warning for old group. Removal in v2.0.0 or 6 months. |
| `rich` dependency adds weight for users who only want SAST | Low | Low | `rich` is in `[fuzz]` optional group, not in core deps. Fuzzer logs fall back to `logging.StreamHandler` with basic formatting if rich is not installed. |
| Signal handler conflict between fuzzer and MCP server | N/A | N/A | **Mitigated by design:** `FuzzOrchestrator(install_signal_handlers=False)` for MCP invocations. CLI uses `True`. |
| `preexec_fn` deprecation in Python 3.12+ | Medium | Low | `SubprocessBackend` uses `preexec_fn=_apply_rlimits`. This is deprecated but functional through Python 3.13. Migration to `subprocess.Popen()` with `start_new_session=True` and a wrapper script is tracked as post-merge tech debt. |

## Trust Boundary Analysis

### Fuzzer Module Trust Boundaries

1. **User code -> Fuzzer subprocess:** Fuzz targets execute in subprocesses with rlimits (CPU, memory, file size, file descriptors, no forking on Linux). The fixed `_worker.py` module is the execution entry point -- no dynamic script generation. **Important:** This is rlimit-only isolation, not container isolation. The subprocess runs with the full host filesystem visible, no network isolation, and inherits the parent process's capabilities. This isolation level is acceptable for CLI usage (where the user explicitly chooses to fuzz their own code) but is NOT acceptable for MCP exposure (see SD-01). The subprocess environment includes `PYTHONDONTWRITEBYTECODE=1` and `PYTHONSAFEPATH=1` to reduce implicit import side effects.

2. **AI engine -> Response parser:** Claude's responses are parsed through strict validation (`response_parser.py`). Expression strings are validated via an AST allowlist (`_validate_expression()`) before being serialized to IPC JSON. **Additionally, `_worker.py` independently validates expressions via the same AST allowlist before calling `eval()` with restricted globals** (see SD-02). This dual-layer defense ensures that tampered corpus files or direct worker invocation cannot bypass validation.

3. **MCP client -> Fuzzer via MCP:** The `deep_scan_fuzz` MCP tool is **not registered** until the container-based sandbox backend is implemented. Only `deep_scan_fuzz_status` is available (it performs no code execution). When `deep_scan_fuzz` is eventually enabled: consent is required in every invocation, path validation prevents fuzzing arbitrary system files, cost budget defaults are conservative ($2 for MCP vs $5 for CLI), crash data in MCP responses is validated through `input_validator.py`, and the container backend is mandatory.

4. **Corpus files -> Fuzzer:** Corpus JSON files are deserialized via Pydantic `model_validate()` which rejects invalid/unexpected fields. The `load_from_file()` function checks `schema_version`. **Expression strings are re-validated through the AST allowlist** when loaded for replay, closing the TOCTOU gap between response parser validation and worker execution.

### Security Constraints Preserved from CLAUDE.md

- No `shell=True` in subprocess calls. The existing `subprocess.run()` calls in `execution/sandbox.py` use list-form arguments.
- Path validation through `mcp/path_validator.py` for all file path inputs.
- API keys are never logged (redacted via Pydantic `repr=False` on the `api_key` field).
- No `--api-key` CLI flag (prevents shell history leakage).

### Security Deviations from CLAUDE.md (Justified)

**SD-01: Fuzzer sandbox uses rlimits-only isolation, not container-based isolation.**

CLAUDE.md mandates: "All container operations enforce full security policy: seccomp + no-new-privileges + cap-drop=ALL." The fuzzer's `execution/sandbox.py` runs fuzz targets in subprocesses with rlimits, not containers. This creates a security asymmetry with the DCS auditor:

| Aspect | DCS Auditor (PoC Execution) | Fuzzer (Fuzz Target Execution) |
|---|---|---|
| Isolation | Container (Docker/Podman) | Process (rlimits only) |
| Filesystem | Read-only mount, noexec tmpfs | Full host filesystem |
| Network | --network=none | Unrestricted |
| Privileges | cap-drop=ALL, no-new-privileges | Inherits parent |
| User | Non-root (65534) | Same as parent |
| Seccomp | Custom profile | None |
| Resource Limits | Container cgroups | rlimits (unreliable on macOS) |

**Justification:** The fuzzer executes the user's own code -- code they already have on their filesystem and could run directly via `python my_module.py`. This is analogous to `pytest` executing test code. The auditor, by contrast, executes PoC scripts generated from untrusted findings. The threat model is different: the fuzzer's risk is from AI-generated *inputs* to user code, not from executing entirely untrusted code.

**Compensating controls:**
- `deep_scan_fuzz` is NOT exposed as an MCP tool until the container backend is implemented. This prevents a compromised MCP client from triggering arbitrary code execution on the host.
- CLI usage is acceptable because the user explicitly controls what gets fuzzed.
- `PYTHONSAFEPATH=1` and `PYTHONDONTWRITEBYTECODE=1` are set in the subprocess environment.
- The `_worker.py` module validates all expressions via AST allowlist before `eval()`.
- `DCS_ALLOWED_PATHS` restricts which directories the fuzzer can target.

**Resolution path:** Implement the `ContainerBackend` in `execution/sandbox.py` (listed as post-merge feature #5). Once available, make it the default for MCP invocations and unblock the `deep_scan_fuzz` tool.

**SD-02: `_worker.py` uses `eval()` with restricted globals.**

CLAUDE.md bans `eval()` in production code. The fuzzer's `_worker.py:eval_expression()` function uses `eval()` with a restricted globals dict (`__builtins__` cleared, only data-constructing names like `int`, `float`, `str`, `list`, `dict`, `tuple`, `set`, `frozenset`, `bytes`, `bytearray`, `complex`, `range`, `None`, `True`, `False` available).

**Justification:** The fuzzer must evaluate expression strings (e.g., `"[1, 2, 3]"`, `"{'key': 'value'}"`) into Python objects to pass as arguments to fuzz targets. `ast.literal_eval()` handles most cases but cannot evaluate expressions like `"range(10)"` or `"bytes(5)"`. The restricted `eval()` is a deliberate, documented exception to the CLAUDE.md rule.

**Mitigations (dual-layer defense):**
1. **Layer 1 (response_parser.py):** Before serialization to IPC JSON, expressions are validated via `_validate_expression()` which walks the AST and rejects `ast.Attribute`, `ast.Subscript` with non-constant indices, function calls to non-allowlisted names, and other dangerous node types. This blocks `.__class__.__bases__[0].__subclasses__()` chains.
2. **Layer 2 (_worker.py):** Before `eval()`, the worker independently validates the expression through the same `_validate_expression()` function (imported from a shared module or inlined). This closes the TOCTOU gap where corpus file tampering or direct worker invocation could bypass Layer 1.
3. **Restricted globals:** Even if validation is bypassed, the `eval()` call has `__builtins__` cleared and only safe constructors available.

**Implementation:** Move `_validate_expression()` to `fuzzer/ai/expression_validator.py` (shared module). Both `response_parser.py` and `_worker.py` import and call it. Remove `memoryview` from `RESTRICTED_BUILTINS` in `_worker.py` (unnecessary for data construction and provides a potential memory probing vector).

## Supply Chain Assessment

### New Dependencies

| Package | Version | Risk | Justification |
|---|---|---|---|
| `anthropic` | `>=0.25.0` | Low-Medium | Official Anthropic SDK. Optional dependency for fuzzing only. Brings transitive deps: `httpx`, `pydantic` (shared), `distro`, `jiter`, `sniffio`, `anyio`. |
| `anthropic[vertex]` | `>=0.25.0` | Low-Medium | Vertex AI support. Optional. Adds `google-auth`, `google-cloud-aiplatform`, and transitive deps (protobuf, grpcio). |
| `google-auth` | `>=2.0.0` | Low | Google's official auth library. Required for Vertex AI. Optional. |
| `coverage` | `>=7.0.0` | Low | Standard Python coverage.py. Used for coverage-guided fuzzing. Optional. |
| `rich` | `>=13.0.0` | Low | Terminal rendering. Used for verbose logging in fuzzer. Optional. |
| `pytest-mock` | `>=3.12.0` | Low | Test-only dependency. Already widely used. |

All new runtime dependencies are optional (`[fuzz]` or `[vertex]` extras). The core SAST functionality gains zero new dependencies.

**Supply chain action items:**
- Run `pip-audit` on the full `[fuzz]` and `[vertex]` dependency trees as part of Phase 1. Document any known CVEs.
- Pin `anthropic` to a specific minor version range (e.g., `>=0.25.0,<1.0.0`) to avoid unexpected transitive dependency updates.
- Add `make audit-deps` target that runs `pip-audit` on all optional dependency groups.

### Plugin Supply Chain Risk

The fuzzer plugin registry discovers plugins via `importlib.metadata.entry_points(group="deep_code_security.fuzzer_plugins")`. Any package installed in the same Python environment can register an entry point under this group. **Mitigations:**
- `DCS_FUZZ_ALLOWED_PLUGINS` allowlist restricts which plugin names can be loaded (default: `"python"`).
- Plugins are lazy-loaded: `list_plugins()` reads entry point metadata without importing or instantiating plugin code. Only `get_plugin(name)` loads the plugin.
- The source package of each loaded plugin is logged for audit purposes.

## Test Plan

### Test Command

```bash
make test
```

This runs `pytest tests/ -v --cov=src/deep_code_security --cov-report=term-missing --cov-fail-under=90 --ignore=tests/test_integration`.

### Additional Make Targets

```makefile
# Run fuzzer tests only
test-fuzzer:
	$(PYTEST) $(TESTS)/test_fuzzer -v \
		--cov=$(SRC)/fuzzer \
		--cov-report=term-missing
```

### Test Structure

```
tests/
    test_fuzzer/
        __init__.py
        conftest.py                       # Shared fixtures (mock Anthropic client, sample targets)
        test_models.py                    # Pydantic model serialization roundtrips
        test_orchestrator.py              # FuzzOrchestrator (mocked AI engine)
        test_consent.py                   # Consent management
        test_ai/
            __init__.py
            test_engine.py                # AIEngine with mocked client
            test_prompts.py               # Prompt construction
            test_response_parser.py       # Expression validation, JSON parsing
            test_context_manager.py       # Token budget
            test_expression_validator.py  # AST allowlist validation (shared module)
        test_execution/
            __init__.py
            test_sandbox.py               # SandboxManager, rlimits
            test_runner.py                # FuzzRunner, JSON IPC
            test_worker_validation.py     # _worker.py AST validation before eval()
        test_analyzer/
            __init__.py
            test_signature_extractor.py   # Function discovery
            test_source_reader.py         # Side-effect detection
        test_corpus/
            __init__.py
            test_manager.py               # CorpusManager, dedup
            test_serialization.py         # JSON roundtrip + expression re-validation
        test_coverage_tracking/
            __init__.py
            test_collector.py             # Coverage aggregation
            test_delta.py                 # DeltaTracker
        test_plugins/
            __init__.py
            test_registry.py              # Plugin discovery, allowlist, lazy loading
            test_python_target.py         # PythonTargetPlugin
        test_reporting/
            __init__.py
            test_dedup.py                 # Crash deduplication
        test_replay/
            __init__.py
            test_runner.py                # ReplayRunner + expression re-validation
    test_shared/
        test_formatters/
            test_fuzz_formatters.py       # format_fuzz() on all four formatters
            test_replay_formatters.py     # format_replay() on all four formatters
    test_mcp/
        test_fuzz_tools.py                # deep_scan_fuzz_status (deep_scan_fuzz deferred)
```

### Key Test Cases

**Model Conversion:**
- `test_fuzz_input_roundtrip` -- FuzzInput serializes and deserializes correctly.
- `test_fuzz_input_args_list_to_tuple` -- `model_validate({"args": ["a", "b"], ...})` produces a `tuple`.
- `test_fuzz_input_not_frozen` -- FuzzInput allows attribute reassignment.
- `test_fuzz_result_roundtrip` -- FuzzResult with all fields populated.
- `test_corpus_compat` -- Load existing fuzzy-wuzzy corpus JSON into Pydantic FuzzResult.
- `test_unique_crash_pydantic` -- UniqueCrash model validation.
- `test_fuzzer_config_model_validator` -- FuzzerConfig `@model_validator` loads API key, detects Vertex.
- `test_fuzzer_config_api_key_not_serialized` -- `api_key` excluded from `model_dump()` and `repr()`.

**Expression Validation (Security-Critical):**
- `test_worker_validates_before_eval` -- `_worker.py` rejects expressions with `ast.Attribute` nodes.
- `test_worker_rejects_subclass_attack` -- `eval_expression("().__class__.__bases__[0].__subclasses__()")` is rejected.
- `test_worker_rejects_import_expression` -- `eval_expression("__import__('os')")` is rejected.
- `test_corpus_replay_revalidates_expressions` -- Tampered corpus file with malicious expression is rejected on load.
- `test_direct_worker_invocation_validates` -- `_worker.py` called directly with crafted JSON validates expressions.

**Formatter Integration:**
- `test_sarif_fuzz_results` -- SARIF output from fuzz crashes validates against schema.
- `test_sarif_fuzz_tool_name` -- `tool.driver.name` is `"deep-code-security"`.
- `test_sarif_fuzz_analysis_mode` -- `properties.analysis_mode` is `"dynamic"`.
- `test_text_fuzz_output` -- Text format includes crash summary, targets, coverage.
- `test_json_fuzz_schema` -- JSON output has expected structure.
- `test_replay_sarif_only_non_fixed` -- SARIF replay output excludes fixed inputs.
- `test_formatter_without_fuzz_support` -- `supports_fuzz()` returns `False` for Formatter-only classes.

**CLI Integration:**
- `test_dcs_fuzz_requires_consent` -- `dcs fuzz` without `--consent` exits with error.
- `test_dcs_fuzz_path_validation` -- Invalid paths rejected.
- `test_dcs_fuzz_output_dir_write_validation` -- `--output-dir ./src/` rejected.
- `test_dcs_fuzz_format_sarif` -- `--format sarif` produces SARIF.
- `test_dcs_fuzz_F_flag` -- `-F func_name` correctly sets function filter.
- `test_dcs_replay_text` -- Replay produces text output.
- `test_dcs_corpus_list` -- Corpus command lists crash/interesting counts.
- `test_dcs_fuzz_plugins_list` -- Lists "python" plugin.

**MCP Integration:**
- `test_deep_scan_fuzz_not_registered` -- `deep_scan_fuzz` tool is NOT available (deferred).
- `test_deep_scan_fuzz_status` -- Returns anthropic availability, consent status, and container backend status.
- `test_fuzz_crash_data_validated` -- Crash data in MCP responses passes through `input_validator.py`.

**Plugin Security:**
- `test_plugin_allowlist_default` -- Only "python" plugin is loadable by default.
- `test_plugin_allowlist_rejects_unknown` -- Plugin not in allowlist is rejected with log warning.
- `test_plugin_lazy_loading` -- `list_plugins()` does not instantiate plugin classes.

**Signal Handler:**
- `test_orchestrator_no_signal_handlers` -- `FuzzOrchestrator(config, install_signal_handlers=False)` does not install SIGINT/SIGTERM handlers.
- `test_orchestrator_default_installs_handlers` -- Default behavior installs signal handlers.

**Consent Migration:**
- `test_consent_migration_from_old_path` -- Migrates from `~/.config/fuzzy-wuzzy/`.
- `test_consent_no_migration_if_new_exists` -- No migration if new file exists.
- `test_consent_no_migration_if_old_missing` -- No crash if old file absent.
- `test_consent_migration_atomicity` -- Uses temp file + rename.

**Prompt Injection:**
- `test_adversarial_docstring` -- Target with "Ignore all previous instructions" docstring does not alter prompt structure.
- `test_json_in_comment` -- Target with JSON-like comments does not produce spurious fuzz inputs.

## Acceptance Criteria

1. `dcs fuzz <target> --consent --iterations 1 --inputs-per-iter 3 --format json` produces valid JSON output with crash summary (or empty if no crashes). Requires `ANTHROPIC_API_KEY` or Vertex AI credentials.
2. `dcs fuzz <target> --consent --format sarif` produces SARIF 2.1.0 JSON that passes schema validation, with `tool.driver.name` = `"deep-code-security"` and `properties.analysis_mode` = `"dynamic"`.
3. `dcs replay --target <module.py> ./fuzzy-output/corpus --format text` replays saved crash inputs and reports fixed/failing status.
4. `dcs hunt <path>` continues to work identically to before the merge.
5. `dcs full-scan <path>` continues to work identically to before the merge.
6. `dcs status` includes fuzzer availability information (anthropic installed, consent status).
7. `dcs fuzz <path>` without `--consent` flag fails with a clear error message.
8. `dcs fuzz <path>` with a path outside `DCS_ALLOWED_PATHS` fails with path validation error.
9. Existing fuzzy-wuzzy corpus directories (`./fuzzy-output/corpus/`) are readable by the merged CLI without migration.
10. `make test` passes with 90%+ coverage.
11. `make lint` passes.
12. `make sast` passes (no new bandit findings).
13. The `anthropic` package is not required for SAST-only usage (`pip install deep-code-security` without `[fuzz]`).
14. All fuzzy-wuzzy models are Pydantic v2 BaseModel subclasses (no dataclasses in `fuzzer/` for data-crossing models).
15. The `_worker.py` `eval()` call is preceded by AST validation (the same `_validate_expression()` used by `response_parser.py`). This is a justified exception to the CLAUDE.md `eval()` ban, documented in SD-02.
16. The private `dcs-verification` plugin continues to work without modification.
17. `deep_scan_fuzz` MCP tool is NOT registered (deferred until container backend). Only `deep_scan_fuzz_status` is available.
18. Expression strings are re-validated on corpus replay load.
19. Plugin registry respects `DCS_FUZZ_ALLOWED_PLUGINS` allowlist.
20. `FuzzOrchestrator` does not install signal handlers when `install_signal_handlers=False`.

## Task Breakdown

### Phase 1: Foundation (Shared Infrastructure)

**Task 1.1: Extend shared/config.py**
- Modify: `src/deep_code_security/shared/config.py`
  - Add all `fuzz_*` attributes to `Config.__init__()`.
  - Add `DCS_FUZZ_*` environment variable parsing.
  - Add `DCS_FUZZ_ALLOWED_PLUGINS` (default: `"python"`).
  - Add `DCS_FUZZ_MCP_TIMEOUT` (default: `120`).

**Task 1.2: Extend formatter protocol**
- Modify: `src/deep_code_security/shared/formatters/protocol.py`
  - Add `FuzzReportResult`, `FuzzConfigSummary`, `FuzzTargetInfo`, `FuzzCrashSummary`, `UniqueCrashSummary` Pydantic models.
  - Add `ReplayResultDTO`, `ReplayResultEntry` Pydantic models.
  - Add `FuzzFormatter` protocol (separate from `Formatter`) with `format_fuzz()` and `format_replay()`.

**Task 1.3: Update formatter registry**
- Modify: `src/deep_code_security/shared/formatters/__init__.py`
  - Add `supports_fuzz(formatter) -> bool` helper that checks `isinstance(formatter, FuzzFormatter)`.
  - `register_formatter()` continues to validate only `format_hunt` and `format_full_scan`.

**Task 1.4: Update pyproject.toml**
- Modify: `pyproject.toml`
  - Add `[project.optional-dependencies] fuzz` with `anthropic>=0.25.0,<1.0.0`, `coverage`, `rich`.
  - Add `[project.optional-dependencies] vertex` that extends `[fuzz]` with `anthropic[vertex]`, `google-auth`.
  - Add `pytest-mock` to dev dependencies.
  - Add entry point `[project.entry-points."deep_code_security.fuzzer_plugins"]`.
  - Add `"fuzzer/execution/_worker.py"` to `[tool.setuptools.package-data]`.

**Task 1.5: Update Makefile**
- Modify: `Makefile`
  - Add `test-fuzzer` target.
  - Add `audit-deps` target that runs `pip-audit` on `[fuzz]` and `[vertex]` extras.

### Phase 2: Core Fuzzer Module

**Task 2.1: Create fuzzer directory structure**
- Create: `src/deep_code_security/fuzzer/__init__.py`
- Create: `src/deep_code_security/fuzzer/ai/__init__.py`
- Create: `src/deep_code_security/fuzzer/execution/__init__.py`
- Create: `src/deep_code_security/fuzzer/analyzer/__init__.py`
- Create: `src/deep_code_security/fuzzer/corpus/__init__.py`
- Create: `src/deep_code_security/fuzzer/coverage_tracking/__init__.py`
- Create: `src/deep_code_security/fuzzer/plugins/__init__.py`
- Create: `src/deep_code_security/fuzzer/reporting/__init__.py`
- Create: `src/deep_code_security/fuzzer/replay/__init__.py`

**Task 2.2: Convert and copy models**
- Create: `src/deep_code_security/fuzzer/models.py`
  - Convert `FuzzInput`, `FuzzResult`, `TargetInfo`, `CoverageReport`, `FuzzReport`, `ReplayResult` from dataclass to Pydantic BaseModel.
  - Convert `UniqueCrash` from dataclass to Pydantic BaseModel.
  - `FuzzInput` is NOT frozen.
  - `FuzzReport.unique_crashes` uses `@property` (not `cached_property`).

**Task 2.3: Copy and adapt exceptions**
- Create: `src/deep_code_security/fuzzer/exceptions.py`
  - Preserve full hierarchy: `FuzzerError` (base), `PluginError`, `ExecutionError`, `AIEngineError`, `CoverageError`, `CorpusError`, `InputValidationError`, `ConsentRequiredError`, `CircuitBreakerError`.

**Task 2.4: Extract consent module**
- Create: `src/deep_code_security/fuzzer/consent.py`
  - Extract `verify_consent()`, `record_consent()`, `revoke_consent()` from orchestrator.
  - Use `~/.config/deep-code-security/consent.json` as path.
  - Add migration logic from `~/.config/fuzzy-wuzzy/consent.json` (copy, not move; temp file + rename).

**Task 2.5: Create shared expression validator**
- Create: `src/deep_code_security/fuzzer/ai/expression_validator.py`
  - Extract `_validate_expression()` from `response_parser.py` into a shared module.
  - Both `response_parser.py` and `_worker.py` import from this module.
  - Remove `memoryview` from `RESTRICTED_BUILTINS`.

**Task 2.6: Copy AI engine**
- Create: `src/deep_code_security/fuzzer/ai/engine.py`
- Create: `src/deep_code_security/fuzzer/ai/prompts.py`
- Create: `src/deep_code_security/fuzzer/ai/response_parser.py`
- Create: `src/deep_code_security/fuzzer/ai/context_manager.py`
  - Update all imports from `fuzzy_wuzzy.*` to `deep_code_security.fuzzer.*`.
  - Guard `import anthropic` with try/except as before.
  - `response_parser.py` imports `_validate_expression` from `expression_validator.py`.

**Task 2.7: Copy execution module**
- Create: `src/deep_code_security/fuzzer/execution/sandbox.py`
- Create: `src/deep_code_security/fuzzer/execution/runner.py`
- Create: `src/deep_code_security/fuzzer/execution/_worker.py`
  - Update imports.
  - **Update `WORKER_MODULE` constant** from `'fuzzy_wuzzy.execution._worker'` to `'deep_code_security.fuzzer.execution._worker'`.
  - **Update usage string** in `_worker.py` from `fuzzy_wuzzy.execution._worker` to `deep_code_security.fuzzer.execution._worker`.
  - **Add `_validate_expression()` call before `eval()`** in `_worker.py:eval_expression()`. Import from `expression_validator.py`.
  - **Remove `memoryview` from `RESTRICTED_BUILTINS`** in `_worker.py`.
  - **Add `PYTHONDONTWRITEBYTECODE=1` and `PYTHONSAFEPATH=1`** to `_build_env()` in `runner.py`.

**Task 2.8: Copy analyzer module**
- Create: `src/deep_code_security/fuzzer/analyzer/source_reader.py`
- Create: `src/deep_code_security/fuzzer/analyzer/signature_extractor.py`
  - Update imports.

**Task 2.9: Copy corpus module**
- Create: `src/deep_code_security/fuzzer/corpus/manager.py`
- Create: `src/deep_code_security/fuzzer/corpus/serialization.py`
  - Update imports.
  - **Preserve manual serialization logic** (`serialize_fuzz_result()` with truncation, schema_version). Do NOT replace with `model_dump()`.
  - **Add expression re-validation** in `deserialize_fuzz_result()`: validate all expression strings in `FuzzInput.args` and `FuzzInput.kwargs` through `_validate_expression()` before returning.

**Task 2.10: Copy coverage tracking module**
- Create: `src/deep_code_security/fuzzer/coverage_tracking/collector.py`
- Create: `src/deep_code_security/fuzzer/coverage_tracking/delta.py`
  - Update imports.

**Task 2.11: Copy and adapt plugins module**
- Create: `src/deep_code_security/fuzzer/plugins/base.py`
  - `TargetPlugin` ABC preserved, but its methods now use Pydantic models from `fuzzer/models.py`.
- Create: `src/deep_code_security/fuzzer/plugins/registry.py`
  - Entry point group changes to `deep_code_security.fuzzer_plugins`.
  - **Lazy loading:** `list_plugins()` returns names without instantiation. `get_plugin(name)` instantiates.
  - **`DCS_FUZZ_ALLOWED_PLUGINS` allowlist check** before loading.
  - **Log source package** of each loaded plugin.
  - Fallback: also check `fuzzy_wuzzy.plugins` for backward compat with deprecation warning (removed in v2.0.0 or 6 months).
- Create: `src/deep_code_security/fuzzer/plugins/python_target.py`
  - Update imports.

**Task 2.12: Copy reporting/dedup module**
- Create: `src/deep_code_security/fuzzer/reporting/dedup.py`
  - Update imports. `UniqueCrash` is now Pydantic.
  - Export `deduplicate_crashes()` function for use by `FuzzReport.unique_crashes` property.

**Task 2.13: Copy replay runner**
- Create: `src/deep_code_security/fuzzer/replay/runner.py`
  - Update imports. `ReplayResult` is now Pydantic.
  - **Add expression re-validation** when loading corpus inputs for replay.

**Task 2.14: Adapt orchestrator**
- Create: `src/deep_code_security/fuzzer/orchestrator.py`
  - Update all imports.
  - Use `fuzzer.consent` module instead of inline consent logic.
  - Accept DCS `Config` object and extract fuzz settings.
  - Remove inline reporter calls (formatting moves to CLI/MCP layer).
  - Return `FuzzReport` Pydantic model from `run()`.
  - **Add `install_signal_handlers: bool = True` parameter to `__init__()`.** When `False`, skip `_setup_signal_handlers()`.

**Task 2.15: Create fuzzer config adapter**
- Create: `src/deep_code_security/fuzzer/config.py`
  - `FuzzerConfig` as Pydantic model.
  - **Use `@model_validator(mode='after')`** to replicate `__post_init__` behavior (API key loading, Vertex auto-detection, GCP project detection).
  - **`api_key` field uses `Field(default="", repr=False, exclude=True)`**.
  - Read config from `~/.config/deep-code-security/config.toml` with fallback to old path + deprecation warning.
  - Factory: `from_dcs_config(config: Config, **cli_overrides) -> FuzzerConfig`.

### Phase 3: Formatter Unification

**Task 3.1: Implement TextFormatter.format_fuzz() and format_replay()**
- Modify: `src/deep_code_security/shared/formatters/text.py`
  - Port logic from `fuzzy_wuzzy/reporting/formatters.py:format_text()`.
  - Port logic from `fuzzy_wuzzy/replay/formatters.py:format_replay_text()`.
  - Class now satisfies both `Formatter` and `FuzzFormatter` protocols.

**Task 3.2: Implement JsonFormatter.format_fuzz() and format_replay()**
- Modify: `src/deep_code_security/shared/formatters/json.py`
  - Port logic from `fuzzy_wuzzy/reporting/formatters.py:format_json()`.
  - Port logic from `fuzzy_wuzzy/replay/formatters.py:format_replay_json()`.

**Task 3.3: Implement SarifFormatter.format_fuzz() and format_replay()**
- Modify: `src/deep_code_security/shared/formatters/sarif.py`
  - Port logic from `fuzzy_wuzzy/reporting/formatters.py:format_sarif()`.
  - Port logic from `fuzzy_wuzzy/replay/formatters.py:format_replay_sarif()`.
  - Change `tool.driver.name` to `"deep-code-security"`.
  - Add `properties.analysis_mode: "dynamic"` to all fuzz results.

**Task 3.4: Implement HtmlFormatter.format_fuzz()**
- Modify: `src/deep_code_security/shared/formatters/html.py`
  - Add crash summary table and expandable crash details.
  - `format_replay()` can raise `NotImplementedError` (or produce minimal HTML).

### Phase 4: CLI Integration

**Task 4.1: Add fuzz command**
- Modify: `src/deep_code_security/cli.py`
  - Add `@cli.command() def fuzz(...)` with full option set.
  - **`--function` uses `-F` (capital), `--format` uses `-f`, `--output-file` uses `-o`.**
  - **`--output` is renamed to `--output-dir` (no short flag).**
  - Add write-path validation for `--output-dir` (reject `src/`, `registries/`, `.git/`).
  - Instantiate `FuzzOrchestrator` with `install_signal_handlers=True`.
  - Check `supports_fuzz(formatter)` before calling `format_fuzz()`.

**Task 4.2: Add replay command**
- Modify: `src/deep_code_security/cli.py`
  - Add `@cli.command() def replay(...)`.
  - Check `supports_fuzz(formatter)` before calling `format_replay()`.

**Task 4.3: Add corpus, fuzz-plugins, report commands**
- Modify: `src/deep_code_security/cli.py`
  - Add `@cli.command() def corpus(...)`.
  - Add `@cli.command() def fuzz_plugins(...)`.
  - Add `@cli.command() def report(...)`.

**Task 4.4: Extend status command**
- Modify: `src/deep_code_security/cli.py`
  - Add fuzzer availability info to `status` output.

### Phase 5: MCP Server Extension

**Task 5.1: Add deep_scan_fuzz_status tool**
- Modify: `src/deep_code_security/mcp/server.py`
  - Add tool registration with schema.
  - Implement `_handle_fuzz_status()`.
  - Include `container_backend_available: false` in status response.

**Task 5.2: Add deep_scan_fuzz stub (deferred)**
- Modify: `src/deep_code_security/mcp/server.py`
  - Add `_handle_fuzz()` method stub with code comment preserving the full tool schema and handler design.
  - Do NOT register the tool in the tool list.
  - Add `# TODO: Register deep_scan_fuzz when container backend is implemented (see SD-01)`.

**Task 5.3: Extend input_validator.py for fuzz data**
- Modify: `src/deep_code_security/mcp/input_validator.py`
  - Add validation functions for fuzz crash data (exception messages, tracebacks, function names).
  - These are used by `_handle_fuzz()` when it is eventually enabled, and by `_handle_fuzz_status()` if it returns any crash data from polled runs.

### Phase 6: Test Migration

**Task 6.1: Create test_fuzzer directory and migrate tests**
- Create: `tests/test_fuzzer/` (full directory tree as shown above).
- Copy and adapt all tests from `~/projects/fuzzy-wuzzy/tests/`.
- Update all imports.

**Task 6.2: Add security-critical tests**
- Add: `tests/test_fuzzer/test_ai/test_expression_validator.py` -- AST allowlist validation.
- Add: `tests/test_fuzzer/test_execution/test_worker_validation.py` -- `_worker.py` validates before `eval()`.
- Add: `tests/test_fuzzer/test_corpus/test_serialization.py` -- Expression re-validation on replay.
- Add: `tests/test_fuzzer/test_plugins/test_registry.py` -- Allowlist enforcement, lazy loading.

**Task 6.3: Add formatter tests for fuzz/replay**
- Create: `tests/test_shared/test_formatters/test_fuzz_formatters.py`
- Create: `tests/test_shared/test_formatters/test_replay_formatters.py`
- Include `supports_fuzz()` tests for Formatter-only classes.

**Task 6.4: Add CLI tests for fuzz commands**
- Create: `tests/test_fuzzer/test_cli.py`
- Include `-F` flag test, `--output-dir` write-path validation test.

**Task 6.5: Add MCP tests for fuzz tools**
- Create: `tests/test_mcp/test_fuzz_tools.py`
- Test that `deep_scan_fuzz` is NOT registered.
- Test `deep_scan_fuzz_status` responses.

**Task 6.6: Ensure coverage threshold**
- Update: `pyproject.toml` `[tool.coverage.run]` source to include fuzzer.
- Run `make test` and fix any coverage gaps.

### Phase 7: Cleanup

**Task 7.1: Update CLAUDE.md**
- Modify: `CLAUDE.md`
  - Add fuzzer to architecture diagram.
  - Update MCP server description: "5 tools" -> "6 tools (deep_scan_fuzz deferred pending container backend)".
  - Add new environment variables table.
  - Add CLI commands table.
  - Add test targets.
  - Add `_worker.py` `eval()` to Known Limitations section with justification reference to SD-02.

**Task 7.2: Final verification**
- Run: `make test`, `make lint`, `make sast`.

### Files Summary

| Action | File |
|---|---|
| Modify | `pyproject.toml` |
| Modify | `Makefile` |
| Modify | `CLAUDE.md` |
| Modify | `src/deep_code_security/shared/config.py` |
| Modify | `src/deep_code_security/shared/formatters/protocol.py` |
| Modify | `src/deep_code_security/shared/formatters/__init__.py` |
| Modify | `src/deep_code_security/shared/formatters/text.py` |
| Modify | `src/deep_code_security/shared/formatters/json.py` |
| Modify | `src/deep_code_security/shared/formatters/sarif.py` |
| Modify | `src/deep_code_security/shared/formatters/html.py` |
| Modify | `src/deep_code_security/cli.py` |
| Modify | `src/deep_code_security/mcp/server.py` |
| Modify | `src/deep_code_security/mcp/input_validator.py` |
| Create | `src/deep_code_security/fuzzer/__init__.py` |
| Create | `src/deep_code_security/fuzzer/models.py` |
| Create | `src/deep_code_security/fuzzer/orchestrator.py` |
| Create | `src/deep_code_security/fuzzer/config.py` |
| Create | `src/deep_code_security/fuzzer/exceptions.py` |
| Create | `src/deep_code_security/fuzzer/consent.py` |
| Create | `src/deep_code_security/fuzzer/ai/__init__.py` |
| Create | `src/deep_code_security/fuzzer/ai/engine.py` |
| Create | `src/deep_code_security/fuzzer/ai/prompts.py` |
| Create | `src/deep_code_security/fuzzer/ai/response_parser.py` |
| Create | `src/deep_code_security/fuzzer/ai/context_manager.py` |
| Create | `src/deep_code_security/fuzzer/ai/expression_validator.py` |
| Create | `src/deep_code_security/fuzzer/execution/__init__.py` |
| Create | `src/deep_code_security/fuzzer/execution/sandbox.py` |
| Create | `src/deep_code_security/fuzzer/execution/runner.py` |
| Create | `src/deep_code_security/fuzzer/execution/_worker.py` |
| Create | `src/deep_code_security/fuzzer/analyzer/__init__.py` |
| Create | `src/deep_code_security/fuzzer/analyzer/source_reader.py` |
| Create | `src/deep_code_security/fuzzer/analyzer/signature_extractor.py` |
| Create | `src/deep_code_security/fuzzer/corpus/__init__.py` |
| Create | `src/deep_code_security/fuzzer/corpus/manager.py` |
| Create | `src/deep_code_security/fuzzer/corpus/serialization.py` |
| Create | `src/deep_code_security/fuzzer/coverage_tracking/__init__.py` |
| Create | `src/deep_code_security/fuzzer/coverage_tracking/collector.py` |
| Create | `src/deep_code_security/fuzzer/coverage_tracking/delta.py` |
| Create | `src/deep_code_security/fuzzer/plugins/__init__.py` |
| Create | `src/deep_code_security/fuzzer/plugins/base.py` |
| Create | `src/deep_code_security/fuzzer/plugins/registry.py` |
| Create | `src/deep_code_security/fuzzer/plugins/python_target.py` |
| Create | `src/deep_code_security/fuzzer/reporting/__init__.py` |
| Create | `src/deep_code_security/fuzzer/reporting/dedup.py` |
| Create | `src/deep_code_security/fuzzer/replay/__init__.py` |
| Create | `src/deep_code_security/fuzzer/replay/runner.py` |
| Create | `tests/test_fuzzer/__init__.py` |
| Create | `tests/test_fuzzer/conftest.py` |
| Create | `tests/test_fuzzer/test_models.py` |
| Create | `tests/test_fuzzer/test_orchestrator.py` |
| Create | `tests/test_fuzzer/test_consent.py` |
| Create | `tests/test_fuzzer/test_cli.py` |
| Create | `tests/test_fuzzer/test_ai/__init__.py` |
| Create | `tests/test_fuzzer/test_ai/test_engine.py` |
| Create | `tests/test_fuzzer/test_ai/test_prompts.py` |
| Create | `tests/test_fuzzer/test_ai/test_response_parser.py` |
| Create | `tests/test_fuzzer/test_ai/test_context_manager.py` |
| Create | `tests/test_fuzzer/test_ai/test_expression_validator.py` |
| Create | `tests/test_fuzzer/test_execution/__init__.py` |
| Create | `tests/test_fuzzer/test_execution/test_sandbox.py` |
| Create | `tests/test_fuzzer/test_execution/test_runner.py` |
| Create | `tests/test_fuzzer/test_execution/test_worker_validation.py` |
| Create | `tests/test_fuzzer/test_analyzer/__init__.py` |
| Create | `tests/test_fuzzer/test_analyzer/test_signature_extractor.py` |
| Create | `tests/test_fuzzer/test_analyzer/test_source_reader.py` |
| Create | `tests/test_fuzzer/test_corpus/__init__.py` |
| Create | `tests/test_fuzzer/test_corpus/test_manager.py` |
| Create | `tests/test_fuzzer/test_corpus/test_serialization.py` |
| Create | `tests/test_fuzzer/test_coverage_tracking/__init__.py` |
| Create | `tests/test_fuzzer/test_coverage_tracking/test_collector.py` |
| Create | `tests/test_fuzzer/test_coverage_tracking/test_delta.py` |
| Create | `tests/test_fuzzer/test_plugins/__init__.py` |
| Create | `tests/test_fuzzer/test_plugins/test_registry.py` |
| Create | `tests/test_fuzzer/test_plugins/test_python_target.py` |
| Create | `tests/test_fuzzer/test_reporting/__init__.py` |
| Create | `tests/test_fuzzer/test_reporting/test_dedup.py` |
| Create | `tests/test_fuzzer/test_replay/__init__.py` |
| Create | `tests/test_fuzzer/test_replay/test_runner.py` |
| Create | `tests/test_shared/test_formatters/test_fuzz_formatters.py` |
| Create | `tests/test_shared/test_formatters/test_replay_formatters.py` |
| Create | `tests/test_mcp/test_fuzz_tools.py` |

No files are deleted from the existing DCS codebase. The fuzzy-wuzzy standalone project at `~/projects/fuzzy-wuzzy/` is not modified.

## Context Alignment

### CLAUDE.md Patterns Followed

- **Pydantic v2 for all data-crossing models:** All fuzzy-wuzzy dataclasses are converted to Pydantic BaseModel. `FuzzInput`, `FuzzResult`, `TargetInfo`, `CoverageReport`, `UniqueCrash`, `FuzzReport`, `ReplayResult` all become Pydantic models.
- **Type hints on all public functions:** All adapted code maintains type hints. New code follows the same pattern.
- **`__all__` in `__init__.py` files:** Every new `__init__.py` defines `__all__`.
- **pathlib.Path over os.path:** New code uses `Path`. Migrated code is updated where practical.
- **No mutable default arguments:** Pydantic models use `Field(default_factory=list)`.
- **models.py per phase:** The fuzzer phase follows this with `fuzzer/models.py`.
- **orchestrator.py per phase:** The fuzzer phase follows this with `fuzzer/orchestrator.py`.
- **Security rules:** No `shell=True` or `yaml.load()` calls. The fuzzer's `_worker.py` uses `eval()` with restricted globals -- this is a **justified deviation** from the CLAUDE.md `eval()` ban, documented in Security Deviation SD-02 with dual-layer defense (AST validation in both `response_parser.py` and `_worker.py`).
- **All file paths validated through path_validator.py:** Fuzz target paths and output directories are validated against `DCS_ALLOWED_PATHS`. Write paths additionally reject protected directories.
- **`mcp/input_validator.py` validates all external data in MCP responses:** Fuzz crash data (exception messages, tracebacks, function names -- all derived from executing untrusted code) passes through `input_validator.py` before inclusion in MCP tool responses.
- **90%+ test coverage:** Comprehensive test migration and new tests for integration points, written alongside each phase.
- **MCP server tool count:** Updated from 5 to 6 active tools (deep_scan_fuzz deferred). CLAUDE.md Task 7.1 explicitly updates this.

### Prior Plans This Relates To

- **`plans/deep-code-security.md` (APPROVED):** This plan extends the approved architecture with a new `fuzzer/` phase. The three-phase pipeline (Hunter -> Auditor -> Architect) is unchanged. The fuzzer is a parallel analysis mode, not a replacement or modification of the existing pipeline.
- **`plans/output-formats.md` (APPROVED):** This plan builds on the formatter registry architecture. The `Formatter` protocol is **not modified** -- a separate `FuzzFormatter` protocol is introduced for fuzz/replay output methods. The registry pattern (`register_formatter`, `get_formatter`) is reused without modification. The SARIF 2.1.0 implementation is extended (not duplicated) to handle fuzz results.

### Historical Alignment Notes

1. **`format_hunt()` `target_path` parameter:** The output-formats plan initially deferred including `target_path` in formatter method signatures. However, the implemented code in `shared/formatters/protocol.py` already includes `target_path: str = ""` as a parameter on both `format_hunt()` and `format_full_scan()`. This plan's `FuzzFormatter` methods follow the same signature pattern. This is consistent with the codebase as-implemented, not a revision of the output-formats plan.

2. **`Formatter` protocol is not extended.** The output-formats plan defined `Formatter` with exactly two methods. This plan does NOT add methods to `Formatter`. Instead, a separate `FuzzFormatter` protocol is introduced. This preserves structural subtyping for existing `Formatter` implementors.

### Deviations from Established Patterns

1. **`TargetPlugin` remains an ABC, not a Protocol.** DCS uses `Protocol` for `ExploitGeneratorProtocol` and `SandboxProvider`. fuzzy-wuzzy uses `ABC` for `TargetPlugin`. Rationale: `TargetPlugin` is meant to be explicitly subclassed by third-party plugins (they `class MyPlugin(TargetPlugin)`). A Protocol would not enforce this inheritance contract. The ABC pattern is appropriate for a public extension point where method signatures must be strictly adhered to.

2. **Consent requirement for MCP fuzz tool.** No other DCS MCP tool requires a consent parameter. Rationale: The fuzz tool sends source code to an external API (Anthropic/Vertex), which is a fundamentally different trust model than local tree-sitter parsing. Making consent explicit in every MCP call prevents an agent from accidentally transmitting code without user authorization.

3. **`anthropic` as optional dependency.** DCS's existing dependencies are all local-only (tree-sitter, pydantic, etc.). Adding a cloud API client as a dependency is a pattern change. Rationale: It is declared as an optional `[fuzz]` extra, so the core SAST tool gains zero new dependencies. Users who never fuzz never install `anthropic`.

4. **`rich` as optional dependency.** DCS uses plain `click.echo()` for all output. fuzzy-wuzzy uses `rich.logging.RichHandler`. Rationale: `rich` is only imported in the fuzzer's `_setup_logging()` function with a try/except fallback to `logging.StreamHandler` with basic formatting. It is in the `[fuzz]` optional group. The core DCS code never imports or uses `rich`.

5. **FuzzerConfig as Pydantic model (not plain class like DCS Config).** DCS `Config` is a plain class reading env vars. The fuzzer's `FuzzerConfig` is a Pydantic model. Rationale: `FuzzerConfig` crosses the data boundary between CLI -> orchestrator -> AI engine. Per CLAUDE.md, data-crossing models must be Pydantic. DCS `Config` does not cross data boundaries (it's a singleton used within the process). Refactoring `Config` to Pydantic is out of scope for this plan.

6. **Fuzzer sandbox uses rlimits-only isolation (SD-01).** See the Security Deviations section for full rationale. The `deep_scan_fuzz` MCP tool is deferred until container-based sandboxing is available.

7. **`_worker.py` uses `eval()` with restricted globals (SD-02).** See the Security Deviations section for full rationale. Dual-layer AST validation mitigates the risk.

<!-- Context Metadata
discovered_at: 2026-03-14T00:00:00Z
claude_md_exists: true
recent_plans_consulted: plans/output-formats.md, plans/deep-code-security.md
archived_plans_consulted: none (previously referenced plans/archive/output-formats/output-formats.feasibility.md which was not accessible at planning time)
review_artifacts_addressed:
  - plans/merge-fuzzy-wuzzy.redteam.md (CRITICAL-01, CRITICAL-02, MAJOR-01 through MAJOR-06, Minor-01 through Minor-06, Info-01 through Info-03)
  - plans/merge-fuzzy-wuzzy.review.md (all required edits, all optional suggestions)
  - plans/merge-fuzzy-wuzzy.feasibility.md (C1, C2, M1 through M7, m1 through m7)
-->
