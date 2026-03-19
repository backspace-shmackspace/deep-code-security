# Plan: Semgrep Scanner Backend

## Status: DRAFT (revised)

## Context

**Problem:** The custom tree-sitter taint engine in deep-code-security has fundamental detection-rate limitations. It performs intraprocedural taint tracking only, yielding ~10-25% detection on real-world injection vulnerabilities. The tree-sitter query registries are brittle (aliased imports, fully-qualified names, and class attribute access are all blind spots), and each new language or CWE category requires days of handcrafted tree-sitter query development and per-language AST node type mappings. Recent C language and conditional-assignment-sanitizer work demonstrated the compounding cost: every enhancement to the taint engine must be implemented separately for each language's AST structure.

Semgrep is a mature, open-source static analysis engine that provides:
- Battle-tested rule libraries covering 4,000+ rules across 30+ languages.
- A pattern-matching DSL far more expressive than tree-sitter s-expression queries, resolving the aliased-import, fully-qualified-name, and class-attribute blind spots that plague tree-sitter queries.
- Intraprocedural taint tracking in Semgrep OSS (same scope as the existing tree-sitter engine -- this is parity, not an upgrade in taint depth).
- JSON output that can be normalized into the existing RawFinding model.
- Multi-language support without per-language AST node type mappings.

**Scope of improvement:** Semgrep OSS provides the same intraprocedural taint scope as the existing tree-sitter engine. The improvement is in **pattern matching expressiveness**, not taint depth. Specifically, Semgrep resolves the tree-sitter query brittleness limitation documented in CLAUDE.md (Known Limitation #2): aliased imports (`req = request; req.form`), fully-qualified names (`flask.request.form`), and class attributes (`self.request.form`) are all matched by Semgrep's pattern DSL but missed by tree-sitter s-expression queries. This reduces false negatives from pattern-matching gaps, not from deeper taint analysis.

**Semgrep OSS vs. Semgrep Pro -- critical distinction:** Semgrep OSS (LGPL-2.1) provides intraprocedural taint tracking and reports match locations in JSON output. However, the `extra.dataflow_trace` field (containing `taint_source`, `intermediate_vars`, `taint_sink`) is a **Semgrep Pro / AppSec Platform feature** and is NOT available in OSS output. This plan targets Semgrep OSS only. The normalization pipeline constructs Source, Sink, and TaintPath objects from rule metadata and metavariable bindings in the OSS output -- not from `dataflow_trace`. See the Normalization Strategy section below for details.

**Current state:** The Hunter phase consists of five tightly-coupled modules:
- `hunter/parser.py` -- tree-sitter grammar loading and file parsing
- `hunter/registry.py` -- YAML source/sink registry with compiled tree-sitter queries
- `hunter/source_sink_finder.py` -- tree-sitter query execution against ASTs
- `hunter/taint_tracker.py` -- intraprocedural worklist taint propagation (1,100 lines, three language-specific code paths)
- `hunter/orchestrator.py` -- coordinates parse -> find -> track -> paginate

The Auditor (sandbox verification, confidence scoring), Architect (remediation guidance), Bridge (SAST-to-Fuzz pipeline), and Fuzzer phases all consume `RawFinding[]` and must continue working unchanged.

**Constraints:**
- Semgrep OSS (LGPL-2.1) is free but provides only intraprocedural taint and does not emit dataflow traces in JSON output. Semgrep Pro provides interprocedural taint and dataflow traces but requires a commercial license.
- The existing tree-sitter engine should be retained as a fallback for environments where Semgrep is not installed (e.g., CI with no `semgrep` binary).
- Semgrep is invoked as a subprocess (`semgrep --config ... --json`), not as a Python library -- there is no stable Python API.
- The MCP server runs natively (not containerized), so Semgrep must be installed on the host.
- The `.dcs-suppress.yaml` suppression system operates on RawFinding objects and must continue working regardless of the scanner backend.
- All CLI and MCP interfaces must remain unchanged.

**Key architectural decision -- Backend Selection Strategy:**

| Strategy | Pros | Cons | Recommendation |
|----------|------|------|---------------|
| Full replacement | Simpler codebase, no maintenance of tree-sitter engine | Breaks environments without Semgrep installed; loses conditional-assignment-sanitizer work | Reject |
| Semgrep-primary with tree-sitter fallback | Better pattern matching when Semgrep available; graceful degradation; reduces per-language maintenance | Two code paths to maintain; must keep tree-sitter code working | **Accept** |
| Tree-sitter primary, Semgrep optional augmentation | Lowest risk to existing tests | Misses the point; Semgrep pattern matching resolves the query brittleness that generates false negatives | Reject |

**Recommendation:** Introduce a `ScannerBackend` abstraction in the Hunter orchestrator. The default backend is `SemgrepBackend` when the `semgrep` binary is found on `$PATH`; otherwise, the existing `TreeSitterBackend` is used. The backend selection is logged and reported in `ScanStats`. Users can force a specific backend via the `DCS_SCANNER_BACKEND` environment variable (`semgrep`, `treesitter`, or `auto`).

## Goals

1. **Wrap Semgrep as the primary scanner backend** for finding generation, replacing the custom tree-sitter taint engine as the default when Semgrep is available.
2. **Normalize Semgrep OSS JSON output into existing RawFinding/Source/Sink/TaintPath Pydantic models** using rule metadata and metavariable bindings (not `dataflow_trace`, which is Pro-only).
3. **Retain the tree-sitter engine as a fallback** for environments without Semgrep installed.
4. **Write Semgrep rules** that cover the same CWE categories currently defined in the YAML registries (Python, Go, C), plus additional rules enabled by Semgrep's superior pattern matching (aliased imports, class attributes, chained calls).
5. **Maintain all existing interfaces** (CLI, MCP, suppressions, output formats) without changes.
6. **Maintain or improve the existing test suite** -- 90%+ coverage.

## Non-Goals

1. **Requiring Semgrep Pro / commercial license** -- this plan uses Semgrep OSS only. The `dataflow_trace` feature (Pro-only) is not used. Rich dataflow trace normalization is documented as a future enhancement contingent on Semgrep Pro evaluation (same as our v1.1 interprocedural tracking deferral).
2. **Removing tree-sitter from the project** -- tree-sitter is retained as a fallback and continues to be used by the Architect's impact_analyzer and the Fuzzer's signature_extractor.
3. **Modifying the Auditor, Architect, Bridge, or Fuzzer phases** -- these consume RawFinding[] and must continue working unchanged.
4. **Adding new languages beyond Python, Go, and C** -- Semgrep supports them, but language additions are out of scope for this plan.
5. **Changing the confidence scoring model** -- the existing weighted model (taint completeness 45%, sanitizer 25%, CWE baseline 20%, exploit bonus 10%) continues to apply. The implications of always-synthetic taint paths from Semgrep OSS are documented in the Confidence Scoring Adaptation section.
6. **Running Semgrep in a container** -- it runs on the host alongside the MCP server.

## Assumptions

1. Semgrep OSS (`semgrep` CLI, version >= 1.50.0, < 2.0.0) can be installed via `pip install semgrep` or system package manager. The Semgrep binary is on `$PATH`.
2. Semgrep's JSON output format for OSS mode (the `results` array with `check_id`, `path`, `start`, `end`, `extra.message`, `extra.severity`, `extra.metadata`, `extra.metavars`) is stable within the 1.x version range.
3. Semgrep rule files (`.yaml`) can be bundled in the project at `registries/semgrep/` without licensing issues (user-authored rules under MIT).
4. Semgrep's taint mode (`pattern-sources`, `pattern-sinks`, `pattern-sanitizers`) provides at least equivalent intraprocedural detection coverage to the custom tree-sitter engine. However, the OSS JSON output does NOT include `dataflow_trace` -- only the match location and metavariable bindings are available.
5. The Semgrep subprocess completes within `DCS_SEMGREP_TIMEOUT` seconds (default: 120s).
6. Environments without Semgrep installed will continue to use the tree-sitter backend with existing detection rates.

## Proposed Design

### Architecture Overview

```
HunterOrchestrator.scan()
    |
    v
ScannerBackend (protocol)
    |
    +-- SemgrepBackend (default when `semgrep` on $PATH)
    |       invokes: semgrep --config registries/semgrep/ --json --metrics=off
    |                        --no-git-ignore --timeout <t> --max-target-bytes <b>
    |                        <target_path>
    |       normalizes: Semgrep OSS JSON -> RawFinding[] (via rule metadata + metavars)
    |       post-filters: results to discovered_files only
    |
    +-- TreeSitterBackend (fallback)
            wraps: existing parser.py + registry.py + source_sink_finder.py + taint_tracker.py
            output: RawFinding[] (unchanged)
    |
    v
RawFinding[] -> suppressions -> dedup -> sort -> paginate -> return
```

### Component Design

#### 1. `ScannerBackend` Protocol (`hunter/scanner_backend.py`)

A `typing.Protocol` defining the contract for scanner backends:

```python
from typing import Protocol

class ScannerBackend(Protocol):
    """Protocol for scanner backends that produce RawFinding lists."""

    name: str  # "semgrep" or "treesitter"

    def scan_files(
        self,
        target_path: Path,
        discovered_files: list[DiscoveredFile],
        severity_threshold: str,
    ) -> BackendResult:
        """Scan files and return raw findings.

        Args:
            target_path: Root of the target codebase.
            discovered_files: Pre-filtered list of files to scan.
            severity_threshold: Minimum severity to include.

        Returns:
            BackendResult containing findings, source/sink counts, and diagnostics.
        """
        ...

    @classmethod
    def is_available(cls) -> bool:
        """Check if this backend's dependencies are available."""
        ...
```

`BackendResult` is a Pydantic model (for field validation consistency with the rest of the codebase):

```python
class BackendResult(BaseModel):
    """Result from a scanner backend scan."""

    findings: list[RawFinding] = Field(default_factory=list)
    sources_found: int = Field(default=0, ge=0)
    sinks_found: int = Field(default=0, ge=0)
    taint_paths_found: int = Field(default=0, ge=0)
    backend_name: str = Field(...)
    diagnostics: list[str] = Field(default_factory=list)

    model_config = {"frozen": True}
```

#### 2. `SemgrepBackend` (`hunter/semgrep_backend.py`)

The core new module. Responsibilities:

1. **Availability check:** Verify `semgrep` binary is on `$PATH` via `shutil.which("semgrep")`. Parse `semgrep --version` output and warn if the version is outside the tested range (>= 1.50.0, < 2.0.0).
2. **Rule resolution:** Point Semgrep at the DCS rule directory (`registries/semgrep/`), not the public Semgrep registry. This ensures deterministic, version-controlled rules. Validate at `is_available()` time that the rules directory contains at least one `.yaml` file.
3. **Subprocess invocation:** Run `semgrep --config <rules_dir> --json --metrics=off --no-git-ignore --timeout <timeout> --max-target-bytes <max_bytes> <target_path>` with list-form arguments (never `shell=True`).
4. **Output parsing:** Parse Semgrep's JSON output (the `results` array).
5. **Post-filtering:** Filter Semgrep results to include only files present in the `discovered_files` list. This ensures `DCS_MAX_FILES` is respected and language filters are applied consistently. Semgrep may scan more files than `discovered_files` contains (since it does its own file discovery), but post-filtering ensures only DCS-approved files appear in findings. Log a diagnostic if findings were filtered out.
6. **Normalization:** Convert each Semgrep OSS result into a `RawFinding` using the normalization strategy described below (rule metadata + metavariable bindings, NOT `dataflow_trace`).
7. **Error handling:** If Semgrep exits non-zero, log the error and return an empty `BackendResult` with diagnostics. Do not crash the scan. If the `results` array is empty AND the rules directory contains rule files, log a warning to help distinguish "clean codebase" from "misconfigured rules."
8. **Timeout:** Enforce `DCS_SEMGREP_TIMEOUT` (default: 120s) on the subprocess.

**Normalization Strategy (Semgrep OSS -- no `dataflow_trace`):**

Semgrep OSS taint-mode output provides the following for each match:

```json
{
  "check_id": "dcs.python.cwe-89.sql-injection-string-concat",
  "path": "app.py",
  "start": {"line": 42, "col": 8},
  "end": {"line": 42, "col": 55},
  "extra": {
    "message": "User input from request.form flows to SQL query via string concatenation.",
    "severity": "ERROR",
    "metadata": {
      "cwe": ["CWE-89: SQL Injection"],
      "source_category": "web_input",
      "source_function": "request.form",
      "sink_category": "sql_injection",
      "sink_function": "cursor.execute",
      "dcs_severity": "critical"
    },
    "metavars": {
      "$SOURCE": {
        "start": {"line": 40, "col": 12, "offset": 380},
        "end": {"line": 40, "col": 32, "offset": 400},
        "abstract_content": "request.form['id']"
      }
    }
  }
}
```

The normalizer constructs `RawFinding` objects as follows:

- **Source:** Constructed from rule metadata (`metadata.source_category`, `metadata.source_function`) and the metavariable binding for `$SOURCE` (if present in `extra.metavars`). If `$SOURCE` metavar is present, its `start.line` and `start.col` provide the source location. If no `$SOURCE` metavar, the source location is set to the match location (same as the sink -- indicating a direct pattern match without separable source/sink positions).
- **Sink:** Constructed from the match location (`start.line`, `start.col`) and rule metadata (`metadata.sink_category`, `metadata.sink_function`, `metadata.cwe`).
- **TaintPath:** A synthetic two-step path is always constructed (source step + sink step). This is an inherent limitation of Semgrep OSS, which does not expose intermediate taint propagation steps. The `sanitized` flag is always `False` because Semgrep taint mode only reports unsanitized paths (it filters sanitized paths internally rather than reporting them with a flag).
- **vulnerability_class:** From the rule's `metadata.cwe` field (first entry).
- **severity:** Mapped from `metadata.dcs_severity` (preferred) or Semgrep severity (`ERROR` -> `critical`, `WARNING` -> `high`, `INFO` -> `medium`).
- **raw_confidence:** Computed using the same heuristic as `HunterOrchestrator._compute_raw_confidence()`.

**Why no `dataflow_trace`:** The `extra.dataflow_trace` field (containing `taint_source`, `intermediate_vars`, `taint_sink`) is a Semgrep Pro / AppSec Platform feature. It is NOT emitted by Semgrep OSS. The normalization pipeline is designed to work entirely from OSS output fields. If Semgrep Pro is adopted in the future, the normalizer can be extended to extract richer taint paths from `dataflow_trace`, but that is explicitly out of scope for this plan.

#### 3. `TreeSitterBackend` (`hunter/treesitter_backend.py`)

Wraps the existing tree-sitter pipeline as a `ScannerBackend`. This is a thin adapter that calls the existing `parser.py`, `registry.py`, `source_sink_finder.py`, and `taint_tracker.py` modules. The existing code is not modified -- the adapter simply calls it and packages results as a `BackendResult`.

#### 4. Semgrep Rule Files (`registries/semgrep/`)

Custom DCS rules organized by language and CWE:

```
registries/semgrep/
    python/
        cwe-78-command-injection.yaml
        cwe-89-sql-injection.yaml
        cwe-94-code-execution.yaml
        cwe-22-path-traversal.yaml
    go/
        cwe-78-command-injection.yaml
        cwe-89-sql-injection.yaml
        cwe-22-path-traversal.yaml
    c/
        cwe-78-command-injection.yaml
        cwe-119-memory-corruption.yaml
        cwe-120-buffer-overflow.yaml
        cwe-134-format-string.yaml
        cwe-190-integer-overflow.yaml
        cwe-676-dangerous-function.yaml
```

Each rule file uses Semgrep taint mode with `metadata` fields for DCS normalization. Correct DSL syntax is used throughout -- multiple alternative sources/sinks use separate list entries under `pattern-sources`/`pattern-sinks` (OR semantics), not `patterns` (AND semantics).

Example rule (validated against `semgrep --validate`):

```yaml
rules:
  - id: dcs.python.cwe-89.sql-injection-string-concat
    message: >
      User input from $SOURCE flows to SQL query via string concatenation.
      Use parameterized queries instead.
    severity: ERROR
    languages: [python]
    mode: taint
    metadata:
      cwe:
        - "CWE-89: SQL Injection"
      source_category: web_input
      source_function: request.form
      sink_category: sql_injection
      sink_function: cursor.execute
      dcs_severity: critical
    pattern-sources:
      - pattern: request.form
      - pattern: request.args
      - pattern: request.json
      - pattern: request.data
      - pattern: request.values
    pattern-sinks:
      - pattern: $CURSOR.execute($QUERY, ...)
      - pattern: $CURSOR.executemany($QUERY, ...)
    pattern-sanitizers:
      - pattern: $CURSOR.execute($QUERY, ($PARAMS, ...))
```

**DSL syntax notes (addressing red team finding F-02):**
- `pattern-sources` is a list of pattern entries. Each entry is an OR alternative -- Semgrep matches if ANY source pattern matches. Listing multiple patterns as separate entries is the correct syntax for OR semantics. The original draft incorrectly used `patterns:` (AND combinator) inside `pattern-sources`.
- `pattern-sanitizers` uses structural pattern matching. The parameterized query sanitizer `$CURSOR.execute($QUERY, ($PARAMS, ...))` matches calls where the second argument is a tuple (parameterized query), which Semgrep recognizes as safe. The original draft used an invalid `where:` / `type:` constraint that does not exist in the Semgrep DSL.
- All rule files MUST pass `semgrep --validate --config <file>` before merge. This is enforced in the test plan and CI.

**Sanitizer rules for C conditional bounds-checks:**

The C rules (CWE-119, CWE-120, CWE-190) include `pattern-sanitizers` that cover the conditional-assignment patterns recognized by the tree-sitter engine's conditional-assignment-sanitizer:

```yaml
# Example: CWE-120 buffer overflow sanitizer for conditional bounds-check
pattern-sanitizers:
  # if (n > max) n = max;
  - pattern: |
      if ($N > $MAX) $N = $MAX;
  # Ternary clamp: n = (n > max) ? max : n;
  - pattern: |
      $N = ($N > $MAX) ? $MAX : $N;
```

These cover the two patterns the tree-sitter engine recognizes. The tree-sitter engine also recognizes patterns the Semgrep rules do not (macro-based clamps, early-return guards), but those are already documented as out-of-scope in CLAUDE.md Known Limitation #10.

**Advantages over tree-sitter queries:**
- Semgrep's `pattern: request.form` matches `flask.request.form`, `self.request.form`, `req = request; req.form`, and `from flask import request; request.form` -- all of which the tree-sitter queries miss.
- Taint mode with `pattern-sources` and `pattern-sinks` handles multi-step flows within a function automatically.
- Sanitizer patterns can match structural patterns, not just function names.

#### 5. Modified `HunterOrchestrator` (`hunter/orchestrator.py`)

The orchestrator gains a `_backend` attribute selected at init time:

```python
class HunterOrchestrator:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or get_config()
        self._backend = _select_backend(self.config)
        # ... rest unchanged
```

The `scan()` method delegates file scanning to `self._backend.scan_files()` instead of the inline parse -> find_sources -> find_sinks -> taint_track pipeline. The deduplication, suppression, severity filtering, sorting, and pagination logic remain unchanged.

The `_compute_raw_confidence()` method is moved to a shared location so both backends can use it.

**Backend selection failure mode:** When `DCS_SCANNER_BACKEND=semgrep` is set and Semgrep is not available, `_select_backend()` raises `RuntimeError` at `HunterOrchestrator.__init__()` time with a clear error message. The MCP server catches this during `deep_scan_hunt` invocation and returns `ToolError(retryable=False)` with the message "Semgrep backend requested but semgrep binary not found on $PATH." The server does NOT fail at startup -- other tools (status, verify, remediate) remain functional.

#### 6. Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DCS_SCANNER_BACKEND` | `auto` | Scanner backend: `semgrep`, `treesitter`, or `auto` (prefer semgrep) |
| `DCS_SEMGREP_TIMEOUT` | `120` | Maximum seconds for Semgrep subprocess execution |
| `DCS_SEMGREP_RULES_PATH` | `<DCS_REGISTRY_PATH>/semgrep` | Path to DCS Semgrep rule files (see validation below) |

#### 7. Confidence Scoring Adaptation

The confidence scoring model is unchanged in structure. The adaptation accounts for the fact that Semgrep OSS produces synthetic two-step taint paths (no `dataflow_trace`).

**Taint completeness scoring with Semgrep OSS:**

All Semgrep OSS findings produce a synthetic two-step `TaintPath` (source step + sink step). This means:

| Backend | TaintPath.steps | Taint completeness score | Notes |
|---------|-----------------|--------------------------|-------|
| Semgrep OSS (with `$SOURCE` metavar) | 2 steps (source + sink) | 50 (partial) | Source location from metavar binding |
| Semgrep OSS (no `$SOURCE` metavar) | 2 steps (synthetic) | 50 (partial) | Source location = match location |
| Tree-sitter (full taint path) | 3+ steps | 100 (full path) | Includes intermediate assignments |
| Tree-sitter (partial path) | 2 steps | 50 (partial) | Same as Semgrep OSS |

This means Semgrep OSS findings will typically score lower on taint completeness (50) than tree-sitter findings with full taint paths (100). However, Semgrep OSS compensates by detecting more findings (due to better pattern matching), and the sanitizer score is always 100 (no sanitizer) because Semgrep taint mode filters sanitized paths rather than reporting them. The net effect on composite confidence varies by finding.

**Sanitizer scoring asymmetry between backends:**

The two backends handle sanitizers fundamentally differently:

| Backend | Sanitizer behavior | `TaintPath.sanitized` | Sanitizer score |
|---------|-------------------|----------------------|-----------------|
| Tree-sitter | Reports all findings, flags sanitized paths with `sanitized=True` | `True` when sanitizer detected | 0 (sanitized) or 100 (not sanitized) |
| Semgrep OSS | Filters sanitized paths internally; only reports unsanitized paths | Always `False` (sanitized paths are not reported) | Always 100 (only unsanitized paths survive) |

This asymmetry is correct behavior, not a bug: Semgrep produces fewer findings (pre-filtered by sanitizers) with higher average confidence, while tree-sitter produces more findings with explicit sanitizer annotations and lower average confidence for sanitized paths. Both are valid. The plan does NOT attempt to force symmetric confidence scoring between backends.

**Future enhancement (Semgrep Pro):** If Semgrep Pro is adopted, the normalizer can extract `dataflow_trace.intermediate_vars` to build multi-step taint paths, which would yield taint completeness scores of 100 (full path). This is deferred to the Semgrep Pro evaluation stage.

### Integration Points (Unchanged)

The following modules consume RawFinding[] and require NO modifications:

| Module | Uses | Change Required |
|--------|------|-----------------|
| `auditor/orchestrator.py` | RawFinding[] | None |
| `auditor/confidence.py` | RawFinding.taint_path | None (steps populated by backend) |
| `auditor/exploit_generator.py` | RawFinding.source, .sink | None |
| `architect/orchestrator.py` | VerifiedFinding[] | None |
| `architect/guidance_generator.py` | VerifiedFinding | None |
| `bridge/resolver.py` | RawFinding[] | None |
| `bridge/orchestrator.py` | RawFinding[] | None |
| `shared/suppressions.py` | RawFinding.sink.cwe, .sink.file, .sink.line | None |
| `mcp/server.py` | RawFinding[], ScanStats | ScanStats gets `scanner_backend` field |
| `mcp/input_validator.py` | RawFinding fields | None |
| `cli.py` | HunterOrchestrator.scan() | None (returns same signature) |
| `shared/formatters/` | RawFinding[], ScanStats | None |

## Interfaces / Schema Changes

### Modified Models

**`hunter/models.py` -- ScanStats:**
```python
class ScanStats(BaseModel):
    # ... existing fields unchanged ...
    scanner_backend: str = Field(
        default="treesitter",
        description="Scanner backend used: 'semgrep' or 'treesitter'",
    )
```

This is an additive, backward-compatible change. Existing consumers that do not read `scanner_backend` are unaffected.

### New Models

**`hunter/scanner_backend.py` -- BackendResult:**
```python
class BackendResult(BaseModel):
    """Result from a scanner backend scan."""

    findings: list[RawFinding] = Field(default_factory=list)
    sources_found: int = Field(default=0, ge=0)
    sinks_found: int = Field(default=0, ge=0)
    taint_paths_found: int = Field(default=0, ge=0)
    backend_name: str = Field(...)
    diagnostics: list[str] = Field(default_factory=list)

    model_config = {"frozen": True}
```

### CLI Changes

None. The `dcs hunt`, `dcs full-scan`, and `dcs hunt-fuzz` commands continue to work unchanged. The `dcs status` command is extended to show the active scanner backend:

```
$ dcs status
Sandbox available: True
Container runtime: podman
Scanner backend: semgrep (v1.78.0)
Registries: c, go, python
...
```

### MCP Changes

The `deep_scan_status` response gains a `scanner_backend` field:
```json
{
  "scanner_backend": "semgrep",
  "scanner_backend_version": "1.78.0",
  ...
}
```

The `deep_scan_hunt` response's `stats` object gains the `scanner_backend` field from ScanStats. No other MCP tool schemas change.

## Data Migration

None. No persistent data is affected. The change is purely in the runtime scanner pipeline.

## Rollout Plan

### Stage 0: Semgrep Rule Validation (pre-implementation, this plan)

Before committing to the backend implementation, validate the Semgrep OSS approach end-to-end:

1. Write 2-3 Python Semgrep taint rules (CWE-89, CWE-78) using correct DSL syntax.
2. Run `semgrep --validate --config <rules>` to confirm syntactic correctness.
3. Run `semgrep --config <rules> --json --metrics=off tests/fixtures/vulnerable_samples/python/` and inspect the OSS JSON output to confirm:
   - Taint-mode matches are reported for known vulnerable fixtures.
   - The `extra.metavars` field contains `$SOURCE` bindings with location data.
   - The `extra.dataflow_trace` field is confirmed absent in OSS output.
4. Compare detection counts against the tree-sitter backend on the same fixtures.
5. Document the actual detection delta. If the improvement is negligible, reconsider the plan scope.

This stage produces a written validation report appended to this plan before Stage 1 begins. It requires approximately 1 day and can be performed by one engineer.

### Stage 1: Core Implementation (this plan)
- Implement `ScannerBackend` protocol, `SemgrepBackend`, `TreeSitterBackend` adapter.
- Write Semgrep rules for Python, Go, C covering existing CWE categories.
- Modify `HunterOrchestrator` to use the backend abstraction.
- Full test suite passes with both backends.

### Stage 2: Detection Rate Validation (post-merge)
- Run both backends against the existing test fixtures and compare findings.
- Run against OpenSSL (C) to validate false positive rate.
- Run against real-world Python/Go web apps with known CVEs.
- Document actual detection rate improvement.

### Stage 3: Semgrep Pro Evaluation (future, out of scope)
- Evaluate Semgrep Pro for interprocedural taint tracking and `dataflow_trace` normalization.
- This replaces the previously planned v1.1 interprocedural taint work.
- License cost-benefit analysis required before commitment.

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Semgrep JSON output format changes between versions | Medium | Medium | Pin version range (>=1.50.0,<2.0.0). Runtime version check in `is_available()`. Write normalizer tests against known output fixtures. |
| Semgrep subprocess performance on large codebases | Medium | Medium | `DCS_SEMGREP_TIMEOUT` cap (120s default). Semgrep is optimized for large repos (used by companies scanning millions of LoC). |
| Semgrep binary not available in CI/CD environments | Medium | Low | Tree-sitter fallback ensures functionality. Document Semgrep as an optional but recommended dependency. |
| Custom Semgrep rules have gaps vs. community rules | Medium | Medium | Start with DCS custom rules (for metadata control). Future enhancement: allow `--config r/python.security` for community rules. |
| Normalization loses information from Semgrep output | Low | Low | The normalizer preserves metavar bindings, CWE, severity. Rule `metadata` fields provide explicit Source/Sink categories. |
| Two scanner backends double the testing surface | High | Medium | Backend protocol ensures both backends produce valid RawFinding structure. Compatibility tests validate both paths. |
| Semgrep OSS taint mode is limited to intraprocedural | Known | Low | This matches the existing tree-sitter engine's limitation. The plan explicitly documents this as parity, not regression. The improvement is in pattern matching, not taint scope. |
| Supply chain risk of Semgrep binary | Low | Medium | Semgrep is widely used (40K+ GitHub stars, backed by Semgrep Inc). Pin version range, verify checksums in CI. |
| Conditional-assignment-sanitizer work (just shipped) becomes less exercised with Semgrep | Medium | Low | The tree-sitter backend retains this work. Semgrep rules include equivalent sanitizer patterns for C conditional bounds-checks (see Section 4.4). |
| Semgrep taint confidence is capped at 50 (taint completeness) without Pro | Known | Medium | Documented in Confidence Scoring Adaptation. Semgrep compensates with better sanitizer filtering (no false sanitizer-related downgrades) and better pattern coverage. |
| Rules directory is empty or contains invalid rules | Medium | Medium | `is_available()` validates at least one `.yaml` file exists. `semgrep --validate` in CI. Log warning when results are empty with non-empty rules directory. |

## Test Plan

### Test Command

```bash
# From /Users/imurphy/projects/deep-code-security/

# Run all tests (includes both backends)
make test

# Run hunter tests only (both backends)
make test-hunter

# Run with specific backend forced
DCS_SCANNER_BACKEND=treesitter make test-hunter
DCS_SCANNER_BACKEND=semgrep make test-hunter  # requires semgrep installed

# Lint
make lint

# Security scan
make sast
```

### Test Categories

| Category | Count (est.) | Description |
|----------|-------------|-------------|
| SemgrepBackend unit tests | 15-20 | JSON normalization, subprocess invocation, error handling, post-filtering |
| TreeSitterBackend adapter tests | 5-8 | Verify adapter wraps existing pipeline correctly |
| Backend selection tests | 5-8 | Auto-detection, env override, fallback behavior, version checking |
| Semgrep rule validation tests | 10-15 | Each rule file tested with `semgrep --validate` |
| Cross-backend compatibility tests | 5-8 | Both backends produce valid RawFinding objects; both pass input validation; both work with suppressions |
| Existing test suite regression | ~80 existing | All existing tests must continue passing |

### Key Test Scenarios

1. **Semgrep backend produces valid RawFinding:** Scan `tests/fixtures/vulnerable_samples/python/sql_injection.py` with SemgrepBackend. Verify the returned RawFinding has correct Source, Sink, TaintPath, CWE, and severity. Verify the finding passes `input_validator.py` validation.

2. **TreeSitter fallback when Semgrep unavailable:** Mock `shutil.which("semgrep")` to return None. Verify `_select_backend()` returns TreeSitterBackend. Verify scan produces findings.

3. **Semgrep JSON normalization from OSS output:** Feed known Semgrep OSS JSON output (from fixture file, confirmed to NOT contain `dataflow_trace`) to the normalizer. Verify Source is constructed from rule metadata + metavar bindings. Verify TaintPath has exactly 2 steps (synthetic). Verify `TaintPath.sanitized` is `False`.

4. **Semgrep timeout handling:** Mock subprocess to exceed `DCS_SEMGREP_TIMEOUT`. Verify BackendResult with empty findings and diagnostic message.

5. **Semgrep non-zero exit:** Mock subprocess with exit code 1 and stderr. Verify graceful degradation with diagnostic logged.

6. **Suppression compatibility:** Generate findings via SemgrepBackend, apply `.dcs-suppress.yaml`. Verify suppressions work on Semgrep-generated findings (same CWE format in sink.cwe).

7. **Cross-backend structural compatibility:** Scan the same Python SQL injection fixture with both backends. Verify both produce `RawFinding` objects where: (a) all required fields are populated, (b) both pass `input_validator.py` validation, (c) both detect the same CWE category in the same file. Do NOT assert identical field values (line numbers, function names, confidence scores are expected to differ between backends).

8. **Backend reported in ScanStats:** After scan, verify `stats.scanner_backend` is "semgrep" or "treesitter" as appropriate.

9. **MCP status shows backend:** Call `deep_scan_status`, verify response includes `scanner_backend` field.

10. **DCS_SCANNER_BACKEND override:** Set env to "treesitter". Verify Semgrep is not invoked even when available.

11. **Post-filtering respects discovered_files:** Mock Semgrep returning findings for files not in `discovered_files`. Verify those findings are excluded from `BackendResult.findings`. Verify a diagnostic is logged.

12. **DCS_SCANNER_BACKEND=semgrep without semgrep:** Set env to "semgrep", mock `shutil.which` returning None. Verify `_select_backend()` raises `RuntimeError`. Verify MCP returns `ToolError(retryable=False)`.

13. **Semgrep rule validation:** Run `semgrep --validate --config <file>` on every `.yaml` file in `registries/semgrep/`. Verify all pass. (This test requires `semgrep` installed and is skipped in CI environments without it.)

14. **Subprocess includes --metrics=off:** Mock subprocess invocation. Verify the constructed command list includes `--metrics=off`.

15. **Empty rules directory warning:** Configure `DCS_SEMGREP_RULES_PATH` to an empty directory. Verify `is_available()` returns False (or logs a clear diagnostic).

16. **DCS_SEMGREP_RULES_PATH validation:** Test with paths containing `..` traversal, symlinks, and non-existent directories. Verify fallback to default in each case.

## Acceptance Criteria

1. [ ] `make test` passes with 90%+ coverage.
2. [ ] `make lint` passes with zero errors.
3. [ ] `make sast` passes with zero high/critical findings.
4. [ ] When Semgrep is installed, `dcs hunt <path>` uses SemgrepBackend by default and produces valid RawFinding objects.
5. [ ] When Semgrep is NOT installed, `dcs hunt <path>` falls back to TreeSitterBackend with no errors or degraded UX beyond a log message.
6. [ ] `DCS_SCANNER_BACKEND=treesitter` forces tree-sitter even when Semgrep is installed.
7. [ ] `DCS_SCANNER_BACKEND=semgrep` returns a clear `ToolError(retryable=False)` from MCP (or `RuntimeError` from CLI) if Semgrep is not installed.
8. [ ] Semgrep-generated RawFinding objects are accepted by `auditor/verifier.py` (input validation passes).
9. [ ] Semgrep-generated RawFinding objects are accepted by `bridge/resolver.py` (fuzz target resolution works).
10. [ ] `.dcs-suppress.yaml` suppressions work correctly with Semgrep-generated findings.
11. [ ] All existing Hunter, Auditor, Architect, Bridge, and MCP tests pass without modification.
12. [ ] `dcs status` and `deep_scan_status` report the active scanner backend.
13. [ ] Semgrep rules cover all CWE categories currently in `registries/python.yaml`, `registries/go.yaml`, and `registries/c.yaml`.
14. [ ] Semgrep subprocess is invoked with list-form arguments (never `shell=True`).
15. [ ] Semgrep subprocess command includes `--metrics=off`.
16. [ ] Semgrep subprocess is bounded by `DCS_SEMGREP_TIMEOUT`.
17. [ ] No new dependencies are added to the core `[project.dependencies]` -- Semgrep is an optional dependency.
18. [ ] All Semgrep rule files pass `semgrep --validate`.
19. [ ] Semgrep results are post-filtered to `discovered_files` (respects `DCS_MAX_FILES`).
20. [ ] `DCS_SEMGREP_RULES_PATH` is validated with `Path.resolve()` and `..` traversal rejection.

## Task Breakdown

### Files to Create

| File | Description |
|------|-------------|
| `src/deep_code_security/hunter/scanner_backend.py` | `ScannerBackend` protocol, `BackendResult` model, `select_backend()` factory |
| `src/deep_code_security/hunter/semgrep_backend.py` | `SemgrepBackend` class: subprocess invocation, JSON parsing, normalization (OSS-only, no `dataflow_trace`) |
| `src/deep_code_security/hunter/treesitter_backend.py` | `TreeSitterBackend` adapter wrapping existing parser/registry/finder/tracker |
| `registries/semgrep/python/cwe-78-command-injection.yaml` | Python command injection rules |
| `registries/semgrep/python/cwe-89-sql-injection.yaml` | Python SQL injection rules |
| `registries/semgrep/python/cwe-94-code-execution.yaml` | Python code execution rules |
| `registries/semgrep/python/cwe-22-path-traversal.yaml` | Python path traversal rules |
| `registries/semgrep/go/cwe-78-command-injection.yaml` | Go command injection rules |
| `registries/semgrep/go/cwe-89-sql-injection.yaml` | Go SQL injection rules |
| `registries/semgrep/go/cwe-22-path-traversal.yaml` | Go path traversal rules |
| `registries/semgrep/c/cwe-78-command-injection.yaml` | C command injection rules |
| `registries/semgrep/c/cwe-119-memory-corruption.yaml` | C memory corruption rules (includes conditional bounds-check sanitizers) |
| `registries/semgrep/c/cwe-120-buffer-overflow.yaml` | C buffer overflow rules (includes conditional bounds-check sanitizers) |
| `registries/semgrep/c/cwe-134-format-string.yaml` | C format string rules |
| `registries/semgrep/c/cwe-190-integer-overflow.yaml` | C integer overflow rules (includes conditional bounds-check sanitizers) |
| `registries/semgrep/c/cwe-676-dangerous-function.yaml` | C dangerous function rules |
| `registries/semgrep/c/cwe-22-path-traversal.yaml` | C path traversal rules |
| `tests/test_hunter/test_scanner_backend.py` | Backend selection and protocol tests |
| `tests/test_hunter/test_semgrep_backend.py` | SemgrepBackend unit tests (subprocess mocked, OSS JSON fixtures) |
| `tests/test_hunter/test_treesitter_backend.py` | TreeSitterBackend adapter tests |
| `tests/test_hunter/test_semgrep_rules.py` | Semgrep rule validation tests (`semgrep --validate`) |
| `tests/test_hunter/test_cross_backend_compat.py` | Cross-backend structural compatibility tests |
| `tests/fixtures/semgrep_output/` | Fixture JSON files with known Semgrep OSS output (confirmed no `dataflow_trace`) |

### Files to Modify

| File | Change |
|------|--------|
| `src/deep_code_security/hunter/orchestrator.py` | Add backend selection; delegate scan to backend; add `scanner_backend` to ScanStats |
| `src/deep_code_security/hunter/models.py` | Add `scanner_backend` field to ScanStats |
| `src/deep_code_security/hunter/__init__.py` | Add new modules to `__all__` |
| `src/deep_code_security/shared/config.py` | Add `DCS_SCANNER_BACKEND`, `DCS_SEMGREP_TIMEOUT`, `DCS_SEMGREP_RULES_PATH` (with validation) |
| `src/deep_code_security/mcp/server.py` | Add `scanner_backend` to `_handle_status` response |
| `src/deep_code_security/cli.py` | Add `scanner_backend` to `dcs status` output |
| `pyproject.toml` | Add `semgrep>=1.50.0,<2.0.0` to `[project.optional-dependencies]`; no change to core deps |
| `CLAUDE.md` | See CLAUDE.md update specification below |

**Total: 23 new files, 8 modified files**

**CLAUDE.md update specification:**
- Add `DCS_SCANNER_BACKEND`, `DCS_SEMGREP_TIMEOUT`, `DCS_SEMGREP_RULES_PATH` to the Environment Variables table.
- Add `Scanner backend` row to the Key Design Decisions table (choice: "Semgrep-primary with tree-sitter fallback", rationale: "Resolves tree-sitter query brittleness; Semgrep OSS provides parity intraprocedural taint with superior pattern matching").
- Update the Architecture diagram to show the `ScannerBackend` abstraction in the Hunter phase.
- Update Known Limitations section: note that Known Limitation #2 (query brittleness) is resolved when using the Semgrep backend. Add a new limitation noting that Semgrep OSS taint paths are always synthetic two-step (no intermediate variable traces without Semgrep Pro).
- Add Semgrep as an optional dependency in the Architecture section description.

## Work Groups

### Shared Dependencies
- `src/deep_code_security/hunter/scanner_backend.py` (implement first -- defines protocol used by all groups)
- `src/deep_code_security/hunter/models.py` (add `scanner_backend` field to ScanStats)
- `src/deep_code_security/shared/config.py` (add new env vars with validation)

### Work Group 1: Semgrep Backend Core
- `src/deep_code_security/hunter/semgrep_backend.py`
- `tests/test_hunter/test_semgrep_backend.py`
- `tests/fixtures/semgrep_output/` (fixture JSON files from OSS output)

### Work Group 2: TreeSitter Backend Adapter
- `src/deep_code_security/hunter/treesitter_backend.py`
- `tests/test_hunter/test_treesitter_backend.py`

### Work Group 3: Semgrep Rules (Python)
- `registries/semgrep/python/cwe-78-command-injection.yaml`
- `registries/semgrep/python/cwe-89-sql-injection.yaml`
- `registries/semgrep/python/cwe-94-code-execution.yaml`
- `registries/semgrep/python/cwe-22-path-traversal.yaml`

### Work Group 4: Semgrep Rules (Go + C)
- `registries/semgrep/go/cwe-78-command-injection.yaml`
- `registries/semgrep/go/cwe-89-sql-injection.yaml`
- `registries/semgrep/go/cwe-22-path-traversal.yaml`
- `registries/semgrep/c/cwe-78-command-injection.yaml`
- `registries/semgrep/c/cwe-119-memory-corruption.yaml` (with conditional bounds-check sanitizers)
- `registries/semgrep/c/cwe-120-buffer-overflow.yaml` (with conditional bounds-check sanitizers)
- `registries/semgrep/c/cwe-134-format-string.yaml`
- `registries/semgrep/c/cwe-190-integer-overflow.yaml` (with conditional bounds-check sanitizers)
- `registries/semgrep/c/cwe-676-dangerous-function.yaml`
- `registries/semgrep/c/cwe-22-path-traversal.yaml`

### Work Group 5: Orchestrator Integration + CLI/MCP
- `src/deep_code_security/hunter/orchestrator.py` (modify)
- `src/deep_code_security/hunter/__init__.py` (modify)
- `src/deep_code_security/mcp/server.py` (modify)
- `src/deep_code_security/cli.py` (modify)
- `tests/test_hunter/test_scanner_backend.py`

### Work Group 6: Cross-Backend Validation + Docs
- `tests/test_hunter/test_semgrep_rules.py`
- `tests/test_hunter/test_cross_backend_compat.py`
- `pyproject.toml` (modify)
- `CLAUDE.md` (modify)

## Context Alignment

### CLAUDE.md Patterns Followed

| Pattern | Alignment | Notes |
|---------|-----------|-------|
| Pydantic v2 for data-crossing models | Full | BackendResult uses Pydantic BaseModel; RawFinding/ScanStats remain Pydantic |
| Type hints on all public functions | Full | All new public functions have type hints |
| `__all__` in `__init__.py` | Full | New modules added to `hunter/__init__.py` |
| pathlib.Path over os.path | Full | All path handling uses pathlib |
| No mutable default arguments | Full | BackendResult uses `Field(default_factory=list)` |
| Never `subprocess.run(shell=True)` | Full | Semgrep invoked with list-form args |
| Never `yaml.load()` | Full | Semgrep rules loaded by Semgrep binary, not by our code |
| Never `eval()`/`exec()` | Full | No eval/exec in new code |
| 90%+ test coverage | Full | New test files cover all new code |
| `models.py` per phase | Full | ScanStats change is in existing models.py |
| `orchestrator.py` per phase | Full | Orchestrator modified, not replaced |
| All file paths through `path_validator.py` | Full | `DCS_SEMGREP_RULES_PATH` validated with `Path.resolve()` and `..` rejection |

### Prior Plans This Relates To

| Plan | Relationship |
|------|-------------|
| `deep-code-security.md` (APPROVED) | This plan modifies the Hunter phase architecture defined in the original plan. The original plan designed the tree-sitter pipeline; this plan wraps it as a fallback behind a new Semgrep-primary backend. |
| `c-language-support.md` (APPROVED) | C taint tracker enhancements are preserved in the tree-sitter fallback. Equivalent Semgrep rules are written for C CWE categories, including conditional bounds-check sanitizer patterns. |
| `conditional-assignment-sanitizer.md` (APPROVED) | The conditional bounds-check sanitizer in `taint_tracker.py` is preserved in the tree-sitter backend. Semgrep rules for C CWE-119/CWE-120/CWE-190 include equivalent `pattern-sanitizers` for conditional bounds-check patterns. This recently shipped work is NOT discarded. |
| `suppressions-file.md` (APPROVED) | The suppressions system operates on RawFinding objects and is backend-agnostic. No changes needed. |

### Deviations from Established Patterns

| Deviation | Justification |
|-----------|---------------|
| Semgrep is an optional dependency, not a core dependency | Making Semgrep required would break environments that cannot install it (e.g., air-gapped, minimal containers). The tree-sitter fallback ensures the tool always works. |
| New `registries/semgrep/` directory alongside existing `registries/*.yaml` | The tree-sitter registries remain for the fallback backend. The Semgrep rules directory is separate because Semgrep rules use a completely different format (Semgrep YAML DSL vs. tree-sitter s-expression queries). Both coexist. |
| Subprocess invocation of Semgrep binary | Semgrep has no stable Python API. The CLI is the supported interface. This follows the same pattern as sandbox container invocation via `subprocess`. |

## Security Analysis

### Trust Boundary Analysis

**New trust boundary: Semgrep binary execution.**

| Aspect | Analysis |
|--------|----------|
| Binary provenance | Semgrep is installed via `pip install semgrep` or system package. Users control the installation source. The Semgrep binary is trusted at the same level as the Python interpreter itself -- if an attacker can replace the Semgrep binary, they can also replace the Python interpreter. |
| Input to Semgrep | Source code files (already trusted -- user's own code) and DCS rule files (version-controlled in the repo, validated via `DCS_SEMGREP_RULES_PATH` path validation). |
| Output from Semgrep | JSON on stdout. Parsed with `json.loads()` (safe). No `eval()` or `yaml.load()`. Each result validated for required fields before normalization; malformed results logged and skipped. |
| Failure mode | Non-zero exit code logged as warning. Empty findings returned. No crash propagation. |
| Resource limits | `DCS_SEMGREP_TIMEOUT` bounds execution time (default: 120s). `--max-target-bytes` bounds per-file memory. |
| No network access | `--metrics=off` is passed in the subprocess command to disable Semgrep telemetry. This is enforced in the command construction, not just documented. |

**Existing trust boundaries unchanged:**
- Path validation via `path_validator.py` (applied before backend invocation).
- Input validation via `input_validator.py` (applied to RawFinding before template interpolation in Auditor).
- Sandbox security policy for exploit verification.

### Supply Chain Assessment

| Dependency | License | Risk | Mitigation |
|------------|---------|------|------------|
| `semgrep` (optional, >=1.50.0,<2.0.0) | LGPL-2.1 | Low | Widely used (40K+ GitHub stars). Not a core dependency -- tree-sitter fallback available. Pin version range. Runtime version check warns on out-of-range versions. |
| No new core dependencies | N/A | None | Semgrep is in `[project.optional-dependencies]` only. |

### Input Validation Specification

| Input | Validation |
|-------|------------|
| `DCS_SCANNER_BACKEND` env var | Must be one of `auto`, `semgrep`, `treesitter`. Invalid values fall back to `auto` with a warning log. |
| `DCS_SEMGREP_TIMEOUT` env var | Parsed as int, capped at 600, minimum 10. Invalid values fall back to default (120). |
| `DCS_SEMGREP_RULES_PATH` env var | Resolved via `Path.resolve()` (resolves symlinks). Rejected if the resolved path contains `..` components (defense in depth). Validated as an existing directory containing at least one `.yaml` file. If validation fails, falls back to default with a WARNING log. A WARNING is also logged if the resolved path is not under the project root (legitimate but worth noting). |
| Semgrep JSON output | Parsed with `json.loads()`. Each result validated for required fields (`check_id`, `path`, `start`, `end`, `extra.severity`, `extra.metadata.cwe`) before normalization. Malformed results logged and skipped. |
| Semgrep subprocess stderr | Truncated to 4KB. Logged at WARNING level. Never interpolated into templates or returned in MCP responses. |
| Semgrep version | Parsed from `semgrep --version` output. Versions outside >=1.50.0,<2.0.0 produce a WARNING log but do not block execution. |

---

## Review Response Matrix

This section tracks how each finding from the red team, librarian, and feasibility reviews was addressed.

| Finding | Severity | Resolution |
|---------|----------|------------|
| F-01 (dataflow_trace is Pro-only) | Critical | Redesigned normalization to use rule metadata + metavars from OSS output. Removed all dataflow_trace dependencies. See Normalization Strategy section. |
| F-02 (invalid Semgrep rule DSL syntax) | Critical | Fixed example rules: `patterns` -> separate list entries for OR semantics. Removed invalid `where`/`type` sanitizer constraint. Added `semgrep --validate` to test plan and CI. |
| F-03 (detection improvement overstated) | Major | Reframed throughout: improvement is in pattern-matching expressiveness, not taint scope. Added Stage 0 (pre-implementation validation) to rollout plan. |
| F-04 (--metrics=off missing from command) | Major | Added `--metrics=off` to the subprocess command specification. Added test scenario #14 to verify. Added AC #15. |
| F-05 (DCS_SEMGREP_RULES_PATH validation) | Major | Added `Path.resolve()`, `..` rejection, existence check, `.yaml` file presence check. See Input Validation Specification. |
| F-06 (cross-backend parity tests unrealistic) | Major | Replaced "parity tests" with "compatibility tests" that verify structural validity, not field-value equality. See test scenario #7. |
| F-07 (Semgrep bypasses DCS_MAX_FILES) | Major | Added post-filtering of Semgrep results against `discovered_files` list. See SemgrepBackend responsibility #5. Added test scenario #11. Added AC #19. |
| R-1 (path validation for rules path) | Required | Addressed same as F-05. |
| R-2 (--metrics=off in command spec) | Required | Addressed same as F-04. |
| R-3 (CLAUDE.md update underspecified) | Required | Added explicit CLAUDE.md update specification in Files to Modify section. |
| M-1 (rule syntax errors) | Major | Addressed same as F-02. |
| M-2 (confidence scoring asymmetry) | Major | Added Sanitizer Scoring Asymmetry section documenting the behavioral difference between backends. |
| M-3 (dataflow_trace is Pro-only) | Major | Addressed same as F-01. |
| M-4 (parity tests unrealistic) | Major | Addressed same as F-06. |
| M-5 (empty rules directory handling) | Major | Added `.yaml` file existence check in `is_available()`. Added empty-results warning diagnostic. Added test scenario #15. |
| F-08 (version compatibility) | Minor | Pinned version range >=1.50.0,<2.0.0. Added runtime version check with warning. |
| F-09 (failure mode for explicit semgrep selection) | Minor | Specified: `RuntimeError` at `_select_backend()`, `ToolError(retryable=False)` from MCP. Added test scenario #12. |
| F-10 (conditional-assignment-sanitizer) | Minor | Added Semgrep `pattern-sanitizers` for C conditional bounds-checks to Work Group 4 rules. See Section 4.4. |
| F-11 (BackendResult dataclass vs Pydantic) | Minor | Changed `BackendResult` to Pydantic `BaseModel` with `frozen=True` config. |
| F-12 (registry_version_hash for Semgrep) | Info | The Semgrep backend computes `registry_version_hash` by hashing the Semgrep rule files in the same way the tree-sitter backend hashes its YAML files. |
| F-13 (--no-git-ignore implications) | Info | Post-filtering against `discovered_files` resolves this: Semgrep may scan gitignored files, but findings from those files are excluded by the post-filter. |
| F-14 (300s timeout is high) | Info | Reduced default from 300s to 120s. |
| m-2 (scope to Python first) | Minor | Retained full scope (Python + Go + C) in this plan since the tree-sitter registries already cover all three. Stage 0 validates the approach with Python first. |
| m-5 (version pinning) | Minor | Addressed same as F-08. |
| m-6 (.gitignore discrepancy) | Minor | Addressed by post-filtering (same as F-07/F-13). |
| m-7 (is_available as staticmethod) | Minor | Changed to `@classmethod`. |
| S-1 (C sanitizer rules) | Optional | Adopted -- included in Work Group 4. |
| S-2 (--disable-version-check) | Optional | Not adopted. The version check latency is negligible (<100ms) and provides useful diagnostics. |

---

<!-- Context Metadata
discovered_at: 2026-03-19T10:00:00
revised_at: 2026-03-19
claude_md_exists: true
recent_plans_consulted: conditional-assignment-sanitizer.md, c-language-support.md, suppressions-file.md
archived_plans_consulted: deep-code-security.md, merge-fuzzy-wuzzy.md
reviews_addressed: semgrep-scanner-backend.redteam.md (FAIL -> revised), semgrep-scanner-backend.review.md (R-1/R-2/R-3), semgrep-scanner-backend.feasibility.md (M-1 through M-5)
-->

## Status: APPROVED
