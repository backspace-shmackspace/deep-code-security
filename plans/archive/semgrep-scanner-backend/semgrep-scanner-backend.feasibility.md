# Feasibility Review (Round 2): semgrep-scanner-backend

**Reviewer:** code-reviewer (agent)
**Date:** 2026-03-19
**Plan:** `./plans/semgrep-scanner-backend.md` (Status: DRAFT revised)
**Round:** 2 (revision review)

---

## Verdict: PASS

The revised plan resolves both Critical findings (F-01, F-02) and all five
Major findings (M-1 through M-5) from round 1. The remaining concerns are
minor and do not block implementation. The plan is technically feasible and
ready for Stage 0 validation followed by Stage 1 implementation.

---

## Round 1 Finding Resolution Audit

### F-01: `dataflow_trace` Pro-only dependency [Critical] -- RESOLVED

The original plan built its entire normalization pipeline around
`extra.dataflow_trace`, which is a Semgrep Pro feature unavailable in OSS
output. The revised plan completely redesigns the normalization strategy
(lines 166-207):

- Source is constructed from rule `metadata` fields (`source_category`,
  `source_function`) plus the `$SOURCE` metavariable binding location from
  `extra.metavars`.
- Sink is constructed from the match location and rule `metadata`.
- TaintPath is always a synthetic two-step path (source step + sink step).
- The plan explicitly states `dataflow_trace` is NOT used (lines 17-18,
  207) and defers richer trace support to a future Semgrep Pro evaluation.

The Confidence Scoring Adaptation section (lines 326-352) documents the
consequences: Semgrep OSS findings cap at taint completeness score 50
(partial path). This is honest and well-reasoned. The sanitizer scoring
asymmetry table (lines 343-349) is a particularly good addition -- it
explains why Semgrep findings have `sanitized=False` always (Semgrep filters
sanitized paths internally rather than reporting them).

**Assessment:** Fully resolved. The normalization design is realistic for
Semgrep OSS output.

### F-02: Invalid Semgrep rule DSL syntax [Critical] -- RESOLVED

The revised example rule (lines 241-269) uses correct syntax:

- `pattern-sources` lists each source pattern as a separate list entry
  (lines 258-263), which gives OR semantics. The original draft used
  `patterns:` (AND combinator), which was incorrect.
- The invalid `where:`/`type:` sanitizer constraint is replaced with a
  structural pattern `$CURSOR.execute($QUERY, ($PARAMS, ...))` (line 268),
  which matches parameterized query calls.
- The plan mandates `semgrep --validate --config <file>` for all rule files
  (line 274, AC #18, test scenario #13).

The DSL syntax notes at lines 271-274 explicitly call out the original error
and explain the fix, which demonstrates understanding rather than just
mechanical correction.

**Assessment:** Fully resolved. The example rule syntax is valid. The
`semgrep --validate` enforcement in CI provides ongoing protection.

### M-1: Rule syntax errors -- RESOLVED (same as F-02)

### M-2: Confidence scoring asymmetry -- RESOLVED

The revised plan adds a dedicated "Sanitizer scoring asymmetry between
backends" table (lines 343-349) that documents the behavioral difference:
tree-sitter reports sanitized paths with `sanitized=True`, while Semgrep
filters them out. The plan correctly states "This asymmetry is correct
behavior, not a bug" (line 350) and does not attempt to force symmetric
scoring.

**Assessment:** Fully resolved.

### M-3: `dataflow_trace` is Pro-only -- RESOLVED (same as F-01)

### M-4: Cross-backend parity tests unrealistic -- RESOLVED

Test scenario #7 (lines 535-536) was rewritten as "compatibility tests"
rather than "parity tests." It now verifies: (a) all required fields are
populated, (b) both pass `input_validator.py` validation, (c) both detect
the same CWE category in the same file. The plan explicitly states "Do NOT
assert identical field values (line numbers, function names, confidence
scores are expected to differ between backends)" (line 536).

**Assessment:** Fully resolved. The test expectations are realistic.

### M-5: Missing error handling for empty rules directory -- RESOLVED

The revised plan addresses this at multiple levels:

- `is_available()` validates that the rules directory contains at least one
  `.yaml` file (line 158, line 484).
- The error handling section states: "If the `results` array is empty AND the
  rules directory contains rule files, log a warning" (line 163).
- Test scenario #15 (line 551) explicitly tests the empty directory case.
- AC #20 requires `DCS_SEMGREP_RULES_PATH` validation.

**Assessment:** Fully resolved.

### Other Round 1 Findings

All minor and info-level findings from round 1 were also addressed:

| Finding | Resolution | Verified |
|---------|------------|----------|
| m-1 (BackendResult dataclass vs Pydantic) | Changed to Pydantic BaseModel with `frozen=True` (line 149) | Yes |
| m-3 (300s timeout) | Reduced to 120s default (line 164) | Yes |
| m-4 (--metrics=off) | Added to subprocess command spec (line 159) and test #14 (line 549) | Yes |
| m-5 (version pinning) | Pinned `>=1.50.0,<2.0.0` (line 67, 618) with runtime version check (line 157) | Yes |
| m-6 (.gitignore discrepancy) | Resolved via post-filtering against `discovered_files` (line 161) | Yes |
| m-7 (is_available staticmethod) | Changed to `@classmethod` (line 132) | Yes |

The Review Response Matrix (lines 755-787) tracks all 26 findings from three
review documents. Every finding has a documented resolution with cross-
references to the plan section where the fix was made. This is excellent
traceability.

---

## New Concerns in the Revised Plan

### Major (0)

No new major issues found.

### Minor (5)

**m-1. Semgrep metavar `$SOURCE` `abstract_content` may fail input validation.**

The normalization example (line 191) shows `$SOURCE` metavar with
`abstract_content: "request.form['id']"`. The plan says `source.function`
is populated from `metadata.source_function` (line 200), which would be
`request.form` -- this passes `_FUNCTION_NAME_RE` (`^[a-zA-Z_][a-zA-Z0-9_.]*$`).
However, if a future rule or a rule author inadvertently sets
`source_function` to include brackets, parentheses, or other characters from
the actual `abstract_content` string, the finding would fail
`input_validator.py` validation and be rejected by the Auditor.

This is not a bug in the plan as written (the plan correctly uses
`metadata.source_function` which is author-controlled), but it is a fragile
coupling. A rule author must know that `metadata.source_function` must match
`^[a-zA-Z_][a-zA-Z0-9_.]*$` -- this constraint is not documented in the
Semgrep rules specification.

**Recommendation:** Add a note in the Semgrep Rules section (Section 4.4) or
a `README.md` in `registries/semgrep/` documenting the field format
constraints for `metadata.source_function`, `metadata.sink_function`, and
`metadata.source_category`. These must match the regex patterns in
`input_validator.py`. Consider validating these fields during normalization
(before constructing the Source/Sink objects) and logging a warning if a rule
produces a finding with invalid metadata.

**m-2. `_compute_raw_confidence()` extraction is underspecified.**

The plan states `_compute_raw_confidence()` is "moved to a shared location
so both backends can use it" (line 312), but does not specify where. The
current implementation lives in `HunterOrchestrator` (orchestrator.py lines
281-300) and has a specific heuristic: sanitized paths get 0.3, 3+ steps
get 0.8, 2 steps get 0.6, fewer get 0.4. For Semgrep findings (always 2
synthetic steps, never sanitized), this always returns 0.6.

The plan should specify whether this function moves to `scanner_backend.py`,
`models.py`, or a new utility module. This is a small detail but relevant
for the implementation since both backends call it.

**Recommendation:** Specify that `_compute_raw_confidence()` moves to
`hunter/scanner_backend.py` alongside `BackendResult`, since it is part of
the backend contract (both backends must produce `raw_confidence` in
`RawFinding`).

**m-3. C Semgrep taint rules for output-parameter sources (recv, fread, read)
may silently regress vs. tree-sitter baseline.**

The tree-sitter C registry (c.yaml lines 30-90) explicitly documents that
output-parameter sources (`recv`, `fread`, `read`, `scanf`, `getline`,
`getdelim`) are NOT effective taint sources in v1. These are commented out.
The plan's Semgrep rules for C (lines 228-234) include rules for CWE-78,
CWE-119, CWE-120, CWE-134, CWE-190, CWE-676, CWE-22, but the plan does
not specify whether the Semgrep C rules will also exclude output-parameter
sources or attempt to include them.

Semgrep's `mode: taint` with `pattern-sources: - pattern: recv(...)` would
match `recv()` calls but would not correctly taint the *buffer argument* --
it would taint the return value (the byte count), which is the same
limitation as the tree-sitter engine. If the Semgrep rules include these
sources, they would produce false positives (tainting the wrong value). If
they exclude them, parity is maintained but the rules must explicitly
document why.

**Recommendation:** The C Semgrep rules should exclude the same
output-parameter sources that are commented out in `c.yaml`. Add a comment
in each C rule file referencing CLAUDE.md Known Limitation #7.

**m-4. Post-filtering implementation detail: file path format mismatch.**

The plan says Semgrep results are post-filtered against the `discovered_files`
list (line 161). Semgrep outputs relative paths in its `path` field (relative
to the scan root), while `DiscoveredFile.path` is a `Path` object (typically
absolute, from `FileDiscovery.discover()`). The normalizer must ensure path
comparison handles this format difference.

The plan does not specify how path comparison works. If the normalizer
compares `semgrep_result["path"]` (relative, e.g., `app.py`) against
`discovered_file.path` (absolute, e.g., `/home/user/project/app.py`),
all findings will be filtered out.

**Recommendation:** Specify that the post-filter resolves Semgrep's relative
paths to absolute paths using `(target_path / semgrep_path).resolve()` before
comparison against `discovered_files`. Alternatively, compare using the
relative-to-target-path form of both paths.

**m-5. `--max-target-bytes` default value is unspecified.**

The subprocess command includes `--max-target-bytes <max_bytes>` (line 86)
but the plan does not specify the default value or whether it uses Semgrep's
default (1MB). For large auto-generated files (e.g., protobuf stubs,
migration scripts), 1MB may be insufficient, while for security scanning,
files larger than 1MB are rarely relevant.

**Recommendation:** Explicitly state the default (Semgrep's 1MB default is
reasonable) or introduce a `DCS_SEMGREP_MAX_TARGET_BYTES` env var if
configurability is needed.

---

## Implementation Complexity Assessment

| Component | Plan Scope | Realistic Estimate | Notes |
|-----------|-----------|-------------------|-------|
| `ScannerBackend` protocol + `BackendResult` | Shared deps | 0.5 days | Straightforward; protocol definition is well-specified |
| `SemgrepBackend` (subprocess + normalization) | WG1 | 2-3 days | Normalization from OSS output is simpler than the original dataflow_trace approach; well-specified now |
| `TreeSitterBackend` adapter | WG2 | 0.5-1 day | Thin wrapper; existing code unchanged |
| Semgrep rules (Python, 4 files) | WG3 | 2-3 days | Rule authoring + testing with `semgrep --validate` and fixture scans |
| Semgrep rules (Go, 3 files) | WG4 | 1-2 days | Fewer CWE categories than Python |
| Semgrep rules (C, 7 files) | WG4 | 3-4 days | Most complex: includes sanitizer patterns for conditional bounds-checks, C-specific pattern syntax |
| Orchestrator refactor | WG5 | 1-2 days | Backend delegation is clean; dedup/suppression/pagination logic stays |
| CLI/MCP status changes | WG5 | 0.5 day | One new field in status responses |
| Tests (all categories) | WG1-6 | 2-3 days | Well-specified in 16 test scenarios |
| Stage 0 validation | Pre-impl | 1 day | Write 2-3 rules, run against fixtures, confirm OSS output structure |
| Config + docs | Shared/WG6 | 1 day | Three env vars, CLAUDE.md updates |

**Total realistic estimate:** 3-4 weeks for full scope (Python + Go + C).
This is consistent with the round 1 estimate and reflects the substantial
Semgrep rule authoring effort (14 rule files across 3 languages).

The Stage 0 validation (lines 438-451) is a strong addition that was not
in the original plan. It gates the full implementation on empirical evidence
that the Semgrep OSS approach works as expected. This reduces the risk of
committing to 23 new files before validating the approach.

---

## Backward Compatibility Assessment

| Change | Breaking? | Risk |
|--------|-----------|------|
| New `scanner_backend` field on `ScanStats` | No | Additive field with default `"treesitter"` |
| New env vars (`DCS_SCANNER_BACKEND`, `DCS_SEMGREP_TIMEOUT`, `DCS_SEMGREP_RULES_PATH`) | No | All have defaults; existing behavior preserved with `auto` mode |
| Orchestrator `scan()` return type | No | Unchanged `tuple[list[RawFinding], ScanStats, int, bool]` |
| `RawFinding` model | No | No schema changes |
| CLI output | No | `dcs status` gains one line |
| MCP response | No | `deep_scan_status` gains two fields |
| `semgrep` optional dependency | No | Not in core deps; tree-sitter fallback preserves all existing functionality |

**Verdict:** No breaking changes. Fully backward compatible.

---

## Dependency and Library Assumptions

| Assumption | Validity | Risk |
|-----------|----------|------|
| Semgrep OSS `mode: taint` produces results with `extra.metavars` containing `$SOURCE` bindings | Likely valid but must be verified in Stage 0 | Medium -- if metavar bindings are absent, source location cannot be determined (falls back to match location) |
| Semgrep's JSON output schema is stable within 1.x | Mostly valid | Medium -- the `>=1.50.0,<2.0.0` pin mitigates; fixture-based normalizer tests will catch regressions |
| `pip install semgrep` works on macOS (dev) and Linux (CI) | Valid | Low -- Semgrep distributes platform-specific wheels via PyPI |
| Semgrep C taint mode is functional for intraprocedural analysis | Partially valid | Medium -- Semgrep's C support is based on tree-sitter internally; less battle-tested than Python/Go |
| `semgrep --validate` catches all rule syntax errors | Mostly valid | Low -- `--validate` checks syntax but may not catch semantic issues (e.g., overly broad patterns) |
| `--metrics=off` disables all telemetry | Valid | Low -- documented and widely used flag |

**Key risk:** The `$SOURCE` metavar binding assumption is the most important
to validate. If Semgrep OSS taint mode does not populate `$SOURCE` with
location data in `extra.metavars`, the normalizer must fall back to setting
source location equal to the match location (which the plan already handles
at line 200-201). Stage 0 validation will confirm this.

---

## Test Coverage Assessment

The test plan is thorough with 16 explicitly enumerated test scenarios
(lines 523-554). Key observations:

**Strengths:**
- Scenario #3 (OSS JSON normalization) tests the critical path with fixture
  data confirmed to lack `dataflow_trace`.
- Scenario #7 (cross-backend compatibility) has realistic expectations
  (structural validity, not field-value equality).
- Scenario #11 (post-filtering) tests the DCS_MAX_FILES enforcement.
- Scenario #12 (explicit backend without binary) tests the error path.
- Scenario #14 (--metrics=off) tests the privacy-critical flag.
- Scenario #16 (path traversal in rules path) tests security-sensitive input.

**Gaps (minor):**
- No test for Semgrep stderr truncation at 4KB boundary. The plan specifies
  truncation (line 748) but no test exercises the boundary.
- No test for `DCS_SEMGREP_TIMEOUT` boundary values (minimum 10, maximum
  600). The plan specifies these caps (line 745) but no scenario tests them.
- No negative test for a Semgrep rule that produces findings with invalid
  `metadata.source_function` (e.g., containing brackets). This relates to
  concern m-1 above.

These gaps are minor and can be addressed during implementation without
plan changes.

---

## Security Assessment

The revised plan's security posture is sound:

1. **Subprocess invocation** uses list-form arguments with `--metrics=off`
   explicitly in the command spec. No `shell=True`.
2. **`DCS_SEMGREP_RULES_PATH` validation** includes `Path.resolve()`,
   `..` rejection, existence check, and `.yaml` file presence check
   (line 746). Falls back to default on validation failure.
3. **Semgrep stderr** is truncated to 4KB and never interpolated into
   templates or MCP responses (line 748).
4. **Post-filtering** ensures Semgrep does not bypass `DCS_MAX_FILES` or
   language filters (line 161).
5. **Trust boundary** for the Semgrep binary is correctly analyzed: "trusted
   at the same level as the Python interpreter itself" (line 722).
6. **No new core dependencies** -- Semgrep is in `[project.optional-dependencies]`
   only (line 618).

No automatic-FAIL triggers from the project security policy are present.

---

## Recommended Adjustments

1. **[m-1]** Document `metadata.source_function` / `metadata.sink_function`
   format constraints in a README or comment within the `registries/semgrep/`
   directory, noting they must match `input_validator.py` regex patterns.

2. **[m-2]** Specify the target module for `_compute_raw_confidence()`
   extraction (recommend `hunter/scanner_backend.py`).

3. **[m-3]** Explicitly exclude output-parameter sources from C Semgrep
   rules, mirroring the commented-out entries in `c.yaml`, with a comment
   referencing Known Limitation #7.

4. **[m-4]** Specify the path comparison strategy for post-filtering
   (resolve Semgrep relative paths against `target_path` before comparing
   to `discovered_files`).

5. **[m-5]** Specify the `--max-target-bytes` default value explicitly
   (recommend Semgrep's default of 1MB, stated in the plan).

These are implementation details that can be resolved during coding without
plan revision. None are blocking.

---

<!-- Context Metadata
reviewed_at: 2026-03-19
plan_file: plans/semgrep-scanner-backend.md
plan_status: DRAFT (revised)
review_round: 2
previous_review: plans/semgrep-scanner-backend.feasibility.md (round 1, PASS with adjustments)
codebase_files_examined:
  - src/deep_code_security/hunter/orchestrator.py
  - src/deep_code_security/hunter/models.py
  - src/deep_code_security/shared/config.py
  - src/deep_code_security/auditor/confidence.py
  - src/deep_code_security/mcp/input_validator.py
  - src/deep_code_security/mcp/server.py
  - src/deep_code_security/bridge/resolver.py
  - registries/python.yaml
  - registries/c.yaml
  - registries/go.yaml
  - pyproject.toml
round_1_findings_resolved: F-01, F-02, M-1, M-2, M-3, M-4, M-5, m-1, m-2, m-3, m-4, m-5, m-6, m-7
-->
