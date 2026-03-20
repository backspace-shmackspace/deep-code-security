# Review: semgrep-scanner-backend.md (Round 2)

**Plan:** `./plans/semgrep-scanner-backend.md`
**Reviewed:** 2026-03-19
**Round:** 2 (revised plan addressing Round 1 review, red team, and feasibility findings)
**Verdict:** PASS

---

## Overall Assessment

The revised plan comprehensively addresses all Critical, Major, and Required findings
from the Round 1 review (R-1, R-2, R-3), the red team review (F-01 through F-14),
and the feasibility review (M-1 through M-5). The normalization strategy has been
redesigned to work with Semgrep OSS output only (no `dataflow_trace` dependency),
the Semgrep rule DSL syntax has been corrected, and the path validation, metrics-off,
and post-filtering gaps have been resolved. The 39-item Review Response Matrix
(lines 755-787) provides traceable evidence of each resolution.

---

## Conflicts with CLAUDE.md

### C-1: Subprocess invocation (COMPLIANT)

**CLAUDE.md Rule:** "All subprocess calls use list-form arguments (never shell=True)"

**Status:** Fully compliant. The plan specifies list-form arguments in Section 2
(line 159), includes `--metrics=off` in the command specification, and has
Acceptance Criterion #14 explicitly requiring this. Test scenario #14 verifies the
constructed command list.

### C-2: YAML loading (COMPLIANT)

**CLAUDE.md Rule:** "Never `yaml.load()` -- always `yaml.safe_load()`"

**Status:** Compliant. Semgrep rule YAML files are loaded by the Semgrep binary,
not by DCS Python code. Semgrep JSON output is parsed with `json.loads()`. No new
YAML loading is introduced in DCS code.

### C-3: Path validation (COMPLIANT -- R-1 resolved)

**CLAUDE.md Rule:** "All file paths validated through `mcp/path_validator.py`"

**Status:** Now compliant. The revised Input Validation Specification (lines 746-749)
specifies that `DCS_SEMGREP_RULES_PATH` is resolved via `Path.resolve()`, rejected
if it contains `..` components (defense in depth), validated as an existing directory
containing at least one `.yaml` file, and falls back to default with a WARNING log
on failure. A WARNING is logged if the resolved path is not under the project root.
AC #20 enforces this.

### C-4: No eval/exec/os.system/shell=True (COMPLIANT)

**Status:** No new eval, exec, os.system, or shell=True usage.

### C-5: Pydantic v2 for data-crossing models (COMPLIANT -- F-11 resolved)

**CLAUDE.md Rule:** "Pydantic v2 for all data-crossing models"

**Status:** Now compliant. The revised plan uses Pydantic `BaseModel` with
`model_config = {"frozen": True}` for `BackendResult` (lines 140-151). This
resolves the `@dataclass` inconsistency from the original draft.

### C-6: No secrets in logs or error messages (COMPLIANT)

**Status:** Semgrep stderr is "Truncated to 4KB. Logged at WARNING level. Never
interpolated into templates or returned in MCP responses." (line 748).

### C-7: Type hints on all public functions (COMPLIANT)

**Status:** Specified in Context Alignment table (line 684).

### C-8: `__all__` in `__init__.py` (COMPLIANT)

**Status:** New modules added to `hunter/__init__.py` (line 614).

### C-9: pathlib.Path over os.path (COMPLIANT)

**Status:** Specified in Context Alignment table (line 686).

### C-10: No mutable default arguments (COMPLIANT)

**Status:** `BackendResult` uses `Field(default_factory=list)` (lines 143, 148).

### C-11: Registries in YAML files, never hardcoded in Python (COMPLIANT)

**Status:** Semgrep rules live in `registries/semgrep/` directory (line 213).
This follows the existing convention. The Context Alignment section correctly
notes this as a deviation (new subdirectory format) with valid justification
(different rule format).

### C-12: `models.py` per phase, `orchestrator.py` per phase (COMPLIANT)

**Status:** ScanStats change is in existing `models.py` (line 377). Orchestrator
is modified, not replaced (line 298).

### C-13: 90%+ test coverage (COMPLIANT)

**Status:** AC #1 requires `make test` with 90%+ coverage.

### Full CLAUDE.md Compliance Table

| CLAUDE.md Rule | Status | Notes |
|---|---|---|
| Never `yaml.load()` | Compliant | Semgrep rules loaded by Semgrep binary |
| Never `eval()`, `exec()`, `shell=True` | Compliant | Subprocess list-form args |
| All file paths through `path_validator.py` | Compliant | `DCS_SEMGREP_RULES_PATH` validated per R-1 fix |
| Container security policy | N/A | No new container operations |
| Jinja2 SandboxedEnvironment | N/A | No template rendering |
| Input validator for RawFinding | Compliant | Semgrep findings validated by existing `input_validator.py` |
| Pydantic v2 for data-crossing models | Compliant | `BackendResult` is now Pydantic `BaseModel` |
| Type hints on all public functions | Compliant | |
| `__all__` in `__init__.py` | Compliant | |
| pathlib.Path over os.path | Compliant | |
| No mutable default arguments | Compliant | `Field(default_factory=list)` |
| 90%+ test coverage | Compliant | AC #1 |
| Registries in YAML, never hardcoded | Compliant | `registries/semgrep/` |
| `models.py` per phase | Compliant | |
| `orchestrator.py` per phase | Compliant | |

---

## Historical Alignment Issues

### H-1: Context Alignment section exists and is substantive (PASS)

The section (lines 677-711) contains:
- A 12-row CLAUDE.md Patterns Followed table with per-row alignment notes
- A 4-row Prior Plans Referenced table with relationship descriptions
- A 3-row Deviations from Established Patterns table with justifications

This is substantive and follows the precedent established by `c-language-support.md`
and `conditional-assignment-sanitizer.md`.

### H-2: Context metadata block (PASS)

Present at lines 790-797 with `claude_md_exists: true` (correct -- CLAUDE.md exists).
Lists 3 recent plans consulted (`conditional-assignment-sanitizer.md`,
`c-language-support.md`, `suppressions-file.md`), 2 archived plans
(`deep-code-security.md`, `merge-fuzzy-wuzzy.md`), and references the 3 prior
review documents addressed. No issues.

### H-3: Consistent with intraprocedural taint limitation (PASS)

The plan explicitly and repeatedly acknowledges that Semgrep OSS provides only
intraprocedural taint, matching the v1 architectural limitation in CLAUDE.md
Known Limitation #1. Lines 12-16 and 480 frame this correctly as parity in taint
scope with improvement in pattern-matching expressiveness.

### H-4: Consistent with deep-code-security.md architecture (PASS)

The original architecture established the Hunter phase as tree-sitter parse ->
taint track -> RawFinding[]. This plan wraps that pipeline as a fallback behind
a `ScannerBackend` protocol. The original architecture is preserved, not replaced.

### H-5: Consistent with conditional-assignment-sanitizer.md (PASS)

The conditional-assignment-sanitizer plan (commit `7cba085`) adds C-specific
bounds-check sanitizer recognition. The revised Semgrep plan now explicitly:
1. Preserves this work in the tree-sitter fallback (line 702).
2. Includes equivalent Semgrep `pattern-sanitizers` for C CWE-119/CWE-120/CWE-190
   covering `if (n > max) n = max;` and ternary clamp patterns (lines 276-291).
3. Notes the patterns the tree-sitter engine handles but Semgrep rules do not
   (macro-based clamps, early-return guards), aligning with CLAUDE.md Known
   Limitation #10 (line 291).

This is a well-handled alignment with recently shipped work.

### H-6: Consistent with suppressions-file.md (PASS)

The suppression system operates on `RawFinding.sink.cwe`, `.sink.file`, and
`.sink.line` (line 367). Test scenario #6 validates this with Semgrep-generated
findings. No changes to the suppression system are needed.

### H-7: Consistent with c-language-support.md (PASS)

The C language registry entries (CWE-78, CWE-119, CWE-120, CWE-134, CWE-190,
CWE-676) in the plan's Semgrep rules (lines 228-235) mirror the categories
added by `c-language-support.md`. The plan also includes a `cwe-22-path-traversal.yaml`
for C, which extends coverage beyond the existing tree-sitter registry.

### H-8: Consistent with sast-to-fuzz-pipeline.md (PASS)

The bridge consumes `RawFinding[]` and requires no changes (lines 365-366).
AC #9 validates that Semgrep-generated findings are accepted by `bridge/resolver.py`.

### H-9: Consistent with output-formats.md (PASS)

No output format changes. The `ScanStats.scanner_backend` field addition is
additive and backward-compatible (lines 377-387).

### H-10: Consistent with fuzzer-container-backend.md (PASS)

No fuzzer or container changes. The plan does not touch Podman, `_worker.py`,
or the container security policy.

### H-11: Confidence scoring model preserved (PASS)

The plan documents Non-Goal #5: "Changing the confidence scoring model." Section 7
(lines 326-352) provides a thorough analysis of how Semgrep OSS's synthetic
two-step paths and sanitizer-filtering behavior interact with the existing scoring
model. The asymmetry between backends is explicitly documented as correct behavior,
not a bug. The 10% bonus-only exploit weight is unaffected.

### H-12: No contradiction with MCP deployment model (PASS)

The plan correctly states Semgrep runs on the host alongside the MCP server
(Non-Goal #6, line 63), consistent with CLAUDE.md's "MCP deployment: Native stdio."

---

## Verification of Round 1 Required Edits

### R-1: `DCS_SEMGREP_RULES_PATH` validation -- RESOLVED

The Input Validation Specification (line 746) now specifies:
- `Path.resolve()` for symlink resolution
- Rejection of `..` components (defense in depth)
- Validation as existing directory with at least one `.yaml` file
- WARNING log if resolved path is not under project root
- Fallback to default on validation failure

AC #20 enforces this: "`DCS_SEMGREP_RULES_PATH` is validated with `Path.resolve()`
and `..` traversal rejection."

### R-2: `--metrics=off` in subprocess command -- RESOLVED

The subprocess invocation specification (line 159) now reads:
`semgrep --config registries/semgrep/ --json --metrics=off --no-git-ignore --timeout <t> --max-target-bytes <b> <target_path>`

Test scenario #14 verifies the constructed command includes `--metrics=off`.
AC #15 explicitly requires it.

### R-3: CLAUDE.md update specification -- RESOLVED

The plan now includes an explicit "CLAUDE.md update specification" block
(lines 623-629) listing 5 specific items to update: environment variables table,
key design decisions table, architecture diagram, known limitations updates,
and optional dependency notation.

---

## Verification of Critical Red Team Findings

### F-01: `dataflow_trace` is Pro-only -- RESOLVED

The normalization strategy has been completely redesigned (lines 166-207). It now
constructs Source, Sink, and TaintPath from rule metadata (`metadata.source_category`,
`metadata.source_function`, `metadata.sink_category`, etc.) and metavariable bindings
(`extra.metavars.$SOURCE`) from OSS output. The `dataflow_trace` field is explicitly
documented as Pro-only and not used (lines 17-18, 207). The confidence scoring
adaptation (Section 7) correctly handles the always-synthetic two-step paths.

### F-02: Invalid Semgrep rule DSL syntax -- RESOLVED

The example rules (lines 237-273) now use correct syntax:
- Multiple source patterns are listed as separate entries under `pattern-sources`
  (OR semantics), not nested under `patterns` (AND semantics).
- The invalid `where:` / `type:` sanitizer constraint has been replaced with a
  structural pattern match: `$CURSOR.execute($QUERY, ($PARAMS, ...))`.
- The plan notes on lines 271-274 explain the DSL syntax corrections.
- AC #18 requires `semgrep --validate` on all rule files.
- Test scenario #13 runs `semgrep --validate` on every rule.

---

## Conflicts (bullet list with rule heading citations)

None. All CLAUDE.md rules are fully addressed in the revised plan.

---

## Required Edits

None. All required edits from Round 1 (R-1, R-2, R-3) have been satisfactorily
addressed in the revision. All Critical findings from the red team review (F-01,
F-02) have been resolved. All Major findings from the feasibility review (M-1
through M-5) have been addressed.

---

## Optional Suggestions

### S-1: Specify Semgrep Source function name mapping for input validator compatibility

The plan's normalization uses `metadata.source_function` (e.g., `request.form`)
as the `Source.function` field and `metadata.sink_function` (e.g., `cursor.execute`)
as the `Sink.function` field. These values pass the existing `_FUNCTION_NAME_RE`
regex (`^[a-zA-Z_][a-zA-Z0-9_.]*$`) because they contain only alphanumerics and
dots. However, the plan should explicitly state that rule metadata function names
MUST match this regex pattern, to prevent a future rule author from writing
`metadata.source_function: request.form['id']` (which contains `[` and `'` and
would fail input validation). A comment in the Semgrep rule template or a
validation step in the normalizer would prevent this.

### S-2: Consider `--max-memory` flag for Semgrep subprocess

The plan specifies `--timeout` and `--max-target-bytes` as resource limits for
the Semgrep subprocess. Semgrep also supports `--max-memory <MB>` (default: 0,
meaning unlimited). For defense-in-depth against crafted source files causing
Semgrep memory exhaustion, consider adding `--max-memory` with a reasonable
default (e.g., 2048 MB). This aligns with the existing project pattern of
explicit resource limits on all subprocesses.

### S-3: Document that `BackendResult.diagnostics` is log-only

The plan states diagnostics are "logged at WARNING level" and "never interpolated
into templates" (line 748 for stderr). However, the `BackendResult.diagnostics`
field itself is a `list[str]`. The plan should add a brief note clarifying that
these diagnostics are consumed only by internal logging and are never serialized
into MCP responses, CLI output, or any external-facing channel. This prevents
a future implementation from inadvertently leaking diagnostic strings (which
may contain file paths or Semgrep error details) to MCP clients.

### S-4: Test scenario for Semgrep-generated findings through full pipeline

The test plan validates Semgrep findings through `input_validator.py` (test
scenario #1) and `bridge/resolver.py` (AC #9), but does not include a test
that runs a Semgrep-generated finding through the full Auditor pipeline
(confidence scoring). Consider adding an integration test that verifies
`taint_completeness_score()` returns 50 for Semgrep's synthetic two-step
paths and that `sanitizer_score()` returns 100 (since Semgrep OSS never
reports `sanitized=True`). This would catch any confidence scoring regressions
early.

### S-5: Stage 0 validation should also check `$SOURCE` metavar presence

Stage 0 (lines 438-451) validates the Semgrep OSS approach by checking that
taint-mode matches appear and `extra.metavars` contains `$SOURCE` bindings.
Consider explicitly checking whether `$SOURCE.start.line` differs from the
match `start.line` -- this determines whether the normalizer can construct
a Source with a distinct location from the Sink. If they are always identical,
the "with `$SOURCE` metavar" row in the confidence table (line 335) is moot,
and all Semgrep findings would have co-located source and sink.

---

## What Went Well

- **Thorough review response matrix.** The 39-row Review Response Matrix
  (lines 755-787) traces every finding from all three prior reviews to its
  resolution. This is the best implementation of review response tracking
  I have seen in this project.

- **Honest framing of Semgrep OSS limitations.** The plan clearly distinguishes
  Semgrep OSS from Semgrep Pro at every relevant point, avoids overstating
  detection improvement, and correctly frames the value proposition as
  pattern-matching expressiveness rather than taint depth.

- **Confidence scoring asymmetry documentation.** Section 7 (lines 341-351)
  explicitly documents the sanitizer scoring asymmetry between backends and
  correctly identifies it as intended behavior, not a bug.

- **Post-filtering against discovered_files.** The plan addresses the
  `DCS_MAX_FILES` bypass (F-07) by post-filtering Semgrep results against
  the `discovered_files` list, with a diagnostic logged when findings are
  filtered out (line 161). Test scenario #11 validates this.

- **Stage 0 pre-implementation validation.** Moving detection validation before
  full implementation (F-03 remediation) is the correct risk management approach.

- **C sanitizer rule parity.** Including Semgrep `pattern-sanitizers` for
  conditional bounds-check patterns (lines 276-291) demonstrates respect for
  recently shipped work.

---

**Reviewer:** code-reviewer
**Verdict:** PASS
**Plan status:** Ready for APPROVED status.
