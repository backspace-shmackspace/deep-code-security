# Review: c-language-support.md (Revision 3)

**Plan:** `./plans/c-language-support.md`
**Reviewed:** 2026-03-18
**Verdict:** PASS

---

## Conflicts with CLAUDE.md

No conflicts found. All Critical Rules (Security and Code Quality) are satisfied.

| CLAUDE.md Rule | Status | Notes |
|---|---|---|
| Never `yaml.load()` -- always `yaml.safe_load()` | Compliant | Plan does not modify registry loading. Existing `registry.py` uses `yaml.safe_load()`. |
| Never `eval()`, `exec()`, `shell=True` | Compliant | No new use of prohibited functions. Plan adds AST node-type handling and set operations only. |
| All file paths validated through `mcp/path_validator.py` | N/A | No new file path handling. CLI and MCP paths already validated. |
| Pydantic v2 for all data-crossing models | Compliant | No new data-crossing models. `TaintState` is an internal `@dataclass` (not serialized across boundaries), consistent with the existing codebase pattern. |
| Type hints on all public functions | Compliant | Plan specifies type hints on all new/modified methods (`_node_to_var_name(self, node: Any) -> str | None`, `_extract_lhs_name(self, assignment_node: Any) -> str | None`). |
| `__all__` in `__init__.py` | Compliant | No new modules created. |
| pathlib.Path over os.path | Compliant | No new path operations. |
| No mutable default arguments | Compliant | No new dataclass fields with mutable defaults. |
| 90%+ test coverage | Compliant | Comprehensive test plan with 30+ test cases across two test modules. Acceptance criterion 6 requires `make test` at 90%+. |
| Registries in YAML files, never hardcoded | Compliant | All source/sink definitions are in `registries/c.yaml`. No hardcoded patterns in Python code. |
| `models.py` per phase | Compliant | No new models. |
| `orchestrator.py` per phase | Compliant | Only adding CWE names to the existing orchestrator. |

---

## Prior Required Edits Status

### R-1 (Add CLAUDE.md update task): RESOLVED (since Revision 2)

Task 15 in Files to Modify includes explicit CLAUDE.md modification covering C language support, CWE-416 deferral, `mktemp()`/`tmpnam()` detection gap, and output-parameter source limitation. Phase 5 in the Rollout Plan and Acceptance Criterion 11 also reference the CLAUDE.md update.

### R-2 (Clarify `mktemp`/`tmpnam` detection gap): RESOLVED (since Revision 2)

Risk #7 provides a detailed explanation of the detection gap. Registry YAML comments (lines 99-101 of the plan) document the limitation. Task 15 includes it in the CLAUDE.md update scope.

### R-3 (Output-parameter sources): RESOLVED

All four sub-requirements from the Revision 2 review are satisfied:

**a) Problematic sources commented out with "NOT YET SUPPORTED" notes:**
- `scanf`/`fscanf`/`sscanf` are commented out under `cli_input` with the annotation: "NOT YET SUPPORTED: output-parameter source (taints buffer arg, not return value). See Known Limitations."
- `recv`/`recvfrom`/`recvmsg` and `read` are commented out under a `network_input` block with the same annotation.
- `fread` and `getline`/`getdelim` are commented out under a `file_input` block with the same annotation.
- All six groups have clear "NOT YET SUPPORTED" markers.

**b) Known Limitation documenting why these sources are deferred:**
- The registry YAML header comments (lines 103-107 of the plan) contain a multi-line explanation of the output-parameter limitation and the deferral.
- The Proposed Design "Deferred (output-parameter sources)" block (lines 48-61) lists all affected functions with per-function explanations of why each fails.
- The "Sources that work correctly with LHS-seeding" block (lines 56-60) explicitly enumerates the four working sources (`argv`, `getenv`, `gets`, `fgets`) and explains why each works.
- The Deviations from Established Patterns table has a row for "Output-parameter sources deferred" with full justification.

**c) Test fixture descriptions updated to use working sources:**
- `network_input.c` uses `fgets` -> `strcpy` (CWE-120), not `recv`. The description explicitly states it "Uses `fgets` (a return-value source that works with LHS-seeding) rather than `recv` (an output-parameter source that does not)."
- `memory_functions.c` uses `argv[1]` -> `atoi` -> `memcpy` size (CWE-119), not `fread` or `read`.
- The end-to-end test `test_fgets_to_strcpy` replaces the old `test_network_input_to_memcpy`.
- No test case depends on output-parameter tainting.

**d) CLAUDE.md update task (task 15) includes the output-parameter limitation:**
- Task 15 item (d) explicitly specifies: "C source functions that deliver tainted data via output parameters (`recv`, `fread`, `read`, `scanf`, `getline`) are not effective taint sources in v1. Only functions whose return value IS the tainted data (`argv`, `getenv`, `gets`, `fgets`) work correctly with the LHS-seeding taint engine."
- Acceptance criterion 11 mirrors this language.
- Phase 5 of the Rollout Plan references the output-parameter deferral.

---

## Historical Alignment Issues

### H-1: CLAUDE.md update task present (PASS)

Task 15 includes CLAUDE.md update consistent with the precedent set by `suppressions-file.md`.

### H-2: Consistent with intraprocedural taint limitation (PASS)

The plan explicitly acknowledges intraprocedural-only taint tracking (Non-Goal 3, Context Alignment table). CWE-416 is correctly deferred as a Non-Goal.

### H-3: Consistent with deep-code-security.md architecture plan (PASS)

The original architecture plan identifies "C as stretch goal." This plan uses the same patterns: tree-sitter grammar, YAML registry, taint tracker, `_cwe_name()` mapping. No architectural deviations.

### H-4: Consistent with suppressions-file.md (PASS)

The plan references `.dcs-suppress.yaml` as the mechanism for suppressing C false positives (Risks 3, 4). No changes to suppression logic needed.

### H-5: Consistent with sast-to-fuzz-pipeline.md (PASS)

The C fuzzer plugin is explicitly out of scope (Non-Goal 1). The bridge could theoretically convert C findings but the fuzzer only supports Python.

### H-6: Consistent with output-formats.md (PASS)

No output format changes needed. C findings use the same `RawFinding` model.

### H-7: Architect output remains guidance-only (PASS)

Non-Goal 7 explicitly defers Architect remediation guidance for new CWEs.

### H-8: Context Alignment section exists and is substantive (PASS)

The section contains a 13-row CLAUDE.md compliance table, a 3-row Prior Plans Referenced table, and a 3-row Deviations from Established Patterns table with detailed justifications.

### H-9: Context metadata block (PASS)

Present with `claude_md_exists: true` and lists 5 consulted plans (3 recent, 2 archived).

### H-10: No contradiction with fuzzer or container plans (PASS)

No fuzzer changes proposed. The plan does not touch container execution, Podman, `_worker.py`, or `eval()` usage.

---

## Required Edits

None. All three prior required edits (R-1, R-2, R-3) are resolved.

---

## Optional Suggestions

Prior optional suggestions S-1 through S-6 from earlier reviews remain applicable. No new suggestions.

---

**Reviewer:** Librarian (automated)
**Plan status:** DRAFT -- approved for implementation. No required edits remain.
