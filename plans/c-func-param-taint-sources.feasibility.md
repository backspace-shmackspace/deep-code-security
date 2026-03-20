# Feasibility Review: C Function Parameter Taint Sources (Round 2)

**Plan:** `plans/c-func-param-taint-sources.md`
**Round:** 2 (revised plan)
**Reviewed by:** code-reviewer agent
**Date:** 2026-03-20
**Verdict:** PASS

**Sources examined (Round 2):** `taint_tracker.py` (lines 265-341, seeding logic),
`treesitter_backend.py` (lines 183-298, `scan_files()`), `scanner_backend.py` (lines 62-94,
`ScannerBackend` protocol), `orchestrator.py` (lines 67-211, `scan()` method),
`semgrep_backend.py` (lines 275-451, `scan_files()` and command construction),
`models.py` (Source model), `config.py` (Config class), `hunter/__init__.py`

---

## Verification of Round 1 Findings

### M-1: `_find_assigned_var_near_line()` will spuriously seed nearby local variables -- RESOLVED

The revised plan fully addresses this finding. Specifically:

1. **Section 4c ("Taint Seeding for Parameter Sources")** now contains a dedicated subsection
   titled "Taint Seeding for Parameter Sources" that explicitly describes the problem, explains
   WHY the bypass is required (with a concrete code example showing `int x = len + 1` at L2
   within the +/- 2 line window), and provides the exact 3-line code change.

2. **`taint_tracker.py` is listed in Files to Modify** as item #13 with description:
   "In `_analyze_function()`, add `source.category == "func_param"` guard to skip
   `_find_assigned_var_near_line()` for parameter sources (3-line change)."

3. **The proposed code change is correct.** Verified against the actual `_analyze_function()`
   implementation at `taint_tracker.py` lines 285-306. The plan proposes inserting a guard
   before line 291 (`source_var = self._find_assigned_var_near_line(...)`) that sets
   `source_var = None` for `func_param` sources. The existing fallback at line 306
   (`state.add_taint(source.function, initial_step)`) then correctly seeds the parameter
   name as the tainted variable.

4. **Acceptance criterion #13** explicitly requires: "`func_param` sources bypass
   `_find_assigned_var_near_line()` in taint seeding, verified by integration test."

5. **Integration test `test_func_param_bypasses_assigned_var_lookup`** verifies end-to-end
   that the taint path shows the parameter name (not a nearby local variable) as the source.

6. **WG1 (Core Logic)** correctly includes `taint_tracker.py` (file #13) alongside the
   param extractor and backend integration.

7. **Rollout Phase 2** now reads: "Tree-sitter parameter extraction + TaintEngine seeding fix."

8. **Deviations table** includes: "Small change to `TaintEngine._analyze_function()`" with
   justification that it is a 3-line guard that does not alter behavior for other categories.

9. **Assumption #3** now reads: "...Injecting synthetic parameter sources into the sources
   list for each function is sufficient to seed taint from parameters, **with a small
   modification** to the seeding logic for `func_param` category sources (see Section 4c)."

The Round 1 claim that the plan stated "No changes to TaintEngine are needed" has been
thoroughly corrected. The revised plan acknowledges the modification in nine distinct
locations.

**Status: RESOLVED.**

---

### m-1: Semgrep conditional rule inclusion mechanism -- RESOLVED

The revised plan (Section 5) now specifies the separate-directory approach:

- Parameter source rules go in `registries/semgrep/c-param-sources/param-sources.yaml`
  (a separate directory from the main `registries/semgrep/c/` rules).
- The `SemgrepBackend.scan_files()` method conditionally adds a second
  `--config registries/semgrep/c-param-sources/` argument when `c_param_sources` is enabled.
- The plan explicitly notes: "Multiple `--config` flags are supported by the Semgrep CLI."
- The rationale paragraph explains why a separate directory is necessary (Semgrep CLI
  recursively includes all `.yaml` files in a `--config` directory and does not support
  per-file exclusion).

This matches the reviewer's recommended approach (1) from Round 1. **RESOLVED.**

---

### m-2: Semgrep rule pattern may not match all parameter positions -- ACKNOWLEDGED

The plan acknowledges this in Section 5 ("Important limitation") and Risk #5 ("Semgrep Rule
Pattern Limitations"), stating the Semgrep rules are "best effort" and recommending
`DCS_SCANNER_BACKEND=treesitter` for maximum coverage. The limitation is appropriately
scoped -- this is inherent to Semgrep's pattern DSL, not a plan deficiency.

**Status: Acknowledged (no further action needed).**

---

### m-3: `argc` exclusion list -- ACKNOWLEDGED

The `argc` exclusion uses a tuple literal (`if param_name in ("argc",)`) in Section 4a, line
282. This is easily extensible. The plan defers broader parameter-name heuristics to a future
plan (Section 4a docstring, Risk #1 mitigation (e)).

**Status: Acknowledged (deferred by design).**

---

### m-4: Function pointer parameters -- RESOLVED

The revised plan now documents function pointer parameter handling in the
`_extract_params_from_function()` docstring (Section 4a, "Special cases handled" list):
"Function pointer parameters: void (*callback)(int) -> no identifier at expected level,
returns None from `_extract_param_name()`, skip (correct behavior -- function pointer
params are not taintable data)."

A dedicated test case (`test_function_pointer_param_skipped`) is included in the test plan.

**Status: RESOLVED.**

---

### m-5: `Source.function` field semantics overloaded -- RESOLVED

The revised plan documents this in three places:

1. **Assumption #4** explicitly states the overloading is intentional and explains the
   mechanical correctness: "For `func_param` sources it holds the parameter name like
   `"buf"`. This overloading is intentional -- the taint engine uses `source.function`
   as the seed variable name, and for parameter sources the parameter name IS the correct
   variable."

2. **Source Category section (Section 7)** discusses how downstream consumers can distinguish
   via `source.category == "func_param"`.

3. **Deviations table** includes: "`Source.function` field holds parameter name instead of
   source API name" with justification.

**Status: RESOLVED.**

---

### m-6: `ScannerBackend` protocol change -- NO CHANGE NEEDED

This was already handled correctly in the Round 1 plan. The revised plan maintains the same
approach (defaulted parameter, atomic commit). No action was required. **UNCHANGED.**

---

### m-7: Missing test for multi-line parameter declarations -- RESOLVED

The revised test plan (Section "Test Module: test_param_source_extractor.py") now includes:

- `test_multi_line_params` -- multi-line parameter list (`void f(\n  char *buf,\n  int len\n)`)
  produces correct sources with correct line numbers.

**Status: RESOLVED.**

---

## New Concerns

### No new Critical or Major concerns.

The revisions are well-targeted and do not introduce new feasibility risks. Three observations
at the Minor/Informational level:

#### Observation 1: `_MIN_PARAM_NAME_LENGTH = 2` is a reasonable but imperfect heuristic

The plan introduces a minimum parameter name length filter (Section 4a) to mitigate
substring-match false positives in `_check_sink_reachability()`. This is sound for
single-character names (`n` matching `printf`, `internal`, etc.) but 2-character names
can still collide (e.g., `fd` matching `fd_set`, `fd_table`). The plan explicitly
acknowledges this in Risk #2 and positions the threshold as tunable.

No action needed. This is a pragmatic v1 tradeoff, not a feasibility concern.

#### Observation 2: `_is_static()` defense-in-depth for grammar robustness

The revised `_is_static()` implementation (Section 4a, lines 167-191) checks for
`storage_class_specifier` both as a direct child of `function_definition` AND inside a
`declaration_specifiers` child. This was prompted by the Round 1 finding that the
specifier is a direct child (not nested). The dual check is good defensive coding --
if a future tree-sitter-c grammar version restructures the AST, the fallback path
still works.

No concern. This is a positive design choice.

#### Observation 3: Orchestrator parameter threading path

The plan describes `c_param_sources` flowing through: CLI/MCP -> `HunterOrchestrator.scan()`
-> `self._backend.scan_files()`. Verified against `orchestrator.py` line 117-118:
```python
backend_result = self._backend.scan_files(
    target_path, discovered_files, severity_threshold
)
```

The plan correctly identifies this as the call site that needs `c_param_sources` added.
The orchestrator's `scan()` method (line 67) also needs the new parameter, defaulting
from `config.c_param_sources` when not explicitly provided. Both are listed in Files to
Modify (#12).

No concern. The threading path is straightforward.

---

## Complexity Assessment Update

| Component | Round 1 Estimate | Round 2 Estimate | Change |
|-----------|-----------------|-----------------|--------|
| `param_source_extractor.py` | ~100 lines | ~120 lines | Slightly up: `_MIN_PARAM_NAME_LENGTH` filter, function pointer docstring, multi-line handling. Still a single module. |
| Config + env var | Trivial | Trivial | No change. |
| `TreeSitterBackend` integration | ~8 lines | ~8 lines | No change. |
| `SemgrepBackend` integration | ~15 lines | ~15 lines | No change. Separate directory + second `--config` is clean. |
| `ScannerBackend` protocol | 1 line | 1 line | No change. |
| `HunterOrchestrator.scan()` | ~8 lines | ~8 lines | No change. |
| CLI changes | ~20 lines | ~20 lines | No change. |
| MCP server changes | ~20 lines | ~20 lines | No change. |
| `TaintEngine` change | ~3 lines | ~3 lines | Now correctly estimated (was 0 in the original plan). |
| Tests | ~350 lines | ~400 lines | Slightly up: `test_function_pointer_param_skipped`, `test_multi_line_params`, `test_func_param_bypasses_assigned_var_lookup`. |
| Semgrep rule file | ~50 lines | ~50 lines | No change. |

**Total estimated effort:** 1-2 days for an implementer familiar with the codebase. Unchanged
from Round 1.

---

## Summary

The revised plan comprehensively addresses all Round 1 findings:

- **M-1 (Major, must-do):** Fully resolved. The `taint_tracker.py` modification is now
  specified in nine distinct locations: Assumption #3, Section 4c (dedicated subsection with
  code), Files to Modify #13, WG1, Rollout Phase 2, Deviations table, Acceptance Criterion
  #13, integration test, and the existing-tests impact note. The proposed 3-line guard has
  been verified against the actual `_analyze_function()` implementation and is correct.

- **m-1 (should-do):** Resolved. Separate directory approach specified.
- **m-4 (nice-to-have):** Resolved. Function pointer handling documented and tested.
- **m-5 (nice-to-have):** Resolved. `Source.function` overloading documented in three places.
- **m-7 (should-do):** Resolved. Multi-line parameter test added.
- **m-2, m-3, m-6:** Acknowledged or already handled; no further action needed.

No new Critical or Major feasibility concerns were introduced by the revisions. The plan
is ready for implementation.

**Verdict: PASS**
