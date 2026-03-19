# Review: conditional-assignment-sanitizer.md (Revised)

**Plan:** `./plans/conditional-assignment-sanitizer.md`
**Reviewed:** 2026-03-19
**Verdict:** PASS

---

## Conflicts with CLAUDE.md

No conflicts found. All Critical Rules (Security and Code Quality) are satisfied.

| CLAUDE.md Rule | Status | Notes |
|---|---|---|
| Never `yaml.load()` -- always `yaml.safe_load()` | Compliant | No YAML loading added. Registry loading is unchanged. |
| Never `eval()`, `exec()`, `shell=True` | Compliant | No new use of prohibited functions. Plan adds AST node-type handling and set operations only. |
| All subprocess calls use list-form arguments | N/A | No new subprocess calls. |
| All file paths validated through `mcp/path_validator.py` | N/A | No new file path handling. |
| All container operations enforce full security policy | N/A | No container operations. |
| Jinja2 SandboxedEnvironment | N/A | No template rendering. |
| `mcp/input_validator.py` validates RawFinding fields | N/A | No changes to input validation. |
| Pydantic v2 for all data-crossing models | Compliant | No new Pydantic models. `TaintState` is an internal `@dataclass` (not a data-crossing boundary), consistent with existing codebase pattern. `TaintPath.sanitized` and `TaintPath.sanitizer` Pydantic fields are reused unchanged. |
| Type hints on all public functions | Compliant | All new methods shown in the plan have full type annotations (e.g., `_handle_if_sanitizer(self, if_node: Any, state: TaintState) -> None`). |
| `__all__` in `__init__.py` | Compliant | No new modules created. `TaintState` and `TaintEngine` are already exported. |
| pathlib.Path over os.path | Compliant | No new path operations. |
| No mutable default arguments | Compliant | `_SIZE_SANITIZABLE_CATEGORIES` uses `frozenset` (immutable). New `sanitized_vars` field on `TaintState` uses `field(default_factory=dict)`, the correct dataclass pattern. No violations. |
| 90%+ test coverage | Compliant | Plan specifies `make test-hunter`, `make test`, and 90%+ coverage. Acceptance criterion 13 requires it. |
| Registries in YAML files, never hardcoded | Compliant | The conditional sanitizer is a code-level pattern (AST shape matching), not a registry entry. `_SIZE_SANITIZABLE_CATEGORIES` is a module constant tightly coupled to pattern-matching logic, which is architecturally appropriate. No registry changes. |
| `models.py` per phase | Compliant | No new models files. |
| `orchestrator.py` per phase | Compliant | No orchestrator changes. |
| Test fixtures in `tests/fixtures/` | Compliant | New fixtures go in `tests/fixtures/safe_samples/c/`. |

---

## Feasibility Review Concerns Resolution

The feasibility review (`conditional-assignment-sanitizer.feasibility.md`) identified several concerns. The revised plan addresses all of them:

### M-2 (Re-taint after sanitization): RESOLVED

The plan's `add_taint()` method now includes `self.sanitized_vars.pop(var_name, None)` to clear stale sanitization when a variable is re-tainted. Test case 12 (`test_retaint_after_sanitize_clears_sanitization`) verifies this behavior. Lines 155-165 of the plan show the updated `add_taint` method with the clearing logic.

### m-1 (Numeric literal bounds): RESOLVED

The plan introduces `_node_to_comparison_operand` (a superset of `_node_to_var_name` that also accepts `number_literal` nodes) for use in comparison extraction. Test case 8 (`test_if_clamp_numeric_literal_bound`) exercises this. The method is correctly separated from `_node_to_var_name` to avoid treating literals as taint-trackable variable names.

### m-2 (Verify RHS is non-tainted): RESOLVED

The method was renamed from `_find_reassignment_in_body` to `_find_nontainted_reassignment_in_body` and now explicitly checks that the RHS is not tainted via `self._is_rhs_tainted(rhs, state, [])`. Test case 14 (`test_if_clamp_tainted_rhs_not_sanitized`) verifies that `if (n > m) n = m;` where both `n` and `m` are tainted does NOT trigger sanitization.

### m-3 (CWE-category filtering with same variable): RESOLVED

Test case 5 (`test_same_var_bounds_check_no_sanitize_for_injection`) exercises the category filtering by bounds-checking `val` and then using `val` in a path that leads to a non-size sink. This verifies that `_SIZE_SANITIZABLE_CATEGORIES` is the mechanism preventing sanitization, not variable identity.

### M-3 (Sanitization target asymmetry): RESOLVED

The plan documents the asymmetry between Pattern 1 and Pattern 2 sanitization targets at line 419: "Pattern 1 (if-statement) sanitizes the condition variable `cmp_var` because it is reassigned in-place in the body. Pattern 2 (ternary) sanitizes the assignment target `lhs_name` because the ternary expression produces a new bounded value assigned to the LHS."

### F-1 (Fallback path missing conditional sanitization): RESOLVED

The plan explicitly addresses the fallback substring-match path in `_check_sink_reachability` (lines 570-586). Both the primary path and the fallback path now check `state.is_sanitized_for()`. This was called out in the plan's Assumption 3, the `_check_sink_reachability` Enhancement section, and Acceptance Criterion 6.

### F-2 (Ternary branch ordering verification): RESOLVED

The `_check_ternary_clamp` method includes a detailed branch ordering verification table and implementation (lines 422-518). Test case 3 (`test_ternary_max_not_sanitized`) verifies that `(i > num) ? i : num` (a MAX operation) is correctly rejected. Test case 5 from the acceptance criteria reinforces this.

---

## Historical Alignment

### H-1: Consistent with c-language-support.md (PASS)

The plan builds directly on the C taint tracker infrastructure introduced by `c-language-support.md`:
- Uses the same `_LANGUAGE_NODE_TYPES["c"]` mapping
- Extends the same `_node_to_var_name` (via a separate `_node_to_comparison_operand` method, not modifying the original)
- Uses the same `_extract_lhs_name` and `_is_rhs_tainted` methods
- Operates within the intraprocedural-only limitation (Non-Goal 1)
- Does not add preprocessor resolution (consistent with predecessor's Non-Goal 2)
- Does not address CWE-416 use-after-free (consistent with predecessor's Non-Goal 9 and CLAUDE.md Known Limitation 8)
- No contradictions with predecessor design decisions detected.

### H-2: Consistent with intraprocedural taint limitation (PASS)

The plan explicitly acknowledges intraprocedural-only analysis (Non-Goal 1: "This plan does not add cross-function bounds-check tracking"). The deferred Pattern 3 (guard-branch) and Non-Goal "Complex dataflow patterns" are consistent with the v1 scope.

### H-3: Consistent with suppressions-file.md (PASS)

The plan explicitly positions itself as complementary to suppressions: "This plan addresses the root cause (taint tracker not modeling bounds checks) rather than the symptom (suppressing individual findings)." No changes to suppression logic.

### H-4: Consistent with deep-code-security.md base architecture (PASS)

The plan relies on the existing `TaintPath.sanitized` / `sanitizer_score()` / confidence scoring pipeline. The 25% weight for sanitizer_score is verified at `confidence.py` line 161: `base = (0.45 * taint) + (0.25 * sanitizer) + (0.20 * cwe_baseline)`. The `_compute_raw_confidence` method in `orchestrator.py` returns 0.3 for sanitized findings, and `_deduplicate_findings` keeps the highest-confidence finding per `(file, sink_line, cwe)` key. Both verified against actual codebase (lines 281-300 and 352+ of `orchestrator.py`).

### H-5: Consistent with sast-to-fuzz-pipeline.md (PASS)

No fuzzer changes proposed. The plan does not touch the bridge, fuzz targets, or fuzzer execution.

### H-6: Consistent with output-formats.md (PASS)

No output format changes. Sanitized findings flow through existing formatters via `TaintPath.sanitized=True`.

### H-7: CLAUDE.md update task present (PASS)

Phase 5 of the Rollout Plan and Acceptance Criterion 14 require CLAUDE.md Known Limitations update. Task 4 in Files to Modify specifies `CLAUDE.md`. This follows the precedent established by `c-language-support.md` (which also required a CLAUDE.md update task).

---

## Context Alignment Section

Present and substantive. The section:
- Enumerates seven CLAUDE.md patterns and confirms compliance for each (Security rules, Pydantic v2, type hints, registry conventions, file conventions, test fixtures)
- References three prior plans (`c-language-support.md`, `suppressions-file.md`, `deep-code-security.md`) with specific justifications
- Documents three deviations from established patterns, each with clear rationale:
  1. `_SIZE_SANITIZABLE_CATEGORIES` as module constant (not registry entry) -- justified because it is a structural pattern, not a function name
  2. C-only implementation guard -- justified because Python/Go do not produce CWE-119/120/190 findings
  3. `_node_to_comparison_operand` as separate method -- justified to avoid polluting `_node_to_var_name` with literal handling

No issues.

---

## Context Metadata Block

Present at the end of the file (lines 936-941):
```
<!-- Context Metadata
discovered_at: 2026-03-19T02:30:00Z
claude_md_exists: true
recent_plans_consulted: c-language-support.md, suppressions-file.md, sast-to-fuzz-pipeline.md
archived_plans_consulted: none
-->
```

`claude_md_exists: true` is correct (CLAUDE.md exists in the project root). No flags.

---

## Assumption Verification

All eight assumptions were checked against the actual codebase:

1. **`_propagate_taint` line references (349-373):** Verified. Line 349 is `def _propagate_taint(`, line 373 is `visit(func_node)`. The `visit()` function only processes assignment nodes and recurses otherwise. Accurate.
2. **`TaintState` line references (53-88):** Verified. Line 53 is `@dataclass`, line 88 is end of `copy()`. No `sanitized_vars` field exists. Accurate.
3. **`_check_sink_reachability` line references (565-622):** Verified. Line 565 is `def _check_sink_reachability(`, line 622 is `return False, [], None`. Two reachability paths confirmed: primary via `_check_args_for_taint` (lines 593-605) and fallback substring-match (lines 607-620). Accurate.
4. **Tree-sitter C AST node types:** `if_statement` and `conditional_expression` are standard tree-sitter-c grammar nodes. Reasonable.
5. **`TaintPath.sanitized` and `TaintPath.sanitizer` fields:** Verified at `models.py` lines 75-79. `sanitizer_score()` returns 0.0 when `sanitized=True` (line 89-90 of `confidence.py`). The 25-point reduction claim is correct (0.25 * 100 = 25 vs 0.25 * 0 = 0). Accurate.
6. **OpenSSL analysis claim:** Cannot be independently verified from the codebase, but does not affect technical correctness.
7. **`_compute_raw_confidence` and `_deduplicate_findings`:** Verified at `orchestrator.py` lines 281-300 and 352+. `_compute_raw_confidence` returns 0.3 for sanitized, 0.6-0.8 for unsanitized. `_deduplicate_findings` groups by `(file, sink_line, cwe)` and keeps highest confidence. Accurate.
8. **`_node_to_var_name` node types:** Verified. The method handles `identifier`, `qualified_type`, `type_identifier`, `pointer_declarator`, `subscript_expression`, and `parenthesized_expression`. No `number_literal` handling. Accurate.

---

## Required Edits

None. The plan is technically sound, addresses all feasibility review concerns, is consistent with CLAUDE.md rules, and is historically aligned with predecessor plans.

---

## Optional Suggestions

### S-1: Sink category string coupling test

The `_SIZE_SANITIZABLE_CATEGORIES` frozenset uses string literals (`"buffer_overflow"`, `"memory_corruption"`, `"integer_overflow"`) that must match the sink category keys in `registries/c.yaml`. Consider adding a test that asserts these strings are valid sink category keys in the loaded C registry. This is low-risk (the strings have been stable since `c-language-support.md`) but would make the coupling explicit and catch future registry renames.

### S-2: Sanitization propagation through reassignment

When a sanitized variable is copied to a new variable (`m = n`), the new variable inherits taint via `_handle_assignment` but does NOT inherit the sanitization annotation from `sanitized_vars`. This means `m` would be flagged as unsanitized at a later sink. This is a conservative choice (fewer false negatives) but could be documented explicitly in the plan's Non-Goals or Risks section. It is not a correctness issue.

### S-3: Test coverage for operator direction

The test plan exercises `>` (test 1), ternary `>` (test 2), and numeric literal with `>` (test 8), but does not include a test case for `<` or `<=` operators in Pattern 1 (if-statement clamp). While the code handles all four operators, adding a test for `if (n < max)` would verify the reversed-operator path. This is a test completeness suggestion, not a design issue.

### S-4: Unreachable code at line 518

The `_check_ternary_clamp` method has `return False` at line 518 after the `if/else` branches at lines 499-516. Both branches already return, so line 518 is unreachable. This is harmless but will show up in coverage reports. Consider removing the trailing `return False` or restructuring slightly to avoid the dead code.

---

**Reviewer:** Librarian (automated)
**Plan status:** DRAFT -- approved for implementation. No required edits remain.
