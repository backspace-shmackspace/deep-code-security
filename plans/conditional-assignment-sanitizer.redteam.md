# Red Team Review: Conditional Assignment Sanitizer for C Hunter (Revised)

**Reviewed:** `plans/conditional-assignment-sanitizer.md` (post-revision addressing F-1, F-2, F-3, M-2, m-1/F-7)
**Reviewer:** Security Analyst
**Date:** 2026-03-19

## Verdict: PASS

No Critical findings remain. The previous Critical finding (F-1: fallback path bypass) has been adequately addressed -- both reachability paths in `_check_sink_reachability` now check conditional sanitization. The previous Major findings (F-2: ternary branch ordering, F-3: deduplication interaction) and the Minor findings (M-2: stale sanitization on re-taint, F-7: numeric literal bounds) have also been resolved. Four new findings are identified (one Major, three Minor), plus two Info items. The Major finding (R-1) concerns an ordering ambiguity in the ternary sanitization path that could cause the feature to silently fail.

---

## Prior Findings: Disposition

| Original | Status | Notes |
|---|---|---|
| F-1 (Critical): Fallback path bypasses sanitization | **Resolved** | Plan now patches both the primary path (lines 562-564) and the fallback path (lines 574-586). Both paths check `state.is_sanitized_for()` before returning. |
| F-2 (Major): Ternary accepts MAX patterns | **Resolved** | Plan adds branch ordering verification table (lines 93-100) and detailed code in `_check_ternary_clamp` (lines 487-518) that distinguishes clamps from MAX operations by validating which branch contains the bound vs. the tainted variable. |
| F-3 (Major): Deduplication discards sanitized findings | **Resolved** | Plan documents the interaction as intentional (lines 130-138), clarifies the FP reduction target applies only when all paths are sanitized, and confirms the OpenSSL examples have single source-to-sink paths. |
| M-2: `add_taint()` does not clear stale sanitization | **Resolved** | `add_taint()` now calls `self.sanitized_vars.pop(var_name, None)` (line 165). Test 12 (`test_retaint_after_sanitize_clears_sanitization`) verifies the behavior. |
| F-7/m-1: Numeric literal bounds rejected | **Resolved** | New `_node_to_comparison_operand` method (lines 324-341) accepts `number_literal` nodes. Test 8 (`test_if_clamp_numeric_literal_bound`) covers this. |
| F-4: RHS not checked for taintedness | **Resolved** | `_find_nontainted_reassignment_in_body` (lines 348-379) now checks `not self._is_rhs_tainted(rhs, state, [])`. Test 14 (`test_if_clamp_tainted_rhs_not_sanitized`) covers this. |
| F-6: No multi-variable test | **Resolved** | Test 13 (`test_multi_var_only_clamped_var_sanitized`) added. |
| F-8: `add_taint` stale sanitization | **Resolved** | Same as M-2 above. |

---

## New Findings

### R-1: Ternary sanitization ordering race with `add_taint` in `_handle_assignment` (Major)

**Location:** Plan section "Ternary Handling in `_handle_assignment`" (lines 403-417) vs. existing `_handle_assignment` code (lines 438-450 of `taint_tracker.py`).

**Issue:** The plan specifies that the ternary clamp check runs "Inside `_handle_assignment`, after determining `rhs_tainted` is True" (line 408). However, the existing code within the `if rhs_tainted:` block calls `state.add_taint(lhs_name, step)` for each LHS variable. The revised plan also specifies that `add_taint()` clears `sanitized_vars` entries (line 165: `self.sanitized_vars.pop(var_name, None)`).

The plan does not specify the ordering between the `add_taint()` call and the `add_sanitization()` call. There are two possible insertion points:

**Option A -- Ternary check BEFORE `add_taint`:**
```python
if rhs_tainted:
    # Check ternary clamp first
    if rhs_node.type == "conditional_expression" and self.language == Language.C:
        clamped = self._check_ternary_clamp(rhs_node, state)
        if clamped:
            for lhs_name in lhs_names:
                state.add_sanitization(lhs_name, ...)
    # Then propagate taint
    for lhs_name in lhs_names:
        state.add_taint(lhs_name, step)  # CLEARS sanitized_vars!
```
**Result:** `add_taint` undoes the just-added sanitization. The ternary sanitizer is silently broken.

**Option B -- Ternary check AFTER `add_taint`:**
```python
if rhs_tainted:
    for lhs_name in lhs_names:
        state.add_taint(lhs_name, step)
    # Then check ternary clamp
    if rhs_node.type == "conditional_expression" and self.language == Language.C:
        clamped = self._check_ternary_clamp(rhs_node, state)
        if clamped:
            for lhs_name in lhs_names:
                state.add_sanitization(lhs_name, ...)
```
**Result:** `add_taint` clears any prior sanitization first, then `add_sanitization` correctly adds the new state. This is the correct ordering.

The plan's pseudocode (lines 407-416) is ambiguous. An implementer could reasonably choose Option A, which would silently break all ternary sanitization. The if-statement path (Pattern 1) does not have this problem because `_handle_if_sanitizer` runs before recursing into children, and the if-body's assignment to a non-tainted value does not trigger `add_taint`.

**Impact:** If implemented in the wrong order, all ternary clamp sanitizations silently fail. This is a correctness issue that the plan's test suite (Test 2: `test_ternary_clamp_sanitizes`) would catch, but the plan text should be unambiguous to prevent the error in the first place.

**Recommendation:** Explicitly state in the plan that the ternary clamp check must run AFTER the `add_taint()` call. Modify the pseudocode at lines 407-416 to show the correct insertion point relative to `state.add_taint(lhs_name, step)`. Alternatively, restructure so `add_sanitization` is not cleared by `add_taint` when it is being set in the same assignment -- though this would complicate the invariant.

---

### R-2: `_extract_assignment_rhs` uses a fragile operator-detection heuristic that differs from the established pattern (Minor)

**Location:** Plan section "New Method: `_extract_assignment_rhs`" (lines 382-400).

**Issue:** The existing `_handle_assignment` method for C (lines 425-433 of `taint_tracker.py`) identifies the operator by filtering children with `c.type not in ("=", "+=")` and taking the remaining nodes as `[lhs, rhs]`. This pattern is proven and handles the tree-sitter C grammar correctly.

The new `_extract_assignment_rhs` method uses a different approach: iterating through children, skipping nodes whose type is in a hardcoded allowlist (`"identifier"`, `"pointer_declarator"`, `"subscript_expression"`, `"field_expression"`), and checking the text content of remaining nodes against operator strings. This has two fragility concerns:

1. The allowlist is incomplete. If the LHS is a `parenthesized_expression` (e.g., `(*ptr) = val`), a `cast_expression`, or any other node type not in the allowlist, the method will attempt to match its text against the operator strings, potentially producing incorrect results or returning `None`.

2. The method checks `child.text` of non-allowlisted nodes against operator strings. But a `binary_expression` node on the RHS (e.g., `n = max - 1`) would have text like `"max - 1"`, which does not match any operator string. The method would fail to find the `=` operator because the tree-sitter C grammar represents `assignment_expression` children as `[lhs, "=", rhs]` where `"="` is an anonymous node with type `"="`, not a named node. The method should check `child.type` against operator strings rather than `child.text`.

**Impact:** The method may fail to extract the RHS for certain assignment forms, causing the `_find_nontainted_reassignment_in_body` check to return `False` (no valid clamp recognized). This produces false positives (the safe behavior), not false negatives, but reduces the feature's effectiveness for edge-case if-body patterns.

**Recommendation:** Reuse the existing proven pattern from `_handle_assignment` for C: `non_op = [c for c in children if c.type not in ("=", "+=", "-=", "*=", "/=")]` and take `non_op[-1]` as the RHS. This is simpler and consistent with the codebase.

---

### R-3: Lower-bound ternary clamps are not recognized (Minor)

**Location:** Plan section "Branch Ordering Verification" (lines 93-100) and `_check_ternary_clamp` (lines 487-518).

**Issue:** The branch ordering table (lines 95-98) explicitly targets "clamp to upper bound" semantics. The pattern `n = (n < 0) ? 0 : n` (clamp to lower bound) does NOT match the table:

For `(n < 0) ? 0 : n` with tainted `n` on the left:
- `cmp_op` is `<`
- Plan requires (line 504-506): `true_name == tainted_name` (i.e., `0 == n`) -- FALSE
- The pattern is rejected

Lower-bound clamps are relevant for CWE-190 (integer overflow). Passing a negative value to `malloc()` causes it to be interpreted as a very large unsigned value, leading to an undersized allocation. A lower-bound clamp like `if (n < 0) n = 0;` prevents this. The if-statement pattern (Pattern 1) would correctly recognize this (it checks for any comparison + reassignment to non-tainted value, without branch-ordering constraints). But the ternary equivalent is rejected.

This creates an asymmetry: `if (n < 0) n = 0;` is recognized but `n = (n < 0) ? 0 : n;` is not.

**Impact:** Reduced coverage for lower-bound clamp ternaries. This is a subset of Pattern Coverage Gaps (Risk 2 in the plan) but is not explicitly acknowledged. The impact is limited because upper-bound clamps are the dominant pattern for the target CWEs.

**Recommendation:** Either extend the branch ordering table to include lower-bound clamp semantics, or explicitly document in the Non-Goals or Known Limitations that lower-bound ternary clamps are not recognized (while lower-bound if-statement clamps are).

---

### R-4: `_check_ternary_clamp` punctuation filtering depends on undocumented tree-sitter grammar detail (Minor)

**Location:** Plan section "New Method: `_check_ternary_clamp`" (line 454).

**Issue:** The code `semantic = [c for c in children if c.type not in ("?", ":")]` assumes that the `?` and `:` tokens in a `conditional_expression` have node types literally equal to the strings `"?"` and `":"`. While this is correct for the tree-sitter C grammar (anonymous/unnamed nodes use their text as their type), the plan does not document this assumption or cite the grammar specification.

If the tree-sitter C grammar is updated to use named node types for these tokens (e.g., `"ternary_question"`, `"ternary_colon"`), this filter would break silently -- `len(semantic)` would be 5 instead of 3, and the method would return `False` (safe failure, no sanitization applied).

The plan's Assumption 4 says "Both have been verified via AST dumps" for `if_statement` and `conditional_expression`, but does not mention the specific child node types within `conditional_expression`.

**Impact:** Low. Tree-sitter C grammar is stable and `"?"` / `":"` as anonymous node types is the established convention. Failure mode is safe (no sanitization). But the assumption should be documented for maintainability.

**Recommendation:** Add a brief note to Assumption 4 confirming that `conditional_expression` children include anonymous `"?"` and `":"` nodes, verified via AST dump.

---

### R-5: Pseudo-variable taint matching in fallback path limits sanitization effectiveness (Info)

**Location:** Plan section "`_check_sink_reachability` Enhancement" (lines 570-586) and feasibility review M-1.

**Issue:** The revised fallback path (lines 570-586) iterates `state.tainted_vars` and checks `state.is_sanitized_for(tainted_var, sink.category)`. However, `tainted_vars` includes both actual variable names (e.g., `"src_len"`) and source-pattern pseudo-variables (e.g., `"argv"`, `"getenv"`, `"strlen"`).

When the fallback matches on a pseudo-variable (e.g., `"argv"` appears as a substring in the sink node text), `state.is_sanitized_for("argv", ...)` will return `False` because the conditional sanitization was applied to the actual variable name (`"src_len"`), not the pseudo-variable. This means the fallback path will not apply conditional sanitization for pseudo-variable matches.

This was noted in the feasibility review (M-1) but is not addressed in the revised plan. The feasibility review recommended adding a comment and a test case. The plan does neither.

**Impact:** Low in practice. The pseudo-variable fallback path fires primarily when `_check_args_for_taint` cannot find the argument list. In the common case of `memcpy(dst, src, src_len)`, the primary path would find `src_len` as a tainted argument and apply sanitization correctly. The fallback only fires for unusual AST structures where the argument list is not found.

**Recommendation:** Add a brief note in the plan acknowledging this limitation, per the feasibility review's recommendation.

---

### R-6: No test exercises the fallback reachability path with conditional sanitization (Info)

**Location:** Plan section "Test Plan" (lines 706-858).

**Issue:** The plan's 14 test cases all exercise the primary reachability path (via `_check_args_for_taint`). There is no test that exercises the fallback substring-match path (lines 570-586 in the plan) with a conditionally sanitized variable. The plan invested significant effort in fixing the fallback path (F-1 from the prior review), but the fix is not verified by any test.

This is distinct from R-5 (pseudo-variable mismatch). Even when the fallback matches on a real variable name (not a pseudo-variable), the test suite does not exercise this codepath.

**Impact:** Low. The fallback path's conditional sanitization check is straightforward code, and the primary path tests provide confidence in the `is_sanitized_for` logic. But the F-1 fix was the most critical finding in the prior review, and leaving it untested is a coverage gap.

**Recommendation:** Add a test case that forces the fallback path to fire (e.g., by constructing a sink call expression that `_check_args_for_taint` cannot parse) and verifies that conditional sanitization is applied. Alternatively, add a unit test for the fallback path logic directly.

---

## Summary

| # | Finding | Severity | Category |
|---|---------|----------|----------|
| R-1 | Ternary sanitization ordering race with `add_taint` in `_handle_assignment` | **Major** | Correctness |
| R-2 | `_extract_assignment_rhs` uses fragile operator-detection heuristic | Minor | Implementation |
| R-3 | Lower-bound ternary clamps not recognized (asymmetry with if-statement path) | Minor | Coverage gap |
| R-4 | Punctuation filtering depends on undocumented tree-sitter grammar detail | Minor | Maintainability |
| R-5 | Pseudo-variable taint matching limits fallback path sanitization | Info | Known limitation |
| R-6 | No test exercises fallback reachability path with conditional sanitization | Info | Test coverage |

## Assessment of Prior Fix Quality

The five previously identified issues (F-1, F-2, F-3, M-2, F-7) have been thoroughly addressed. The revised plan demonstrates careful attention to:

- **F-1 fix quality:** Both reachability paths are now patched with detailed pseudocode showing the sanitization check at each point. The fallback path fix is structurally sound.
- **F-2 fix quality:** The branch ordering verification is comprehensive, covering both `(tainted OP bound)` and `(bound OP tainted)` orientations with all four comparison operators. The table at lines 95-98 is clear and the code at lines 487-518 is consistent with the table.
- **F-3 fix quality:** The deduplication analysis (lines 130-138) is well-reasoned. The plan correctly identifies that the FP reduction target applies only to single-path cases, and confirms the OpenSSL examples are single-path.
- **M-2 fix quality:** The `add_taint()` modification (line 165) is minimal and correct. Test 12 provides direct verification.
- **F-7 fix quality:** The `_node_to_comparison_operand` method (lines 324-341) is cleanly separated from `_node_to_var_name`, avoiding contamination of the taint variable namespace with numeric literals.

The remaining Major finding (R-1) is an ordering ambiguity in the plan text rather than a fundamental design flaw. It is resolvable with a clarifying edit to the pseudocode placement.
