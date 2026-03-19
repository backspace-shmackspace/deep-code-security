# Feasibility Review: Conditional Assignment Sanitizer for C Hunter (Revised)

**Plan:** `./plans/conditional-assignment-sanitizer.md`
**Reviewer:** code-reviewer agent
**Date:** 2026-03-19
**Verdict:** PASS

---

## Summary

This is a re-review of the revised plan. Five prior findings were targeted for remediation:

- M-2: `add_taint()` clears `sanitized_vars` on re-taint
- m-1: `_node_to_comparison_operand` handles `number_literal` nodes
- F-2: Ternary branch ordering verification against operator direction table
- F-1: Fallback path in `_check_sink_reachability` also patched
- F-3: Deduplication interaction documented as intentional

All five are adequately addressed. The plan is technically feasible and implementation-ready. Two minor implementation-level concerns remain that do not block proceeding, and one unreachable dead-code line warrants a note.

---

## Prior Finding Disposition

### M-2: Re-taint clears sanitization (was "Must Fix") -- RESOLVED

The revised `add_taint` pseudocode (plan lines 155-165) adds `self.sanitized_vars.pop(var_name, None)` as the last line of the method. This is exactly the one-line fix the prior review recommended. The call uses `.pop(key, None)` which is safe when the key is absent -- no `KeyError` risk.

Test 12 (`test_retaint_after_sanitize_clears_sanitization`) validates the behavior end-to-end with the `n = atoi(argv[2])` re-taint pattern.

The fix interacts correctly with the else-branch re-taint edge case raised by redteam F-8: when the else branch reassigns the variable from a tainted source, `_handle_assignment` calls `add_taint`, which clears the stale `sanitized_vars` entry. The re-tainted state is correctly unsanitized at subsequent sinks.

### m-1: Numeric literal bounds (was "Consider") -- RESOLVED

The revised plan introduces `_node_to_comparison_operand` (plan lines 324-341) as a purpose-built superset of `_node_to_var_name`. It calls `_node_to_var_name` first (preserving all existing identifier-extraction logic) and falls back to accepting `number_literal` nodes, returning the literal text (e.g., `"4096"`).

Critically, this method is used exclusively by the comparison extractors (`_extract_comparison`, `_extract_comparison_from_node`) and NOT by `_node_to_var_name` itself or by the taint propagation logic. This maintains the correct invariant that numeric literals are never treated as tainted variable names in taint tracking. The separation is clean.

Test 8 (`test_if_clamp_numeric_literal_bound`) covers `if (n > 4096) n = 4096;`. The plan does not add a test for ternary with numeric literal bound (e.g., `n = (n > 4096) ? 4096 : n;`) -- this is a minor test coverage gap but not a correctness issue, since `_node_to_comparison_operand` is called uniformly by both pattern recognizers.

### F-2: Ternary branch ordering (was "Critical" in redteam) -- RESOLVED

The plan adds a "Branch Ordering Verification" section (lines 93-101) with an operator direction table, and the full `_check_ternary_clamp` pseudocode (lines 426-518) implements a four-way dispatch:

- `var_is_tainted=True`, op `>` or `>=`: overflow branch is "then", so `true_name == bound_name` required
- `var_is_tainted=True`, op `<` or `<=`: overflow branch is "else", so `false_name == bound_name` required
- `var_is_tainted=False` (tainted on right), op `<` or `<=`: same as first case (semantically equivalent)
- `var_is_tainted=False`, op `>` or `>=`: same as second case

The table covers the `(bound OP tainted)` reversed-operand form, which is an important edge case for code like `if (64 > n)`. The logic is correct.

The plan explicitly requires both `true_name == bound_name` AND `false_name == tainted_name` (not just one of them), meaning it rejects partial matches where one branch is something other than the two known operands (e.g., a function call). This is conservative and correct.

Test 3 (`test_ternary_max_not_sanitized`) validates that `(i > num) ? i : num` (a MAX, not a clamp) is rejected.

One dead-code line: after the `if var_is_tainted / else` block at plan line 499, there is `return False` at line 518. Every branch of the `if/else` returns explicitly, so this line is unreachable. It does not affect correctness but should be removed during implementation.

### F-1: Fallback path in `_check_sink_reachability` (was "Critical" in redteam) -- RESOLVED

The revised plan (lines 569-586) patches the fallback substring-match loop to check `state.is_sanitized_for(tainted_var, sink.category)` before returning, setting `fallback_sanitizer = "conditional_bounds_check"` when the check passes. The patched fallback returns `fallback_sanitizer` instead of the hardcoded `None` in the original.

This matches the redteam's recommendation exactly. Both the primary path (`tainted_arg is not None`) and the fallback path (substring match) now consistently apply conditional sanitization.

Assumption 3 in the revised plan explicitly acknowledges both paths: "The method has **two** reachability paths...Both paths must be patched to check conditional sanitization." This awareness is now reflected in the implementation and the acceptance criteria (criterion 6).

### F-3: Deduplication interaction (was "Major" in redteam) -- RESOLVED AS DOCUMENTED

The plan adds a "Deduplication Interaction" section (lines 130-138) that explicitly analyzes the behavior: deduplication keeps the highest-confidence finding, so sanitized findings (confidence 0.3) lose to unsanitized ones (confidence 0.6-0.8) at the same sink. This is correct behavior.

Goal 3 is narrowed: "This target applies only when **all** source-to-sink taint paths for a given sink are conditionally sanitized." The plan also confirms that the cited OpenSSL examples (passphrase.c `src_len`, pem_lib.c `i`, params.c size variables) have single-source paths with no competing unsanitized taint flow, so the FP reduction target is achievable for those cases.

No code change is needed or warranted. The documentation closes the design gap.

---

## Remaining Concerns

### Minor: `_extract_assignment_rhs` logic is fragile (Implementation Risk)

The pseudocode at plan lines 382-400 finds the RHS of an assignment by iterating children and looking for a node whose type is NOT in a set of LHS types and whose text is a known operator token. The two-condition check is inverted from what one might expect: the type exclusion and the text check together identify the operator node, and the method returns `children[i + 1]` (the node after the operator).

This works for simple cases but has a latent risk: the type exclusion list (`"identifier"`, `"pointer_declarator"`, `"subscript_expression"`, `"field_expression"`) is hardcoded and does not cover all possible LHS node types. For example, a `parenthesized_expression` on the LHS (unusual but legal in C for pointer indirection `(*p) = val`) would not be excluded and could cause the method to misidentify the `(` token or the expression itself as the operator position.

The simpler and more robust approach during implementation is to scan for the first child whose text is `"="` (matching the `init_declarator` child directly on the operator token) and return the next sibling. The existing `_handle_assignment` parsing (plan lines 427-433) already uses `non_op = [c for c in children if c.type not in ("=", "+=")]` as a more direct approach.

This does not block the plan but the implementer should be aware that `_extract_assignment_rhs` will need careful testing against the actual tree-sitter C AST, particularly for `n = 4096` (number_literal RHS), `n = max - 1` (binary_expression RHS), and `n = some_struct.field` (field_expression RHS).

### Minor: No ternary test with numeric literal bound

Test 8 covers `if (n > 4096) n = 4096;` (Pattern 1 with numeric literal). No test covers `n = (n > 4096) ? 4096 : n;` (Pattern 2 with numeric literal). Since `_node_to_comparison_operand` is used by both patterns, this gap is low risk, but it would provide confirmation that the ternary branch ordering logic works when `bound_name` is `"4096"` rather than an identifier.

**Recommendation:** Add as test 15 in `TestConditionalSanitizer`, or include a numeric-literal ternary case in the `conditional_bounds.c` fixture.

### Minor: `_find_nontainted_reassignment_in_body` stops on first match of `var_name`

When the if-body assigns `var_name` to a tainted RHS, the method returns `False` immediately (plan lines 372-373) rather than continuing to look for a second assignment to `var_name` later in the body. In the degenerate case:

```c
if (n > 64) {
    n = m;      // tainted RHS -- first match, returns False
    n = 64;     // non-tainted -- never reached
}
```

The second (safe) assignment is invisible. This is unlikely in real code and the fail-open result (no sanitization applied) is the correct conservative outcome, but it is worth documenting in the implementation as intentional.

### Info: Unreachable `return False` at end of `_check_ternary_clamp`

Plan line 518 (`return False`) follows an `if var_is_tainted / else` block where every branch returns explicitly. This line is dead code. Remove it during implementation.

### Info: No integration test against OpenSSL for Goal 3

As noted in the prior review, Goal 3's FP reduction claim cannot be verified mechanically by the test suite. The plan now clarifies the qualifying condition (all paths sanitized), which is verifiable per-finding, but the aggregate "from ~95% to <80%" claim requires manual measurement. This is an acceptable limitation given the cost of maintaining an OpenSSL fixture.

---

## Test Coverage Assessment

The revised test plan has 14 unit tests plus a fixture end-to-end path. Coverage of the five closed findings is as follows:

| Finding | Test Coverage |
|---------|--------------|
| M-2 (re-taint clears) | Test 12 (direct unit test of the re-taint scenario) |
| m-1 (numeric literals) | Test 8 (if-clamp with literal `4096`) |
| F-2 (branch ordering) | Test 3 (MAX anti-pattern rejection) |
| F-1 (fallback path) | Not directly tested by name -- covered implicitly by end-to-end tests when the fallback path fires; no targeted unit test for the fallback path specifically |
| F-3 (deduplication) | Test 13 (multi-var, one sanitized one not -- exercises the dedup winner correctly) |

F-1 (the fallback path patch) does not have a dedicated test that forces the fallback path to fire. The fallback path fires when `_check_args_for_taint` returns `(None, None)` because no argument list node is found or the tainted variable appears in a complex expression. A targeted test that exercises this path (e.g., a sink where the tainted variable appears in a cast expression as the argument) would confirm the patch. This is a test coverage gap for a formerly Critical finding.

**Recommendation:** Add a test case where the tainted variable reaches the sink via the fallback substring-match path (e.g., `memcpy(dst, src, (size_t)n)` where the cast prevents `_check_args_for_taint` from resolving `n` via normal argument traversal) and verify that `taint_path.sanitized=True` when `n` has been bounds-checked. This is the highest-priority missing test.

The new tests for category filtering (tests 4 and 5 together) now properly exercise `_SIZE_SANITIZABLE_CATEGORIES`: test 4 validates variable identity isolation and test 5 validates CWE-category filtering on the same variable. This addresses the prior m-3 concern.

---

## Backward Compatibility

No changes to this assessment from the prior review. The plan remains purely additive:

- `TaintState` gains fields with defaults -- existing instantiations are unaffected
- `add_taint` gains a `.pop()` call on a field that does not yet exist in production -- safe to add first
- `_propagate_taint` adds an `elif` branch C-only -- Python/Go paths unchanged
- `_check_sink_reachability` fallback path replaces hardcoded `None` with a conditional -- only changes behavior when `is_sanitized_for` returns True, which requires the new `sanitized_vars` to be populated
- No Pydantic model changes, no CLI/MCP changes, no registry changes

---

## Complexity Assessment

| Component | Estimated Complexity | Assessment |
|-----------|---------------------|------------|
| `TaintState` extension | Low | Clean dataclass field addition plus three methods |
| `add_taint` modification | Trivial | One `.pop()` call |
| `_handle_if_sanitizer` | Medium | AST pattern matching; defensive early returns throughout |
| `_extract_comparison` / `_extract_comparison_from_node` | Low-Medium | Simple child extraction; two variants |
| `_node_to_comparison_operand` | Low | Thin wrapper over `_node_to_var_name` plus one type check |
| `_find_nontainted_reassignment_in_body` | Low-Medium | Recursive tree search plus RHS taint check |
| `_extract_assignment_rhs` | Low-Medium | Operator token scan; fragile (see concern above) |
| `_check_ternary_clamp` | Medium | Four-way operator direction dispatch; pseudocode is close to production-ready |
| `_check_sink_reachability` patch | Low | Two targeted insertions, primary and fallback paths |
| Test fixtures and tests | Low-Medium | 14 tests, 1 new fixture file |

Overall scope is appropriate for a single commit. The most implementation-sensitive components are `_extract_assignment_rhs` (fragility risk) and `_check_ternary_clamp` (correctness depends on tree-sitter's exact child ordering for `conditional_expression` nodes, which should be confirmed against an AST dump before finalizing).

---

## What the Revised Plan Gets Right

1. **All five prior findings addressed.** M-2 and m-1 are code changes with test coverage. F-2 and F-1 are design changes with corresponding acceptance criteria. F-3 is resolved by explicit documentation that correctly characterizes the deduplication as intentional.

2. **Branch ordering table is rigorous.** The four-row operator direction table (plan lines 95-99) and the corresponding four-branch dispatch in `_check_ternary_clamp` cover both operand orderings and both operator directions. This is more complete than the original redteam recommendation.

3. **`_node_to_comparison_operand` separation preserves taint propagation integrity.** The numeric literal handling is contained to the comparison recognizer and cannot bleed into variable identity resolution elsewhere.

4. **Acceptance criteria are updated.** All five addressed findings have corresponding acceptance criteria (criteria 2, 4, 5, 6, 10). The re-taint behavior and numeric literal support are explicitly testable.

5. **Deduplication interaction is now a documented design decision.** Goal 3's qualifying clause prevents the FP reduction claim from being invalidated by the dedup behavior, and the OpenSSL example analysis confirms the target cases have single-path taint flows.

6. **Test count increased from 8 to 14.** Tests 9-14 address the unit-level `TaintState` methods, the re-taint scenario, the multi-variable isolation, and the tainted-RHS non-clamp case. These were all missing in the original plan.

---

## Recommended Actions Before Implementation

1. **[Should Fix] Add a test that forces the fallback path in `_check_sink_reachability`.** This is the only formerly Critical finding (F-1) without a targeted test. A cast-expression argument like `memcpy(dst, src, (size_t)n)` may be sufficient to bypass `_check_args_for_taint`'s argument resolution and trigger the substring fallback.

2. **[Should Fix] Add a ternary test with numeric literal bound.** Complete the m-1 coverage by testing `n = (n > 4096) ? 4096 : n;` through `TestConditionalSanitizer`.

3. **[Consider] Simplify `_extract_assignment_rhs`.** Scan for the `=` operator child by text content (matching on the operator token directly) rather than the current type-exclusion approach. This reduces fragility without changing behavior.

4. **[Consider] Remove the unreachable `return False` at the end of `_check_ternary_clamp`.** Dead code.

---

## Verdict: PASS

The revised plan adequately addresses all five prior findings. The critical and major issues from the prior review are resolved either by code changes with test coverage or by explicit design documentation. The remaining concerns are minor implementation-level risks that can be addressed during coding without requiring another plan revision. The plan is technically feasible and ready to proceed to implementation.
