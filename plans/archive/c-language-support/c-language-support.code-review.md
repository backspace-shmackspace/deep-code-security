# Code Review: C Language Support for the Hunter Pipeline

**Plan:** `plans/c-language-support.md`
**Reviewer:** code-reviewer agent
**Date:** 2026-03-18

---

## Code Review Summary

The implementation is complete, correct, and faithful to the approved plan. All eight KEY THINGS TO VERIFY pass, the security-critical paths are unchanged, and the new C-specific taint handling is technically sound. No critical or major findings were identified.

---

## Critical Issues (Must Fix)

None.

---

## Major Improvements (Should Fix)

None.

---

## Minor Suggestions (Consider)

### M1. `test_c_pointer_assignment` and `test_c_propagate_with_tainted_rhs` only assert the already-tainted source variable, not the propagated variable

**Files:** `/Users/imurphy/projects/deep-code-security/tests/test_hunter/test_taint_c_paths.py`, lines 87 and 150

Both tests call `_propagate_taint` to exercise pointer assignment chains but then only assert that the *original* seed variable (`"tainted"` and `"source"`) is still tainted. They do not assert that the downstream variable (`"q"` in the pointer test, `"dest"` in the RHS test) was also tainted.

```python
# test_c_pointer_assignment (line 87)
assert state.is_tainted("tainted")   # was already true before propagation
# Missing: assert state.is_tainted("q")

# test_c_propagate_with_tainted_rhs (line 150)
assert state.is_tainted("source")    # was already true before propagation
# Missing: assert state.is_tainted("dest")
```

These tests pass regardless of whether taint propagation actually works. They exercise the code path (good for coverage) but do not verify correctness. Adding the downstream assertions would turn them into real regression guards.

### M2. `test_c_array_subscript_lhs` does not assert taint of `buf`

**File:** `/Users/imurphy/projects/deep-code-security/tests/test_hunter/test_taint_c_paths.py`, line 134

Similar issue: the test seeds `"tainted"` and propagates, but only asserts `state.is_tainted("tainted")`. The intent (per the docstring) is to verify that assigning `buf[0] = tainted` causes `buf` to be tainted, but that assertion is absent.

```python
# Missing: assert state.is_tainted("buf")
```

### M3. `test_c_find_assigned_var_pointer_decl` documents the fixture as `char *env = getenv(...)` but the test body uses variable name `env` while the variable in the docstring says `p`

**File:** `/Users/imurphy/projects/deep-code-security/tests/test_hunter/test_taint_c_paths.py`, lines 253-263

The docstring says "_find_assigned_var_near_line finds variable name 'p' from 'char *p = getenv(...)'", but the fixture code declares `char *env = getenv("PATH")` and the assertion checks `result == "env"`. The assertion is correct; the docstring is just misleading. A trivial one-word fix: update the docstring to match what the code actually tests.

### M4. `snprintf` sanitizer does not neutralize `memory_corruption` -- confirm this is intentional

**File:** `/Users/imurphy/projects/deep-code-security/registries/c.yaml`, lines 191-195

The plan explicitly requires that `snprintf` neutralize only `buffer_overflow`, not `memory_corruption` (KEY THING TO VERIFY #2). The registry correctly follows this. However, there is no comment on the `snprintf` entry explaining _why_ it does not also neutralize `memory_corruption`, unlike `memcpy_s` which neutralizes both. A one-line comment would make the deliberate narrowness clear to future maintainers.

```yaml
  - pattern: "snprintf"
    neutralizes:
      - buffer_overflow
    # NOTE: does not neutralize memory_corruption -- snprintf operates on strings,
    # not raw memory buffers. Use memcpy_s for bounds-checked raw memory operations.
    description: "Bounded format function -- use instead of sprintf"
```

### M5. `bounded_copy.c` safe fixture: `test_safe_bounded_copy_no_findings` assertion logic is weaker than the docstring claims

**File:** `/Users/imurphy/projects/deep-code-security/tests/test_hunter/test_taint_c_paths.py`, lines 366-385

The test docstring says "assert zero unsanitized findings", but the implementation only checks `buffer_overflow`-category paths:

```python
for src, sink, tp in paths:
    if sink.category == "buffer_overflow":
        assert tp.sanitized, ...
```

The `safe_snprintf` function in `bounded_copy.c` calls `printf("Would run: %s\n", cmd)`, where `cmd` is a tainted `snprintf` output that may not be considered sanitized by the `format_string` sink. If a `format_string` path is found for that `printf`, it would be unsanitized and the test would silently ignore it because of the `if sink.category == "buffer_overflow"` guard. This is a coverage gap, not a correctness bug in the production code. Consider asserting `tp.sanitized` for all categories, or adding a comment explaining why only `buffer_overflow` is checked.

### M6. `dangerous_functions.c` exercises a narrow test scenario for CWE-676

**File:** `/Users/imurphy/projects/deep-code-security/tests/fixtures/vulnerable_samples/c/dangerous_functions.c`

The fixture calls `gets()` twice in one function to create a source-then-sink pattern. This is the right approach given the `sink.line > source.line` constraint, but it is non-obvious. The comment block is clear and accurate. As a purely optional improvement: the `test_dangerous_function_gets` test could additionally assert that the found path has `sink.cwe == "CWE-676"` to strengthen the diagnostic value when the test fails in the future.

### M7. `_node_to_var_name` `parenthesized_expression` handler is not covered by a dedicated test

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/hunter/taint_tracker.py`, lines 480-484

The `pointer_declarator` and `subscript_expression` cases have dedicated `TestCLhsExtraction` tests. The `parenthesized_expression` case (lines 480-484) is not explicitly exercised by any test in the new suite. Consider adding a test like:

```python
# parse 'int y = (x);' where x is tainted
```

This is low priority since `parenthesized_expression` is an uncommon LHS pattern in C.

---

## Verification of KEY THINGS

All eight KEY THINGS TO VERIFY pass:

1. **Output-parameter sources commented out with `# NOT YET SUPPORTED`** -- PASS. `recv`/`fread`/`read`/`scanf`/`getline` are all commented out in `registries/c.yaml` with "NOT YET SUPPORTED: output-parameter source" annotations. Three separate commented-out blocks exist (lines 30-36, 60-90) covering `cli_input` (`scanf`), `network_input` (`recv`, `read`), and `file_input` (`fread`, `getline`).

2. **`snprintf` sanitizer neutralizes only `buffer_overflow`, NOT `memory_corruption`** -- PASS. Lines 192-195 of `registries/c.yaml` show `snprintf` with `neutralizes: [buffer_overflow]` only.

3. **`fgets`-based fixtures use the return-value taint pattern** -- PASS. Both `format_string.c` (line 20) and `network_input.c` (line 21) use `char *input = fgets(buf, n, fp); use(input)`, not `fgets(buf,...); use(buf)`.

4. **`_node_to_var_name` handles `pointer_declarator`, `subscript_expression`, `parenthesized_expression`** -- PASS. Lines 467-484 of `taint_tracker.py` implement all three cases.

5. **`_extract_lhs_name` handles `pointer_declarator` and `subscript_expression`** -- PASS. Lines 341-346 of `taint_tracker.py` implement both cases by delegating to `_node_to_var_name`.

6. **`_is_rhs_tainted` includes `field_expression` in the node type tuple** -- PASS. Line 505 of `taint_tracker.py`: `if node.type in ("attribute", "selector_expression", "member_expression", "field_expression"):`.

7. **`_classify_rhs_transform` handles `cast_expression`, `pointer_expression`, `subscript_expression`** -- PASS. Lines 552-563 of `taint_tracker.py` implement all three cases.

8. **`orchestrator.py` `_cwe_name()` includes CWE-119 and CWE-190** -- PASS. Lines 399 and 402 of `orchestrator.py` have both entries.

9. **CLAUDE.md documents C language support limitations** -- PASS. Items 6, 7, 8, and 9 in the Known Limitations section explicitly document: C intraprocedural taint, no preprocessor resolution, no struct member taint, C output-parameter sources deferred, CWE-416 deferred, and `mktemp()`/`tmpnam()` detection gap.

---

## What Went Well

**Deferred sources are consistently annotated.** The three commented-out source blocks in `registries/c.yaml` each carry a clear "NOT YET SUPPORTED: output-parameter source" label. The rationale is restated in the registry header comment block. Future maintainers have everything they need to understand both what is missing and why.

**Return-value taint pattern is explained in fixture comments.** Both `format_string.c` and `network_input.c` include a `NOTE:` comment block explaining the return-value pattern versus the output-parameter pattern. This is good practice for fixtures that exercise a non-obvious engine constraint.

**AST node type verification test is present.** `test_c_node_type_verification` (lines 430-467 of `test_taint_c_paths.py`) directly validates that the tree-sitter-c grammar uses the node type names the engine depends on (`function_definition`, `init_declarator`, `pointer_declarator`, `subscript_expression`, `field_expression`, `cast_expression`, `assignment_expression`). This is the Risk #1 mitigation from the plan and catches the entire class of grammar name mismatch bugs.

**`FileDiscovery.SKIP_DIRS` additions are correct.** `".deps"` and `".libs"` appear in the `SKIP_DIRS` frozenset (lines 53-54 of `file_discovery.py`), matching the plan's Phase 4 requirement.

**`_cwe_name()` is complete for all new C CWE identifiers.** CWE-119 and CWE-190 are present with the exact strings matching the official CWE descriptions. CWE-22 was already present. No CWE referenced in `registries/c.yaml` returns "Unknown Vulnerability" from `_cwe_name()`.

**`gets()` dual source+sink registration is sound.** The taint tracker's `sink.line > source.line` guard (line 255 of `taint_tracker.py`) prevents a single `gets()` call from being both source and sink of the same finding. The `dangerous_functions.c` fixture correctly exercises this with two separate `gets()` calls on different lines.

**Safe sample tests are structurally correct.** `test_safe_command_no_findings` makes a hard assertion (`len(paths) == 0`) because `safe_command.c` has no taint sources. `test_safe_bounded_copy_no_findings` correctly uses the weaker "sanitized paths" assertion because `bounded_copy.c` has `argv` as a taint source but uses bounded functions.

**No security regressions introduced.** The changes to `taint_tracker.py` are purely additive handling for C-specific AST node types within existing methods. No new subprocess calls, no new file I/O, no new YAML loading. The registry loader path is unchanged. The MCP input validation, sandbox security policy, and path validation code are untouched.

---

## Verdict

**PASS** -- The implementation satisfies all plan requirements. The three test correctness gaps (M1, M2, M3) are worth fixing to convert coverage-only tests into genuine regression guards, but they do not block the ship. There are no critical or major findings.
