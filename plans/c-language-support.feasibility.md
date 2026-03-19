# Feasibility Review: C Language Support for the Hunter Pipeline (Revision 3)

**Plan:** `plans/c-language-support.md`
**Reviewer:** code-reviewer (agent)
**Date:** 2026-03-18
**Plan Status:** DRAFT
**Previous Review:** 2026-03-18 (Revision 2, verdict: PASS with Major concern F-5)

---

## Verdict: PASS

The plan has substantively addressed F-5 (output-parameter sources) and remains correct on F-2 (snprintf sanitizer scope). The output-parameter sources (`recv`, `fread`, `read`, `scanf`, `getline`, `getdelim`) are now commented out in the registry YAML with clear documentation. The fixture descriptions and test method names use sources that work with LHS-seeding (`argv`, `getenv`, `gets`, `fgets`). The snprintf sanitizer correctly neutralizes only `buffer_overflow`, not `memory_corruption`. The ~7 hour estimate is reasonable for the narrowed scope. One new Major concern (F-6) is identified regarding `fgets`-based fixtures that may not produce working taint paths due to the buffer-vs-return-value distinction. Three Minor concerns carry forward or are new.

---

## Status of Previous Findings

### F-5. Output-Parameter Sources (Major, Revision 2)

**Status: Resolved (option a adopted)**

The plan adopted option (a) from the Revision 2 review: narrow the source list. Specifically:

1. **Registry YAML (lines 117-177):** `recv`, `recvfrom`, `recvmsg`, `read`, `fread`, `scanf`, `fscanf`, `sscanf`, `getline`, and `getdelim` are all commented out with `# NOT YET SUPPORTED: output-parameter source` annotations. The comments reference the Known Limitations header. This is thorough.

2. **Active sources are correct:** Only `argv`, `gets`, `fgets`, and `getenv` remain as active sources. These all deliver tainted data via return value or direct identifier, which the LHS-seeding engine handles correctly.

3. **Fixture descriptions updated:**
   - `memory_functions.c` (line 445): Uses `argv[1]` -> `atoi` -> `memcpy` size argument. Correct -- `argv` is a direct identifier source.
   - `network_input.c` (line 447): Uses `fgets` -> `strcpy`. Correct source type, though see F-6 below for a subtlety.
   - No fixture uses `recv`, `read`, `fread`, `scanf`, or `getline` as a source.

4. **Test method names updated:**
   - `test_argv_to_memcpy` (line 615): Tests `argv` -> `memcpy`, not a `recv`-based pattern.
   - `test_fgets_to_strcpy` (line 616): Tests `fgets` -> `strcpy`, not a `recv`-based pattern.
   - No test named `test_network_input_to_memcpy` exists. All test names reflect achievable source patterns.

5. **Source count (line 690):** States "4 active sources / 7 sink categories with 7 sanitizers." The 4 active sources (argv, gets, fgets, getenv) and 7 sink categories (command_injection, buffer_overflow, memory_corruption, format_string, integer_overflow, dangerous_function, path_traversal) are correct.

6. **Known Limitations documentation:** Lines 103-107 of the registry YAML provide a clear explanation of the output-parameter limitation. The CLAUDE.md update plan (line 694, task 15d) also documents this. Goal #4 (line 10) explicitly states the deferral rationale. The Deviations section (line 755) provides the most comprehensive explanation.

**One minor inconsistency:** Line 690 says "6 additional sources commented out as deferred" but the actual count of commented-out source entries is 5: `scanf` (1), `recv` (1), `read` (1), `fread` (1), `getline` (1). The `scanf` entry matches 3 functions (`scanf|fscanf|sscanf`) and `recv` matches 3 (`recv|recvfrom|recvmsg`) via regex, but these are single entries. And `getline` matches 2 (`getline|getdelim`). If counting by individual function name rather than registry entry, the number is higher than 6. Either way, the stated "6" does not match any consistent counting method. This is cosmetic and non-blocking.

### F-2. snprintf Sanitizer Scope

**Status: Correct (no issue found)**

The `snprintf` sanitizer (plan lines 279-282) neutralizes only `buffer_overflow`, which is correct. `snprintf` is a bounded format function that prevents buffer overflow in `sprintf`-like patterns, but it does not neutralize `memory_corruption` (which covers `memcpy`/`memmove`/`memset` -- completely different operations). The only sanitizer that neutralizes `memory_corruption` is `memcpy_s` (lines 304-308), which is the bounds-checked counterpart to `memcpy`. This is architecturally sound.

### Minor Findings from Revision 2

| ID | Finding | Status | Notes |
|----|---------|--------|-------|
| m7 | `vsnprintf` missing from sanitizer list | **Open** | Still absent. See m7 below. |
| m8 | Registry version `2.0.0` should be `1.1.0` | **Open** | Plan line 89 still specifies `"2.0.0"`. See m8 below. |
| m9 | Recursive `_node_to_var_name` unbounded for `pointer_declarator` | **Open** | Plan lines 349-351 still recurse without depth limit. See m9 below. |

---

## New Concerns

### Major Concerns

#### F-6. `fgets`-Based Fixtures May Not Produce Working Taint Paths

**Location:** Fixture descriptions for `format_string.c` (line 439) and `network_input.c` (line 447); tests `test_format_string_detected` (line 613) and `test_fgets_to_strcpy` (line 616)

**Issue:** The `fgets` source works with LHS-seeding only when the return value is assigned to a variable AND that variable (not the buffer argument) is used downstream. The plan's fixture descriptions are ambiguous about this, and the natural C idiom uses the buffer variable -- not the return value -- after calling `fgets`.

The taint engine seeds taint as follows (taint_tracker.py lines 233-248):
1. `_find_assigned_var_near_line` finds the LHS of the assignment containing the source call.
2. The LHS variable and the source function name (`"fgets"`) are both added to `tainted_vars`.

For `fgets`, three patterns arise:

**Pattern A (works):**
```c
char *input = fgets(buf, sizeof(buf), stdin);
printf(input);  // "input" is tainted -- finding produced
```
LHS-seeding taints `input`. The sink uses `input`. Taint path found.

**Pattern B (does NOT work):**
```c
char *input = fgets(buf, sizeof(buf), stdin);
printf(buf);  // "buf" is NOT tainted -- finding missed
```
LHS-seeding taints `input`, but the sink uses `buf`. No taint path.

**Pattern C (does NOT work):**
```c
fgets(buf, sizeof(buf), stdin);  // no assignment
printf(buf);  // "buf" is NOT tainted, "fgets" not in "printf(buf)" text
```
No LHS variable found. Only `"fgets"` is tainted as a pseudo-variable. The fallback substring check (taint_tracker.py line 570-572) looks for `"fgets"` in the sink node text `printf(buf)` -- no match. Finding missed.

The plan's `format_string.c` description (line 439) says: "`fgets` -> `printf(user_data)`." This is ambiguous -- is `user_data` the return value of `fgets` or the buffer argument? If the implementer writes Pattern B or C (which are the idiomatic C patterns), the test `test_format_string_detected` will fail.

Similarly, `network_input.c` (line 447) says: "Input read via `fgets(buf, sizeof(buf), stdin)` ... is assigned to a variable and then copied to a fixed-size buffer via `strcpy(dst, buf)`." The phrase "is assigned to a variable" suggests Pattern A, but `strcpy(dst, buf)` uses `buf` (the buffer argument), not the return-value variable. This is Pattern B, which does not produce a taint path.

**Impact:** Two of the eight end-to-end tests (`test_format_string_detected` and `test_fgets_to_strcpy`) may fail if the fixtures use idiomatic C patterns. The `format_string.c` fixture is more easily fixable (use Pattern A with `printf(input)` where `input = fgets(...)`), but the `network_input.c` fixture is harder because the natural `fgets` -> `strcpy` pattern inherently uses the buffer variable.

**Recommendation:** The fixture descriptions should be explicit about which variable carries the taint:

- `format_string.c`: Specify that the pattern must be `char *input = fgets(buf, ...); printf(input);` (Pattern A). Add a comment noting that `printf(buf)` after `fgets(buf, ...)` is a known false negative.

- `network_input.c`: Either (a) change the pattern to use the return value: `char *data = fgets(buf, ...); strcpy(dst, data);`, or (b) change the source to `argv` (e.g., `strcpy(dst, argv[1])`) since the existing `buffer_overflow.c` already uses `argv` -> `strcpy` and this fixture would be redundant, or (c) document that this fixture exercises a known false-negative pattern and remove it from the positive-detection test expectations.

Option (a) is recommended. The fixture would be contrived but valid -- it demonstrates a real taint path. Add a comment in the fixture explaining why the return value is used instead of the buffer.

---

### Minor Concerns

#### m7. `vsnprintf` Still Missing from Sanitizer List (carried from Revision 2)

**Location:** Plan Section 1, sanitizer entries (lines 278-314)

`vsnprintf` is the variadic counterpart to `snprintf` and is equally a bounded format function. If `vsnprintf` appears in a taint path, it will not neutralize a `buffer_overflow` finding. This was raised in the Revision 1 review (as m6) and the Revision 2 review (as m7) and remains unaddressed.

**Recommendation:** Add `vsnprintf` as a sanitizer neutralizing `buffer_overflow`.

#### m8. Registry Version 2.0.0 Still Semantically Incorrect (carried from Revision 2)

**Location:** Plan line 89 (`version: "2.0.0"`)

The registry format is structurally unchanged (same YAML schema, same key names). A minor version bump (`1.1.0`) is more appropriate per semver. A major version bump implies breaking changes to the schema.

**Recommendation:** Use `"1.1.0"` instead of `"2.0.0"`.

#### m9. Recursive `_node_to_var_name` for `pointer_declarator` Still Unbounded (carried from Revision 2)

**Location:** Plan Section 2b, lines 349-351

The code `if child.type == "pointer_declarator": return self._node_to_var_name(child)` recurses without a depth limit. While deeply nested pointer declarators are rare in practice, the project's security-first posture (per CLAUDE.md) suggests a defensive depth limit.

**Recommendation:** Add a `max_depth` parameter (default 10) to the recursive call.

#### m10. Commented-Out Source Count Mismatch

**Location:** Plan line 690

The plan states "6 additional sources commented out as deferred" but the actual count of commented-out source entries in the proposed YAML is 5 (`scanf`, `recv`, `read`, `fread`, `getline`). This is a cosmetic error in the task description table.

**Recommendation:** Change "6" to "5" in line 690.

---

## Effort Estimate Assessment

The ~7 hour estimate (line 720) is reasonable for the narrowed scope:

| Task | Estimate | Assessment |
|------|----------|------------|
| Registry expansion | ~1 hour | Reasonable. The YAML is fully specified in the plan; this is mostly copy-paste with verification that queries compile. |
| Taint tracker enhancements | ~2 hours | Reasonable. Four methods need C-specific branches (`_node_to_var_name`, `_extract_lhs_name`, `_is_rhs_tainted`, `_classify_rhs_transform`). Each is a mechanical addition of 5-15 lines. The risk is AST node type mismatches (Risk #1), but the plan includes a verification test. |
| Orchestrator + file_discovery | ~15 minutes | Correct. Two lines in `_cwe_names` and two strings in `SKIP_DIRS`. |
| Test fixtures | ~1 hour | Reasonable, possibly slightly optimistic if the `fgets`-based fixtures require careful construction per F-6. |
| Test suite | ~2 hours | Reasonable. The test structure mirrors `test_taint_go_paths.py` and `test_go_registry.py`. Most tests are boilerplate with different code strings. |
| Integration testing | ~30 minutes | Reasonable. Running `dcs hunt` on a small C project and verifying output. |
| CLAUDE.md update | ~15 minutes | Correct. Adding Known Limitations bullets. |

**Total: ~7 hours is achievable** assuming the implementer addresses F-6 during fixture creation. If F-6 requires rethinking the `fgets`-based fixtures, add ~30 minutes for the adjustment.

---

## Test Coverage Assessment

The test plan is thorough and covers the right areas:

1. **Registry tests (`test_c_registry.py`):** 10 tests covering loading, version, categories, sanitizers, query compilation, and individual source/sink query matching. Sufficient.

2. **Taint propagation tests (`TestCTaintPropagation`):** 7 tests covering assignment, pointer assignment, init_declarator, `_find_assigned_var`, array subscript, RHS taint, and field expression. Sufficient for the new code paths.

3. **LHS extraction tests (`TestCLhsExtraction`):** 4 tests covering pointer_declarator, double pointer, subscript, and the full `_find_assigned_var_near_line` flow for pointer declarations. These directly target the M1 fix from Revision 1. Sufficient.

4. **End-to-end tests (`TestCEndToEnd`):** 8 tests covering all fixture files plus safe samples. Subject to F-6 for the `fgets`-based tests, but otherwise comprehensive.

5. **Node type verification (`TestCNodeTypes`):** 3 tests including the Risk #1 mitigation test. Good defensive testing.

**Gap:** No negative test for the output-parameter false-negative class. Consider adding a test that parses a `recv(sockfd, buf, ...); strcpy(dst, buf);` pattern and asserts zero findings, documenting the known limitation. This would serve as a regression test if output-parameter support is added later.

---

## Breaking Changes / Backward Compatibility

**No breaking changes.** All modifications are additive:

- Registry: new file content (expanded `c.yaml`), no schema changes.
- Taint tracker: new branches in existing methods, guarded by `node.type` checks that only activate for C AST node types. Python and Go behavior is unaffected because `pointer_declarator`, `subscript_expression`, `parenthesized_expression`, `cast_expression`, `pointer_expression`, and `field_expression` are C-specific tree-sitter node types that do not appear in Python or Go ASTs.
- Orchestrator: two new entries in a dictionary.
- File discovery: two new strings in a frozenset.
- No Pydantic model changes. No CLI changes. No MCP tool changes.

The plan's acceptance criterion #10 ("All existing Python and Go hunter tests pass unchanged") correctly captures this requirement.

---

## Summary of Recommended Adjustments

| ID | Severity | Action |
|----|----------|--------|
| F-6 | Major | Clarify `fgets`-based fixture descriptions to use return-value variable (Pattern A), not buffer variable. `format_string.c` should use `char *input = fgets(...); printf(input);`. `network_input.c` should use `char *data = fgets(...); strcpy(dst, data);`. Document that the idiomatic pattern (`fgets(buf,...); use(buf);`) is a known false negative. |
| m7 | Minor | Add `vsnprintf` to sanitizer list (neutralizes `buffer_overflow`). |
| m8 | Minor | Use registry version `"1.1.0"` instead of `"2.0.0"`. |
| m9 | Minor | Add recursion depth limit to `_node_to_var_name` for nested `pointer_declarator`. |
| m10 | Minor | Fix commented-out source count from "6" to "5" in line 690. |
