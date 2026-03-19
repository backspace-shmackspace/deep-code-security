# Red Team Review (Pass 3): C Language Support for the Hunter Pipeline

**Reviewed:** `plans/c-language-support.md` (revised, post-Pass-2 revision)
**Previous reviews:** Pass 1 (2026-03-18), Pass 2 (2026-03-18)
**Reviewer:** Security Analyst
**Date:** 2026-03-18

## Verdict: PASS

No Critical findings. Both Major findings from Pass 2 (F-1: output-parameter sources, F-2: snprintf neutralizing memory_corruption) have been resolved in the revised plan. The remaining findings are Minor or Info.

---

## Resolution Status of Pass 2 Findings

| Pass 2 # | Severity | Status | Notes |
|-----------|----------|--------|-------|
| F-1 | Major | **RESOLVED** | Output-parameter sources (`recv`, `fread`, `read`, `scanf`, `getline`, `getdelim`) are now commented out in the registry YAML (lines 117-177) with `# NOT YET SUPPORTED` annotations. Goal 4 (line 10) explicitly documents the limitation. Section "Deferred (output-parameter sources)" (lines 48-54) thoroughly explains why these sources do not work with the LHS-seeding engine. The `network_input.c` fixture description (line 447) has been rewritten to use `fgets` (a return-value source) instead of `recv`. The `memory_functions.c` fixture description (line 445) has been rewritten to use `argv -> atoi -> memcpy size` (return-value taint path) instead of `recv -> memcpy buffer`. See F-1 below for a residual minor issue. |
| F-2 | Major | **RESOLVED** | `snprintf` sanitizer now only neutralizes `buffer_overflow` (lines 279-282). `memory_corruption` has been removed from its `neutralizes` list. This matches the existing behavior in the current `registries/c.yaml` (line 113-114). See F-2 below for residual observation. |
| F-3 | Minor | RESOLVED | `fgets` output-parameter limitation is documented in the registry YAML Known Limitations block (lines 103-107). The `network_input.c` fixture (line 447) now assigns the `fgets` return value to a variable (`char *input = fgets(buf, sizeof(buf), stdin)`), ensuring the taint path works. |
| F-4 | Minor | OPEN (acceptable) | Sanitizer substring matching amplification is unchanged. Pre-existing limitation. |
| F-5 | Minor | RESOLVED | `read()` is no longer classified as `network_input` -- it is commented out entirely as a deferred output-parameter source (lines 156-161). The `read()` over-matching concern is moot since it is no longer active. Risk #6 (lines 541-545) now reflects this. |
| F-6 | Minor | **RESOLVED** | Test fixture descriptions for `network_input.c` and `memory_functions.c` have been rewritten to match detectable patterns. `network_input.c` now uses `fgets -> strcpy` (line 447). `memory_functions.c` now uses `argv -> atoi -> memcpy size` (line 445). The `test_fgets_to_strcpy` test (line 616) replaces the old `test_network_input_to_memcpy`. |
| F-7 | Minor | OPEN (acceptable) | `gets()` dual-registration pseudo-variable taint path unchanged. Documented in acceptance criterion 9 (line 665). |
| F-8 | Info | OPEN (acceptable) | SARIF CWE taxonomy -- unchanged. |
| F-9 | Info | OPEN (acceptable) | No automated performance benchmark -- unchanged. |

---

## Findings

### F-1. [Minor] `network_input.c` fixture name is now misleading

**Location:** Plan line 447, line 680, line 616

The `network_input.c` fixture has been rewritten to use `fgets` instead of `recv`. The description now says: "Input read via `fgets(buf, sizeof(buf), stdin)` (or `fgets(buf, sizeof(buf), socket_file)`) is assigned to a variable and then copied to a fixed-size buffer via `strcpy(dst, buf)`."

However, `fgets` reading from `stdin` is not "network input" -- it is standard input / CLI input. The fixture filename `network_input.c` and the parenthetical mention of `socket_file` imply network I/O, but the actual taint source is `fgets` registered under `cli_input`, not `network_input`. The `network_input` source category is entirely commented out in the registry YAML (lines 147-161).

The end-to-end test `test_fgets_to_strcpy` (line 616) references this fixture and expects a CWE-120 finding. The finding would be reported as `cli_input (fgets) -> buffer_overflow (strcpy)`, not `network_input -> buffer_overflow`. This is functionally correct but the test name, fixture name, and finding description do not align with what "network input" means.

**Impact:** Low. The test will pass with the correct CWE, but the naming is misleading. A developer reading the fixture list would expect this file to demonstrate network-sourced taint, which it does not.

**Recommendation:** Rename the fixture from `network_input.c` to `fgets_overflow.c` or `stdin_overflow.c`, and update the test name from `test_fgets_to_strcpy` to match. Alternatively, keep the name but add a header comment in the fixture explaining that `fgets` is used as a stand-in for network sources (`recv`), which are deferred due to the output-parameter limitation.

---

### F-2. [Minor] `memcpy_s` sanitizer neutralizes `memory_corruption` but `strcpy_s` does not -- inconsistency

**Location:** Plan lines 304-313

The sanitizer entries show:
```yaml
- pattern: "memcpy_s"
  neutralizes:
    - buffer_overflow
    - memory_corruption

- pattern: "strcpy_s"
  neutralizes:
    - buffer_overflow
```

`memcpy_s` neutralizes both `buffer_overflow` and `memory_corruption`, which is correct: it is a bounds-checked replacement for `memcpy` (a `memory_corruption` sink) and also prevents the buffer overflow class. However, `strcpy_s` only neutralizes `buffer_overflow`, not `memory_corruption`. This is also correct in principle (`strcpy_s` replaces `strcpy`, which is a `buffer_overflow` sink, not a `memory_corruption` sink).

The inconsistency is not a bug, but the Pass 2 concern about `snprintf` incorrectly neutralizing `memory_corruption` could recur here if someone later adds `memory_corruption` to `strcpy_s` by analogy with `memcpy_s`. The current state is correct.

**Impact:** None currently. The sanitizer scope is correct. This is noted for documentation purposes only.

**Recommendation:** No change needed. The distinction is correct and follows from the different sink categories that `memcpy` vs. `strcpy` belong to.

---

### F-3. [Minor] `_handle_assignment` C branch does not handle `pointer_declarator` -- dual fix needed

**Location:** Plan Section 2a (lines 319-327), Section 2b (lines 330-364), Section 2c (lines 366-393)

The plan correctly identifies that both `_node_to_var_name` (used in `_handle_assignment` for taint propagation) and `_extract_lhs_name` (used in `_find_assigned_var_near_line` for source seeding) need `pointer_declarator` handling. However, the plan's section 2a description says:

> "The existing `_handle_assignment` method (lines 416-424) already handles C's `assignment_expression` and `init_declarator`."

This is only true for non-pointer declarations. For `char *p = tainted;`, the current code at line 422 calls `_node_to_var_name(lhs_node)` where `lhs_node` is a `pointer_declarator` node. Today, `_node_to_var_name` returns `None` for this node type, so `lhs_names` stays empty and taint propagation silently fails. The plan fixes this in section 2b by extending `_node_to_var_name`.

The concern is that sections 2a, 2b, and 2c describe three changes that are interdependent. If section 2b is implemented but section 2c is missed (or vice versa), pointer declarations would work for taint propagation but not for source seeding (or the reverse). The plan's implementation order (Step 3: "Modify taint_tracker.py -- all C-specific enhancements 2a through 2e") treats them as a single step, which mitigates this risk.

**Impact:** Low, if implemented as a single step as the plan specifies. If implemented incrementally, partial fixes would produce subtle false negatives.

**Recommendation:** The implementation order (Step 3) correctly bundles all taint tracker changes. Add a note in Section 2a explicitly stating that `_handle_assignment` will fail for pointer declarations until `_node_to_var_name` is extended (Section 2b), making the dependency clear to the implementer.

---

### F-4. [Minor] `_handle_assignment` C branch does not filter type specifier children

**Location:** Plan lines 416-424 of taint_tracker.py (existing code), Plan Section 2a (lines 319-327)

The current `_handle_assignment` C branch at line 418 filters children by excluding `"="` and `"+="`:
```python
non_op = [c for c in children if c.type not in ("=", "+=")]
```

For a C `init_declarator` like `int x = 5`, the children are `[identifier("x"), "=", number_literal(5)]`. After filtering `"="`, `non_op` is `[identifier("x"), number_literal(5)]`. `non_op[0]` is the LHS, `non_op[-1]` is the RHS. This works.

But for `init_declarator` in tree-sitter-c, the node structure for some declarations may include additional children depending on the grammar version. In particular, `init_declarator` does NOT include the type specifier as a child (the type specifier is a sibling under the parent `declaration` node, not under `init_declarator`), so the current filtering logic is correct for the node types it processes.

However, if the plan adds handling for `subscript_expression` on the LHS (e.g., `buf[i] = tainted;`), this is an `assignment_expression` (not `init_declarator`), and its children are `[subscript_expression, "=", identifier]`. After filtering `"="`, `non_op[0]` is `subscript_expression`, which is correct. The plan's Section 2b adds `subscript_expression` handling to `_node_to_var_name`, so this path will work.

**Impact:** None -- the analysis confirms the plan is correct. Noted for completeness.

**Recommendation:** No change needed.

---

### F-5. [Minor] Performance estimate uses "~4 new active sink queries" but actual count is higher

**Location:** Plan line 468

The plan states:
> "The registry expansion adds ~4 new active sink queries (output-parameter source queries are commented out). Combined with existing queries, the total is ~14 queries per file."

Counting the proposed registry YAML sinks:
- `command_injection`: 3 entries (system, popen, execv) -- existing
- `buffer_overflow`: 2 entries (strcpy, sprintf) -- existing
- `memory_corruption`: 1 entry (memcpy) -- **NEW**
- `format_string`: 1 entry (printf) -- existing
- `integer_overflow`: 1 entry (malloc) -- **NEW**
- `dangerous_function`: 2 entries (gets, mktemp) -- **NEW** (2 entries, not 1)
- `path_traversal`: 1 entry (fopen) -- existing

New sink entries: memcpy (1) + malloc (1) + gets (1) + mktemp (1) = 4 new sink entries. Plus sources: argv, gets, fgets, getenv = 4 source entries (existing). Total active queries = 4 sources + 11 sinks = 15 queries, not 14. With sanitizer checks, the total per-file overhead is slightly higher than stated.

The difference is negligible for performance purposes (~42,000 vs ~45,000 query executions for OpenSSL). The estimate is close enough.

**Impact:** Negligible. The performance estimate is within the correct order of magnitude.

**Recommendation:** No change needed. Minor arithmetic correction for accuracy if desired.

---

### F-6. [Minor] `format_string.c` fixture description relies on `fgets` return-value assignment pattern

**Location:** Plan line 439

The fixture description says:
> "User input read via `fgets` is passed directly as the format string to `printf`."

For this to produce a finding, the test fixture must use a pattern where `fgets` return value is assigned:
```c
char *input = fgets(buf, sizeof(buf), stdin);
printf(input);  // CWE-134
```

The more idiomatic C pattern is:
```c
fgets(buf, sizeof(buf), stdin);
printf(buf);  // buf is NOT tainted via LHS-seeding
```

The plan's existing `buffer_overflow.c` fixture (line 31-33) uses `printf(user_input)` where `user_input` comes from a function parameter, not from `fgets`. The `format_string.c` fixture needs to be carefully crafted to ensure the `fgets` return value is the variable used in `printf`.

Alternatively, the fixture could use `argv` as the source (which is simpler and avoids the `fgets` LHS-seeding nuance), since `argv` is a directly tainted identifier:
```c
printf(argv[1]);  // argv is tainted, flows to printf -- CWE-134
```

The plan does not specify which source to use, only that the fixture demonstrates "fgets -> printf(user_data)". If the implementer uses the idiomatic `fgets(buf, ...)` pattern without assigning the return value, the test will fail.

**Impact:** Low -- the fixture works if implemented correctly (with `fgets` return value assigned), but the description does not make this constraint explicit enough.

**Recommendation:** Either (a) specify in the fixture description that `fgets` return value MUST be assigned to the variable used in `printf`, or (b) use `argv` as the source for simplicity, since the format string vulnerability is the point of the fixture, not the source type.

---

### F-7. [Minor] Sanitizer count claim in Section 5 is "New Sanitizer Entries" but does not mention `snprintf` and `strncpy` are existing

**Location:** Plan lines 77-81, lines 278-313

The plan's section "New Sanitizer Entries" (lines 77-81) lists:
- `strlcpy` / `strlcat` -- NEW
- `strncat` -- NEW
- `memcpy_s` / `strcpy_s` -- NEW

But the full registry YAML (lines 278-313) also includes `snprintf` and `strncpy`, which already exist in the current `registries/c.yaml`. This is not misleading (the section is titled "New Sanitizer Entries"), but the test at line 632 (`test_c_registry_sanitizers`) lists all 7 sanitizers including existing ones. This is correct behavior -- the test should verify the complete set.

**Impact:** None. Noted for completeness.

**Recommendation:** No change needed.

---

### F-8. [Minor] Known Limitations block does not mention `getdelim` alongside `getline`

**Location:** Plan lines 103-107 (registry YAML Known Limitations comment)

The Known Limitations comment in the registry YAML mentions `recv, fread, read, scanf, getline` as deferred output-parameter sources. However, the registry YAML also comments out `getdelim` (line 176: `(#match? @fn "^(getline|getdelim)$")`), and Goal 4 (line 10) and the "Deferred" section (line 54) both list `getdelim`. The Known Limitations comment at line 103-107 should include `getdelim` for consistency:

```
# - C source functions that deliver tainted data via output parameters (recv, fread, read,
#   scanf, getline, getdelim) are not effective taint sources in v1.
```

Currently it says `recv, fread, read, scanf, getline` without `getdelim`.

**Impact:** Very low. Documentation inconsistency.

**Recommendation:** Add `getdelim` to the Known Limitations comment in the registry YAML to match the commented-out query and the deferred sources list.

---

### F-9. [Info] Acceptance criterion 11 is thorough but does not mention `getdelim`

**Location:** Plan line 667

Acceptance criterion 11 says CLAUDE.md should document "C output-parameter source functions (`recv`, `fread`, `read`, `scanf`, `getline`)". The `getdelim` function is listed in Goal 4, the Deferred section, the registry YAML comments, and the Deviations table, but is missing from the acceptance criterion.

**Impact:** Very low. If acceptance criterion 11 is the implementer's checklist, `getdelim` may be omitted from the CLAUDE.md Known Limitations update.

**Recommendation:** Add `getdelim` to acceptance criterion 11 for completeness.

---

### F-10. [Info] Task breakdown file count is 10 new + 5 modified = 15 files

**Location:** Plan lines 669-694

The task breakdown is well-structured and matches the plan content. The implementation order (lines 696-708) correctly bundles all taint tracker changes as a single step. No issues found.

---

## Security-Specific Assessment

### Container Security Assessment

This plan does not involve container changes. The C language support is entirely within the Hunter pipeline, which runs natively on the host. No sandbox/container modifications are proposed.

The plan explicitly defers Auditor PoC templates for C (line 23: "requires compilation and binary execution, which is architecturally different from Python/Go PoCs"). This is the correct decision -- executing arbitrary C code in a sandbox requires a C compiler in the container, which would significantly expand the attack surface.

### Supply Chain Risk

No new dependencies are introduced. The `tree-sitter-c` package is already in `pyproject.toml`. The registry expansion uses YAML loaded via `yaml.safe_load()` with schema validation -- consistent with the existing security model.

### Trust Boundary Mapping

All changes operate within the "Hunter (tree-sitter)" trust boundary. No changes to:
- MCP server input validation
- Sandbox container configuration
- Auditor PoC template rendering
- File path validation

The new registry entries are within the "registries/" trust domain, protected by existing controls.

---

## Verification of Pass 2 Remediation

### F-1 (Pass 2): Output-parameter sources -- VERIFIED RESOLVED

The revision correctly:
1. Comments out `recv`, `recvfrom`, `recvmsg`, `read`, `fread`, `scanf`, `fscanf`, `sscanf`, `getline`, `getdelim` in the registry YAML (lines 117-177) with clear `# NOT YET SUPPORTED` annotations.
2. Documents the limitation in Goal 4 (line 10), the "Deferred (output-parameter sources)" section (lines 48-54), the Known Limitations block (lines 103-107), Risk #6 (lines 541-545), the Deviations table (line 755), and acceptance criterion 11 (line 667).
3. Rewrites the `network_input.c` fixture (line 447) to use `fgets` (a return-value source) instead of `recv`.
4. Rewrites the `memory_functions.c` fixture (line 445) to use `argv -> atoi -> memcpy size` instead of `recv -> memcpy buffer`.
5. Rewrites the end-to-end tests: `test_fgets_to_strcpy` (line 616) replaces `test_network_input_to_memcpy`, and `test_argv_to_memcpy` (line 615) tests the `argv -> atoi -> memcpy` size path.

The active source list is now limited to functions where return-value taint works: `argv` (identifier), `getenv` (return value), `gets` (returns buffer pointer), and `fgets` (returns buffer pointer). This is honest and correct.

### F-2 (Pass 2): snprintf neutralizing memory_corruption -- VERIFIED RESOLVED

The revision correctly:
1. Removes `memory_corruption` from `snprintf`'s `neutralizes` list (lines 279-282). The sanitizer now only neutralizes `buffer_overflow`.
2. This matches the existing `registries/c.yaml` (lines 112-115) where `snprintf` only neutralizes `buffer_overflow`.
3. The `memcpy_s` sanitizer (lines 304-308) correctly neutralizes both `buffer_overflow` and `memory_corruption`, which is appropriate since `memcpy_s` is a direct replacement for `memcpy` (a `memory_corruption` sink).

No false-neutralization scope expansion exists in the revised plan.

---

## Summary

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| F-1 | Minor | `network_input.c` fixture name is misleading -- uses `fgets` (cli_input), not network sources | NEW |
| F-2 | Minor | `memcpy_s` vs `strcpy_s` sanitizer scope inconsistency -- correct but worth noting | NEW (observation) |
| F-3 | Minor | `_handle_assignment` and `_extract_lhs_name` pointer_declarator fixes are interdependent | NEW (implementation note) |
| F-4 | Minor | `_handle_assignment` C branch type specifier filtering analysis -- confirmed correct | NEW (verification) |
| F-5 | Minor | Performance estimate says "~14 queries" but actual count is ~15 | OPEN (negligible) |
| F-6 | Minor | `format_string.c` fixture must use `fgets` return-value assignment or `argv` source | NEW |
| F-7 | Minor | "New Sanitizer Entries" section vs full list includes existing `snprintf`/`strncpy` -- not misleading | OPEN (acceptable) |
| F-8 | Minor | Known Limitations comment omits `getdelim` alongside `getline` | NEW |
| F-9 | Info | Acceptance criterion 11 omits `getdelim` | NEW |
| F-10 | Info | Task breakdown is well-structured, no issues | NEW |

### Items resolved from Pass 2

| Pass 2 # | Severity | Finding | Resolution |
|-----------|----------|---------|------------|
| F-1 | Major | Output-parameter sources not tainted | Commented out in YAML, documented as deferred, fixtures rewritten to use return-value sources |
| F-2 | Major | `snprintf` neutralizes `memory_corruption` | Removed `memory_corruption` from neutralizes list |
| F-3 | Minor | `fgets` output-parameter limitation | Documented; fixture uses return-value assignment pattern |
| F-5 | Minor | `read()` classified as `network_input` | `read()` is now commented out entirely (deferred) |
| F-6 | Minor | Test fixture descriptions imply buffer-content taint | Fixtures rewritten to match detectable patterns |

### Recommended actions before approval

No blocking actions. The following are quality improvements:

1. **F-1 (naming):** Consider renaming `network_input.c` to `fgets_overflow.c` or adding a header comment explaining the fixture uses `fgets` as a stand-in for deferred network sources.
2. **F-6 (fixture clarity):** Specify in the `format_string.c` description that `fgets` return value must be assigned, or use `argv` as the simpler source.
3. **F-8 (documentation):** Add `getdelim` to the Known Limitations comment in the registry YAML (one word addition).
4. **F-9 (documentation):** Add `getdelim` to acceptance criterion 11 (one word addition).
