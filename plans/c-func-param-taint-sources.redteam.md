# Red Team Review: C Function Parameter Taint Sources (Round 2)

**Plan:** `plans/c-func-param-taint-sources.md`
**Reviewer:** Security Analyst (specialist)
**Round:** 2 (revised plan)
**Date:** 2026-03-20
**Verdict:** PASS

---

## Verification of Round 1 Findings

### F-01: Short Parameter Names Cause False Positive Taint via Substring Match -- RESOLVED

**Original Severity:** Major

**Evidence of Resolution:**

The revised plan introduces `_MIN_PARAM_NAME_LENGTH = 2` in `param_source_extractor.py` (Section 4a, lines 113-123). Single-character parameter names (`n`, `s`, `c`, `p`, `i`, `x`) are excluded from taint seeding entirely. The implementation is clean:

- The filter is applied at source extraction time, preventing short names from ever entering the taint state.
- A `logger.debug()` call records skipped parameters for auditability (line 273-278).
- The constant is documented with a clear rationale explaining the substring collision problem.
- Risk #2 (Section "Risks", item 2) provides an honest analysis of the threshold choice, including the recall-precision tradeoff and an explicit path to raise the threshold to 3 if two-character collisions prove problematic.
- Test coverage includes `test_short_param_names_excluded` and `test_two_char_param_names_included` (lines 644-646).
- Acceptance criterion #6 (line 766) explicitly requires single-character name exclusion.

**Residual risk:** The taint engine has three substring-match locations: (1) `_is_rhs_tainted` at line 608-613 for attribute/field expressions, (2) `_check_sink_reachability` fallback at line 992-994, and (3) `_check_args_for_taint` structured path at lines 1097-1101. Two-character parameter names (e.g., `op`) can still produce false matches in the structured path -- for example, `tainted_var = "op"` would substring-match inside argument text like `"output"` or `"copy"`. However, this residual risk is explicitly acknowledged in Risk #2, the collision rate for 2-character names is significantly lower than for 1-character names, and the plan provides a clear escalation path (raise threshold to 3). The format_string sink category already has a dedicated bypass for the fallback path (line 990 of taint_tracker.py), which is the highest-risk sink for false positives. This is acceptable for v1.

---

### F-02: `_find_assigned_var_near_line` Cross-Match with First Statement in Function Body -- RESOLVED

**Original Severity:** Major

**Evidence of Resolution:**

The revised plan adds Section 4c ("Taint Seeding for Parameter Sources", lines 365-397) which directly addresses this finding. The fix is exactly what Round 1 recommended:

```python
if source.category == "func_param":
    source_var = None  # Parameter name IS the variable; skip LHS lookup
else:
    source_var = self._find_assigned_var_near_line(...)
```

The plan provides:

- A detailed explanation of WHY the bypass is required, with two concrete C code examples (lines 371-378 and 380-381) demonstrating the cross-match problem.
- A correct analysis of the multi-line parameter list case (lines 380-381).
- The change is scoped to a 3-line conditional that only affects `func_param` sources -- all other source categories retain their existing behavior.
- The existing fallback path (`state.add_taint(source.function, initial_step)` at line 306 of taint_tracker.py) correctly seeds the parameter name as a tainted variable when `source_var` is `None`.
- Integration test `test_func_param_bypasses_assigned_var_lookup` (line 670) verifies the fix end-to-end.
- Acceptance criterion #13 (line 773) makes this a hard requirement.
- The task breakdown (file #13, line 797) and deviation table (line 892) properly track this as a modification to `taint_tracker.py`.

The plan no longer claims "No changes to TaintEngine are needed" (the original Round 1 concern). It explicitly acknowledges and designs the TaintEngine change.

---

## New Findings (if any)

No new Critical or Major findings were introduced by the revisions. The three additions (minimum name length filter, `func_param` category guard, separate Semgrep directory) are all well-scoped changes that do not introduce new attack surface or break existing behavior.

The separate Semgrep rule directory (`registries/semgrep/c-param-sources/`) with conditional `--config` inclusion is a sound design choice. The existing `SemgrepBackend` builds subprocess commands as Python lists (no `shell=True`), and the new `--config` path is a hardcoded project-relative path, not derived from user input. No injection vector exists.

The `_is_static` function's defensive check of both direct `storage_class_specifier` children and those nested inside `declaration_specifiers` (lines 181-191) provides grammar robustness without introducing correctness issues.

---

## Minor/Info Findings

The following items from Round 1 were either addressed or remain as acceptable deferrals. None block PASS.

### F-03 (Semgrep static-function noise) -- Addressed

The revised plan explicitly recommends `DCS_SCANNER_BACKEND=treesitter` when using `--c-param-sources` for best results (line 458). The recommendation is also included in Risk #5 mitigation (line 593) and will be documented in CLAUDE.md (per the task breakdown, file #17). The Semgrep rules are now in a separate directory (`registries/semgrep/c-param-sources/`) that is only included when the feature is active, preventing any impact on default scans.

### F-04 (argc-only exclusion list) -- Acknowledged, deferred

The exclusion list remains `("argc",)`. Risk #1 mitigation (e) at line 569 explicitly lists this as a future extensibility path: "Future plan can add parameter-name heuristics (e.g., skip `ctx`, `handle`, `flags`, `mode` parameters) or confidence adjustment." The plan's position that the opt-in nature of the feature is the primary noise control mechanism is reasonable for v1. If the exclusion list needs to grow, the tuple is trivially extensible.

### F-05 (confidence downgrade deferred) -- Acknowledged, deferred

Section 8 (lines 490-496) provides a balanced analysis of the confidence adjustment tradeoff and explicitly defers it. The rationale ("Without context, we cannot know which parameters are attacker-controlled. Lowering confidence uniformly punishes legitimate findings.") is defensible. The `source.category == "func_param"` field provides the hook for a future plan to implement category-based scoring.

### F-06 (MCP boolean validation) -- Not addressed

The plan does not add explicit `isinstance()` type checking for the `c_param_sources` MCP parameter beyond the JSON schema `"type": "boolean"`. However, the MCP framework's schema validation (via `BaseMCPServer`) enforces type constraints before the handler runs. The impact is negligible since the parameter only toggles a feature flag with no injection risk.

### F-07 (TUI integration) -- Addressed

Added as an explicit Non-Goal with rationale (line 24): the `DCS_C_PARAM_SOURCES` environment variable provides a functional path for TUI users, and the TUI's subprocess-wrapping architecture means no TUI code changes are needed.

### F-08 (recursive `_unwrap_declarator` depth) -- Addressed

The `_unwrap_declarator` docstring (lines 329-331) now documents that recursion depth is bounded by AST structure and that pathological cases produce at most ~8 levels of nesting, well within Python's recursion limit.

### F-09 (suppression interaction) -- No action needed

The existing suppression and deduplication systems handle parameter-derived findings correctly, as confirmed in the original Round 1 analysis.

### STRIDE-R1 (auditability of `c_param_sources` activation) -- Not addressed

`ScanStats` is not updated to record whether `c_param_sources` was active for a given scan. The `source.category == "func_param"` on individual findings provides per-finding traceability, but there is no scan-level metadata indicating the feature was enabled. This is a minor auditability gap. If a scan produces zero parameter-derived findings (because no non-static functions exist), there would be no evidence in the output that library mode was requested.

This does not block PASS because: (a) the MCP server logs tool parameters at invocation, (b) the CLI flag is visible in shell history, and (c) the `source.category` field on any findings that ARE produced provides the necessary traceability.

---

## What Went Well

The revision is thorough and directly addresses both Major findings with well-designed solutions rather than workarounds:

1. **F-01 resolution is principled.** Rather than just filtering names, the plan provides a clear rationale for the threshold value, documents the recall-precision tradeoff, includes dedicated test cases for both the excluded case (single-char) and the boundary case (two-char), and provides an explicit escalation path if the threshold proves insufficient.

2. **F-02 resolution is minimal and correct.** The 3-line category guard in `_analyze_function()` is the simplest possible fix that addresses the root cause. The plan correctly identifies that `source.function` already holds the parameter name (the variable to taint), so the existing fallback path works without further changes. The plan also provides concrete C code examples demonstrating both the simple case and the multi-line parameter list case.

3. **Semgrep conditional inclusion is well-designed.** Moving the parameter source rules to a separate directory with conditional `--config` inclusion is architecturally clean. It avoids polluting the default rule set, prevents accidental activation, and uses the Semgrep CLI's native multi-config support.

4. **Documentation quality is high.** The plan's deviation table, context alignment section, and prior plan references provide clear traceability. The new Non-Goals section entries (TUI integration, struct member parameters, C++ support) show that the scope was carefully considered.

5. **Test plan is comprehensive.** The test suite covers edge cases identified by the original review (short names, multi-line params, function pointer params, static/non-static mix, the `_find_assigned_var_near_line` bypass verification). The node type verification tests (lines 655-658) provide a safety net against tree-sitter grammar changes.
