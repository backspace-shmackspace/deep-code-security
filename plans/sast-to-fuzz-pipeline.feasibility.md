# Feasibility Review: SAST-to-Fuzz Pipeline (Revision 2)

**Plan:** `plans/sast-to-fuzz-pipeline.md`
**Reviewer:** code-reviewer (agent)
**Date:** 2026-03-17
**Plan Status:** DRAFT (revised)
**Prior Feasibility:** superseded by this document

---

## Verdict: PASS

The three changes introduced in this revision are feasible, internally consistent, and introduce no new security concerns. The two previously unresolved minor items (m-3, m-6) and the one previously unresolved minor item (m-4) carry forward unchanged in status. N-1 from the prior review is addressed below with updated analysis given the new changes. No new concerns are introduced.

---

## Changes Under Review

This review covers only the delta from the prior PASS revision:

1. `TargetInfo` model extended with `lineno: int | None = None`, `end_lineno: int | None = None`, and `is_instance_method: bool = False` fields.
2. `extract_targets_from_source()` extended with `include_instance_methods: bool = False` parameter (passed through `extract_targets_from_file()`).
3. Task numbering adjusted (new Task 1.3 inserted, prior 1.3 through 1.4 renumbered to 1.4 through 1.5).

---

## Change 1: `TargetInfo` Model Extension

**Assessment: Feasible. No issues.**

The current `TargetInfo` in `/Users/imurphy/projects/deep-code-security/src/deep_code_security/fuzzer/models.py` has ten fields, none of which are `lineno`, `end_lineno`, or `is_instance_method`. The plan adds all three with defaults (`None`, `None`, `False`), making them optional. This is a purely additive change to a Pydantic `BaseModel`.

**Backward compatibility is clean.** Every existing call site that constructs `TargetInfo` without line fields continues to work. The test fixtures in `tests/test_fuzzer/conftest.py` (the `sample_target_info` fixture) and in `tests/test_fuzzer/test_models.py` construct `TargetInfo` directly without line number arguments and will continue to pass without modification.

**The `_make_target_info()` function already reads `func_node.lineno` and `func_node.end_lineno`.** Lines 262--263 of the extractor (`source_lines[func_node.lineno - 1 : func_node.end_lineno]`) confirm that both attributes are already accessed on the AST node. Populating the new `TargetInfo` fields from those same values requires only adding two keyword arguments to the `TargetInfo(...)` constructor call at line 280. There is no risk of `AttributeError`: `lineno` and `end_lineno` are guaranteed present on `ast.FunctionDef` and `ast.AsyncFunctionDef` nodes by the Python AST specification.

**The `is_instance_method` field** is correctly differentiated from the existing `is_static_method: bool` field already present in `TargetInfo`. The extractor already has `_is_instance_method()`, `_is_class_method()`, and `_is_static_method()` helpers (lines 150--174) whose return values can be used to populate this field with no new logic.

**One minor precision note (non-blocking):** The plan specifies `is_instance_method=True` for both instance methods and classmethods. The existing `_is_instance_method()` helper returns `False` for classmethods (it checks `not _is_class_method(func_node)`). The plan's intent -- that `requires_instance=True` should be set on both instance methods and classmethods since both require a constructed receiver for invocation -- is correct and reasonable. But `_is_instance_method()` alone will not cover classmethods. The implementation must OR the result with `_is_class_method()` when setting `is_instance_method` on the `TargetInfo`. The plan's Task 1.3 description ("Set to `True` when the function is an instance method or classmethod inside a class (first param is `self` or `cls`, and no `@staticmethod` decorator)") is accurate, but the implementer must use `_is_instance_method(func_node, is_in_class) or _is_class_method(func_node)` -- not just `_is_instance_method()` alone. This is a straightforward implementation detail, not a design flaw. The test case `test_extract_targets_include_instance_methods_true` should cover both instance methods and classmethods to catch this.

---

## Change 2: `extract_targets_from_source()` / `extract_targets_from_file()` Extension

**Assessment: Feasible. No issues.**

The plan adds `include_instance_methods: bool = False` to both `extract_targets_from_source()` and `extract_targets_from_file()`. The default is `False`, preserving existing behavior on all call sites in the codebase. The `extract_targets_from_path()` function is not listed as modified; it passes through to `extract_targets_from_file()`, so callers of `extract_targets_from_path()` also get the existing behavior unchanged.

The behavioral change when `include_instance_methods=True` is straightforward. The existing `extract_targets_from_source()` has two `continue` statements at lines 208--221 that skip instance methods and classmethods with `logger.warning()`. Under `include_instance_methods=True`, those `continue` statements are bypassed and the methods are passed to `_make_target_info()` instead. The `_make_target_info()` function already handles functions inside classes correctly (the `class_name` parameter and `qualified_name` construction at lines 250--253 already produce `Class.method` names). No structural change to `_make_target_info()` is needed other than populating the three new `TargetInfo` fields.

**The resolver's call site** (`extract_targets_from_file(path, allow_side_effects=True, include_instance_methods=True)`) correctly passes both flags. The `allow_side_effects=True` flag is already supported by the extractor and routes through `_make_target_info()` without change.

**The warning log suppression** when `include_instance_methods=True` is implicit in the plan (the `continue` is not executed, so the warning is not emitted). This is correct behavior -- callers who explicitly opt in to instance methods should not receive spurious "Skipping instance method" warnings.

---

## Change 3: Task Numbering (Task 1.3 Inserted)

**Assessment: No feasibility impact.** Pure documentation restructuring. Prior tasks 1.3 and 1.4 become 1.4 and 1.5. The content of all tasks is unchanged. The Files Summary table is consistent with the task descriptions.

---

## Prior Concerns: Updated Status

### Previously Resolved (M-1 through M-5, m-1, m-2, m-5, m-7)

No change from prior review. All remain resolved.

### m-3: CWE guidance map missing CWE-134 and CWE-676
**Status: Unresolved (unchanged).** No change in this revision. Behavior degrades gracefully.

### m-4: Dry-run path does not use SAST-enriched prompt
**Status: Unresolved (unchanged).** No change in this revision. Task 4.2 still does not mention updating `_dry_run()`. UX gap only; not a correctness bug.

### m-6: No automated integration test for the end-to-end pipeline
**Status: Unresolved (unchanged).** No change in this revision. Rollout Plan still specifies manual validation only.

### N-1: `fuzzer.config` gains import-time dependency on `bridge.models`
**Status: Unresolved, and now more concrete.**

The new Task 1.3 makes clear that `bridge.models` is the home of `SASTContext`, and Task 4.1 requires `fuzzer/config.py` to import `SASTContext` from `bridge.models`. With the new `TargetInfo` fields landing in `fuzzer/models.py` (Task 1.3), the dependency graph is now:

```
fuzzer.config  -->  bridge.models  -->  hunter.models
fuzzer.models  (no new external deps -- TargetInfo fields are primitive types)
bridge.resolver  -->  fuzzer.analyzer.signature_extractor  -->  fuzzer.models
```

The `fuzzer.models` changes (new fields with primitive/`None` defaults) introduce no new imports at all -- `int | None` and `bool` are builtins. That part of the change is clean.

The `fuzzer.config` -> `bridge.models` coupling noted in the prior review remains the only coupling concern. No new coupling is introduced by this revision. The prior recommendation to use `TYPE_CHECKING` guards and `Any` at runtime to keep the import lazy still stands and is still unaddressed by the plan. This remains minor and non-blocking.

---

## Security Assessment

No change from prior review. The three changes are entirely internal data model and API-signature modifications with no new security surface:

- New `TargetInfo` fields (`lineno`, `end_lineno`, `is_instance_method`) are populated from trusted AST node attributes on already-parsed source files, not from untrusted input.
- The `include_instance_methods` flag controls code path selection within the extractor; it accepts no external data.
- No new subprocess calls, no new file path handling, no new template rendering, no new MCP input surface.

No automatic FAIL triggers are present.

---

## Implementation Complexity Assessment

No change from prior review. The new Task 1.3 is low complexity: additive changes to an existing Pydantic model and an existing extractor function, both of which already have the underlying data (`func_node.lineno`, `func_node.end_lineno`, `_is_instance_method()`, `_is_class_method()`) immediately available. The total estimate remains ~4--5 days.

The one implementation detail to note for the developer: when populating `TargetInfo.is_instance_method` in `_make_target_info()`, use `_is_instance_method(func_node, is_in_class=bool(class_name)) or _is_class_method(func_node)` to correctly cover both instance methods and classmethods as the plan intends.

---

## Summary

| ID | Category | Status |
|----|----------|--------|
| M-1 | Major (prior) | Resolved |
| M-2 | Major (prior) | Resolved |
| M-3 | Major (prior) | Resolved |
| M-4 | Major (prior) | Resolved |
| M-5 | Major (prior) | Resolved |
| m-1 | Minor (prior) | Resolved |
| m-2 | Minor (prior) | Resolved |
| m-3 | Minor (prior) | Unresolved -- CWE-134/676 missing from guidance map |
| m-4 | Minor (prior) | Unresolved -- `_dry_run()` does not use SAST-enriched prompt |
| m-5 | Minor (prior) | Resolved |
| m-6 | Minor (prior) | Unresolved -- no automated integration test target |
| m-7 | Minor (prior) | Resolved |
| N-1 | Minor (prior) | Unresolved -- `fuzzer.config` gains hard import-time dependency on `bridge.models`; unchanged by this revision |
| C-1 | Change 1 note | Non-blocking -- `is_instance_method` field must be set using `_is_instance_method() or _is_class_method()` to cover both cases; `_is_instance_method()` alone misses classmethods |
