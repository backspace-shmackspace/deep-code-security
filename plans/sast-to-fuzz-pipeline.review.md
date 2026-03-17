# Review: sast-to-fuzz-pipeline.md

**Plan:** `./plans/sast-to-fuzz-pipeline.md`
**Reviewed:** 2026-03-17
**Verdict:** PASS

---

## Prior Required Edits -- Resolution Status

### C-1 (FuzzFormatter backward compatibility): RESOLVED

Unchanged from prior review. The plan creates a new `HybridFormatter` protocol (lines 564-583) separate from `FuzzFormatter`. The existing `FuzzFormatter` protocol is NOT modified (line 593, 684, 1030). The HTML formatter is unaffected (line 1036).

### C-2 (FuzzerConfig.sast_contexts type mismatch): RESOLVED

Unchanged from prior review. `FuzzerConfig.sast_contexts` uses `dict[str, SASTContext] | None` (line 460, 1014). All method signatures are consistent.

### C-3 (MCP correlation response validation): RESOLVED

Unchanged from prior review. Crash-derived data is sanitized through `validate_crash_data()` (lines 639-642, 743-744, 768-774, 928, 1055, 1062).

### C-4 (TargetInfo lacks line range fields): RESOLVED

The prior review required adding `lineno` and `end_lineno` fields to `TargetInfo` so the bridge resolver can map `sink.line` to a containing function.

The revised plan adds Task 1.3 (lines 957-971) which specifies:

- `lineno: int | None = None` and `end_lineno: int | None = None` fields added to `TargetInfo` in `src/deep_code_security/fuzzer/models.py` (line 959). The `None` default ensures existing call sites and test fixtures that construct `TargetInfo` without line info are unaffected.
- `_make_target_info()` in `signature_extractor.py` populates these from `func_node.lineno` and `func_node.end_lineno` (line 962). These values are already available on the AST node (currently used to extract `source_code` at line 262 of the extractor but not stored).
- The resolution algorithm step 4 (line 287) references `TargetInfo.lineno` and `TargetInfo.end_lineno` with a forward reference to Task 1.3.
- Both files appear in the Files Summary table (lines 1106-1107) as Modify entries.
- Test cases `test_target_info_lineno_fields` and `test_target_info_lineno_defaults_none` are specified (lines 966-967).

The `None` default is appropriate: `_make_target_info()` always populates these fields from AST nodes (which always have `lineno` and `end_lineno`), so the bridge resolver will never encounter `None` values in practice. The default only applies to manually constructed `TargetInfo` objects in tests.

### C-5 (extract_targets_from_source skips instance methods): RESOLVED

The prior review required resolving the contradiction between the resolution algorithm (which includes instance methods with `requires_instance=True`) and the extractor (which skips them). The recommended fix was option (a): add an `include_instance_methods` flag.

The revised plan implements option (a) in Task 1.3 (lines 957-971):

- `is_instance_method: bool = False` field added to `TargetInfo` (line 960). Set to `True` for instance methods and classmethods.
- `include_instance_methods: bool = False` parameter added to `extract_targets_from_source()` (line 963). When `False` (default), instance methods and classmethods continue to be skipped with warning logs, preserving existing behavior. When `True`, they are included with `is_instance_method=True`.
- `include_instance_methods: bool = False` parameter added to `extract_targets_from_file()` (line 964), which passes through to `extract_targets_from_source()`.
- The resolution algorithm step 3 (line 286) calls `extract_targets_from_file(path, allow_side_effects=True, include_instance_methods=True)`.
- Step 6 (line 289) maps `TargetInfo.is_instance_method` to `FuzzTarget.requires_instance`.
- Task 1.4 (line 974) confirms the resolver calls with `include_instance_methods=True`.
- Test cases cover both flag values and static method exclusion (lines 968-970).
- Both files appear in the Files Summary table (lines 1106-1107) as Modify entries.

The default `False` preserves backward compatibility: existing fuzzer call sites (`extract_targets_from_path()` at line 311, `FuzzOrchestrator`, etc.) continue to skip instance methods. Only the bridge passes `True`.

---

## New Conflicts Introduced by This Revision

None found. Specific checks performed:

1. **`is_instance_method` naming for classmethods**: The field name `is_instance_method` is applied to both instance methods and classmethods (line 960). While a classmethod receives `cls` rather than `self`, the functional effect is the same -- the fuzzer cannot auto-construct either. The `FuzzTarget.requires_instance` field (lines 147-154) correctly describes both cases as "may require a manual harness." Test case `test_resolve_finding_in_classmethod` (line 858) explicitly covers this. Naming imprecision, not a correctness conflict.

2. **`extract_targets_from_path()` not updated**: This function (extractor line 304) is not modified, which is correct -- it is used by the fuzzer's normal discovery path and should retain the default `include_instance_methods=False`. The bridge calls `extract_targets_from_file()` directly. No conflict.

3. **Pydantic v2 compliance**: `int | None = None` and `bool = False` are valid Pydantic v2 field declarations with immutable defaults. No mutable default argument violation.

4. **Security rules**: No `eval()`, `exec()`, `shell=True`, or `yaml.load()` introduced by this revision.

5. **`__all__` exports**: Adding fields to `TargetInfo` does not require `__all__` changes. No conflict.

6. **Resolution algorithm with `None` defaults**: The bridge resolver always receives `TargetInfo` objects from `extract_targets_from_file()`, which calls `_make_target_info()`, which always populates `lineno` and `end_lineno` from the AST node. The `None` default is only relevant for manually constructed `TargetInfo` objects in tests, not for the bridge's runtime path. No conflict.

---

## Historical Alignment

### H-1: Consistent with merge-fuzzy-wuzzy post-merge features (PASS)

Unchanged. The `CorrelationEntry` model realizes the planned `CorrelatedFinding`.

### H-2: Consistent with fuzzer-container-backend conditional registration (PASS)

Unchanged. `deep_scan_hunt_fuzz` is registered conditionally using the same pattern as `deep_scan_fuzz`.

### H-3: Consistent with backend selection (PASS)

Unchanged. CLI uses `SubprocessBackend`, MCP uses `ContainerBackend`.

### H-4: Consistent with intraprocedural taint limitation (PASS)

Unchanged.

### H-5: Consistent with Architect output constraint (PASS)

Unchanged.

### H-6: FuzzFormatter protocol evolution pattern (PASS)

Unchanged. `HybridFormatter` is a separate protocol from `FuzzFormatter`.

### H-7: Context Alignment section exists and is substantive (PASS)

Unchanged. Section at lines 1131-1161 with CLAUDE.md patterns, prior plans, and documented deviations.

### H-8: Context metadata block (PASS)

Unchanged. Present at lines 1162-1167 with `claude_md_exists: true` and four consulted plans.

---

## Required Edits

None. All prior required edits (C-1 through C-5) are resolved. No new conflicts found.

---

## Optional Suggestions

All prior optional suggestions (S-1 through S-5) are resolved. No new suggestions.

---

**Reviewer:** Librarian (automated)
**Plan status:** Approved.
