# Red Team Review: SAST-to-Fuzz Pipeline (Round 3)

<!-- Review Metadata
reviewer_role: security-analyst
review_round: 3
review_date: 2026-03-17
plan_reviewed: plans/sast-to-fuzz-pipeline.md
plan_status: DRAFT
prior_review: plans/sast-to-fuzz-pipeline.redteam.md (round 2, 2026-03-17)
revision_scope: |
  Only two changes in this revision:
  1. TargetInfo model extended with lineno/end_lineno/is_instance_method fields (Task 1.3, fuzzer/models.py added to Files to Modify)
  2. extract_targets_from_source() extended with include_instance_methods: bool = False parameter (Task 1.3, signature_extractor.py)
source_code_verified:
  - src/deep_code_security/fuzzer/models.py (TargetInfo -- confirmed no lineno/end_lineno/is_instance_method fields exist yet)
  - src/deep_code_security/fuzzer/analyzer/signature_extractor.py (extract_targets_from_source, extract_targets_from_file, _make_target_info -- confirmed func_node.lineno/end_lineno already used internally but not propagated to TargetInfo)
  - src/deep_code_security/fuzzer/plugins/python_target.py (PythonTargetPlugin.discover_targets -- confirmed no include_instance_methods param passed, will get default False)
  - tests/test_fuzzer/test_analyzer/test_signature_extractor.py (confirmed existing tests call extract_targets_from_source without include_instance_methods)
-->

## Verdict: PASS

All Critical and Major findings from rounds 1 and 2 remain resolved. The two changes in this revision directly address NEW-MINOR-01 from round 2 (TargetInfo lacking line range fields and not appearing in the Files to Modify list). No new Critical or Major issues are introduced by these changes.

---

## Revision-Specific Analysis

### Change 1: `TargetInfo` model extended with `lineno`/`end_lineno`/`is_instance_method` fields

**Assessment: Sound. No new issues.**

The plan (Task 1.3, lines 958-960) adds three fields to `TargetInfo` in `fuzzer/models.py`:

- `lineno: int | None = None` -- 1-based start line of function definition.
- `end_lineno: int | None = None` -- 1-based end line of function definition.
- `is_instance_method: bool = False` -- True for instance methods and classmethods.

**Backward compatibility verified.** All three fields have defaults (`None`, `None`, `False`), so existing call sites that construct `TargetInfo` without these fields are unaffected. Verified in source:

- `_make_target_info()` (signature_extractor.py, line 280) constructs `TargetInfo` without these fields today -- will be updated to populate them.
- Test files (`tests/test_fuzzer/test_analyzer/test_signature_extractor.py`) construct `TargetInfo` indirectly through `extract_targets_from_source()` -- no breakage.
- `FuzzReport.targets` (models.py, line 104) stores `TargetInfo` objects -- serialization is additive (new optional fields with defaults).
- No existing consumers inspect `lineno`, `end_lineno`, or `is_instance_method` on `TargetInfo`, so the fields are purely additive.

**Population source verified.** The plan specifies that `_make_target_info()` will populate `lineno` from `func_node.lineno` and `end_lineno` from `func_node.end_lineno` (line 962). The current source code already uses these AST node attributes at line 262 (`source_lines[func_node.lineno - 1 : func_node.end_lineno]`), confirming they are reliably available.

**Files Summary updated.** `src/deep_code_security/fuzzer/models.py` now appears in the Modify list (line 1106), resolving the gap identified in round 2's NEW-MINOR-01.

**Five test cases specified** (lines 966-970): lineno population, lineno defaults, instance methods excluded by default, instance methods included with flag, static methods not marked as instance methods.

### Change 2: `extract_targets_from_source()` extended with `include_instance_methods: bool = False`

**Assessment: Sound. No new issues.**

The plan (Task 1.3, lines 963-964) adds `include_instance_methods: bool = False` to both `extract_targets_from_source()` and `extract_targets_from_file()`.

**Default behavior preserved.** When `False` (default), instance methods and classmethods continue to be skipped with warning logs -- exactly matching the current behavior at lines 207-222 of `signature_extractor.py`. Existing callers are unaffected:

- `PythonTargetPlugin.discover_targets()` calls `extract_targets_from_path()` (python_target.py, line 48) without passing `include_instance_methods`, so it gets the default `False`. Instance methods remain excluded from the fuzzer's normal discovery path.
- `extract_targets_from_path()` calls `extract_targets_from_file()` (signature_extractor.py, line 311) -- the plan should also propagate `include_instance_methods` through `extract_targets_from_path()` for completeness, but since no caller uses it today, this is a minor implementation detail, not a correctness issue.
- All 5 existing test calls to `extract_targets_from_source()` (test_signature_extractor.py) omit the parameter and will get the default `False`.

**Bridge usage correct.** The bridge resolver calls `extract_targets_from_file(path, allow_side_effects=True, include_instance_methods=True)` (plan lines 286, 974), which enables instance method inclusion exclusively for the bridge's use case.

**No API surface leakage.** The `include_instance_methods` parameter is internal to the bridge-to-extractor interaction. It does not appear in CLI arguments, MCP tool parameters, or any user-facing config.

---

## Prior Findings Status (Unchanged from Round 2)

| # | Severity | Status | Title |
|---|----------|--------|-------|
| CRITICAL-01 | Critical | Resolved | Impedance mismatch: SAST finds framework globals, fuzzer needs function parameters |
| MAJOR-01 | Major | Resolved | Instance method handling (now included with annotation) |
| MAJOR-02 | Major | Resolved | Function boundary detection reuses signature_extractor directly |
| MAJOR-03 | Major | Resolved | `fuzz_confirmed` renamed to `crash_in_finding_scope` |
| MAJOR-04 | Major | Resolved | SAST prompt anchoring mitigated by diversity directive + iteration-1-only injection |
| MINOR-01 | Minor | Resolved | `sast_contexts` type unified to `dict[str, SASTContext] \| None` |
| MINOR-02 | Minor | Partially resolved | Rollout plan improved with acceptance criteria but still single-release |
| MINOR-03 | Minor | Partially resolved | `--iterations` default difference (5 vs 10) still undocumented |
| MINOR-04 | Minor | Resolved | Async functions handled by signature_extractor |
| MINOR-05 | Minor | Partially resolved | Dual `analysis_mode` fields persist but are manageable |

---

## Round 2 NEW Findings Status

### NEW-MINOR-01: TargetInfo Model Lacks Line Range Fields Required by Bridge Resolver

**Status: Resolved**

This revision directly addresses this finding:

1. `lineno: int | None = None` and `end_lineno: int | None = None` fields added to `TargetInfo` (plan line 959).
2. `is_instance_method: bool = False` field added to `TargetInfo` (plan line 960).
3. `_make_target_info()` updated to populate these from AST node attributes (plan line 962).
4. `src/deep_code_security/fuzzer/models.py` added to the Files Summary Modify list (plan line 1106).

All four sub-recommendations from round 2 are addressed.

### NEW-MINOR-02: Fallback Behavior When Bridge Names Do Not Match Fuzzer

**Status: Unchanged (Minor)**

This finding is not affected by the current revision. The TOCTOU window between hunt and fuzz remains a theoretical concern, mitigated by the plan's reuse of `signature_extractor.py`. No action required for plan approval.

---

## New Findings

### NEW-MINOR-03: `extract_targets_from_path()` Does Not Propagate `include_instance_methods`

**Severity: Minor**

The plan adds `include_instance_methods` to `extract_targets_from_source()` (line 963) and `extract_targets_from_file()` (line 964), but does not mention updating `extract_targets_from_path()` (signature_extractor.py, line 304), which calls `extract_targets_from_file()` internally.

Currently, no caller of the bridge uses `extract_targets_from_path()` -- the bridge resolver calls `extract_targets_from_file()` directly (plan line 286). So this is not a correctness issue for the current plan. However, if a future caller wanted to use `extract_targets_from_path()` with instance method inclusion, the parameter would be silently dropped.

**Recommendation:** During implementation, also add `include_instance_methods: bool = False` to `extract_targets_from_path()` and pass it through to `extract_targets_from_file()`, for API consistency. This is a one-line addition and does not require a plan revision.

---

## Summary of All Findings

| # | Severity | Status | Title |
|---|----------|--------|-------|
| CRITICAL-01 | Critical | Resolved | Impedance mismatch: SAST finds framework globals, fuzzer needs function parameters |
| MAJOR-01 | Major | Resolved | Instance method handling (now included with annotation) |
| MAJOR-02 | Major | Resolved | Function boundary detection reuses signature_extractor directly |
| MAJOR-03 | Major | Resolved | `fuzz_confirmed` renamed to `crash_in_finding_scope` |
| MAJOR-04 | Major | Resolved | SAST prompt anchoring mitigated by diversity directive + iteration-1-only injection |
| MINOR-01 | Minor | Resolved | `sast_contexts` type unified to `dict[str, SASTContext] \| None` |
| MINOR-02 | Minor | Partially resolved | Rollout plan improved but still single-release |
| MINOR-03 | Minor | Partially resolved | `--iterations` default difference (5 vs 10) undocumented |
| MINOR-04 | Minor | Resolved | Async functions handled by signature_extractor |
| MINOR-05 | Minor | Partially resolved | Dual `analysis_mode` fields persist but manageable |
| NEW-MINOR-01 | Minor | Resolved | `TargetInfo` now has `lineno`/`end_lineno`/`is_instance_method` fields |
| NEW-MINOR-02 | Minor | Unchanged | Fallback-to-all-targets when bridge names do not match fuzzer |
| NEW-MINOR-03 | Minor | New | `extract_targets_from_path()` does not propagate `include_instance_methods` |

Zero Critical findings. Zero Major findings. All prior Critical and Major findings resolved. The plan is approved for implementation.

<!-- Review completed 2026-03-17 -->
