# Feasibility Review: scanner-tui.md (Revision 2)

**Reviewer:** code-reviewer (v1.0.0)
**Date:** 2026-03-20
**Plan reviewed:** `./plans/scanner-tui.md` (Status: DRAFT, revised)

## Verdict: PASS

The revised plan addresses all five prior Major concerns (M-1 through M-5) satisfactorily. The single-scan-plus-in-process-conversion strategy is sound, the JSON extraction paths are now correct, coverage exemptions are properly scoped, and microsecond-precision timestamps resolve the directory collision risk. The plan introduces no new security regressions and follows established project patterns.

Two new Major concerns were identified during this review. Neither is blocking for plan approval, but both must be addressed before or during implementation.

---

## Prior Concerns Resolution

### M-1: Multiple subprocess invocations per scan (RESOLVED)

The revised plan runs the scan exactly once with `--format json`, then uses `shared.formatters.get_formatter("sarif")` and `get_formatter("html")` in-process for format conversion (lines 268-294, Deviation D-3). This eliminates the 200% time penalty. The plan correctly identifies the formatters as pure data transformers with no analysis pipeline dependency.

**Status:** Fully resolved.

### M-2: Wrong fuzz findings_count JSON path (RESOLVED)

The revised plan now specifies the correct extraction path `output["summary"]["unique_crash_count"]` (line 310). This matches the actual JSON structure in `/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/formatters/json.py` lines 74-76.

**Status:** Fully resolved.

### M-3: Missing hunt-fuzz backend_used extraction path (RESOLVED)

The revised plan now specifies the correct hunt-fuzz extraction path `output["hunt_result"]["stats"]["scanner_backend"]` (lines 317-318). This matches the actual JSON structure in `json.py` lines 164-176 where `hunt_result` contains `stats`.

**Status:** Fully resolved.

### M-4: Coverage exemption too broad (RESOLVED)

The revised plan explicitly states that only `app.py` and `screens/*.py` are excluded from the main `make test` coverage gate (lines 700-711). The pure-Python modules `models.py`, `storage.py`, and `runner.py` are included in main coverage, ensuring the business logic with the highest bug risk is always tested.

**Status:** Fully resolved.

### M-5: Timestamp directory collision (RESOLVED)

The revised plan uses microsecond-precision timestamps in the format `YYYY-MM-DD-HH-MM-SS-ffffff` (line 87). The `create_run_dir` docstring explicitly calls out microsecond precision for collision prevention (line 189). Test case `test_create_run_dir_unique_timestamps` verifies two immediate calls produce different directories (line 645).

**Status:** Fully resolved.

---

## Prior Minor Concerns Resolution

### m-1: DCS_OUTPUT_DIR in shared Config (RESOLVED)

The revised plan reads `DCS_OUTPUT_DIR` directly in `tui/storage.py` via `os.environ.get()`. Shared `config.py` is NOT modified (lines 466, 501, 757, 881). Deviation D-5 explicitly documents this decision and the rationale.

**Status:** Fully resolved.

### m-2: ScanConfig.extra_args foot-gun (RESOLVED)

The revised plan removes `extra_args` entirely. `ScanConfig` exposes only explicitly-typed fields (line 296). Section "No free-form CLI argument pass-through" is listed as a non-goal (line 23). The ScanConfigScreen section confirms "no free-form text input for additional CLI arguments" (line 401).

**Status:** Fully resolved.

### m-3 through m-7: Various minor concerns (NOT ADDRESSED, CARRIED FORWARD)

The following prior minor concerns were not explicitly addressed in the revision and are carried forward below where still applicable.

---

## Concerns

### Critical

None.

### Major

**M-6: In-process format conversion requires JSON-to-DTO deserialization -- feasibility gap not addressed**

The plan states the runner will "read the JSON output file and use the `shared.formatters` registry directly to produce SARIF and HTML files in-process" (lines 289-292). However, the formatters accept typed Pydantic DTOs (`HuntResult`, `FullScanResult`, `HuntFuzzResult`, `FuzzReportResult`), not raw JSON strings. This means the runner must:

1. Read the JSON file produced by the subprocess.
2. Deserialize that JSON back into the correct protocol DTO (e.g., `HuntResult.model_validate(json_data)` or reconstruct it manually).
3. Pass the DTO to the formatter.

Step 2 is non-trivial for several reasons:

- The JSON output from `JsonFormatter.format_hunt()` serializes findings via `serialize_models()` which calls `model.model_dump()`. The resulting JSON structure is a plain dict, not a Pydantic-serialized form. Reconstructing a `HuntResult` from it requires deserializing nested `RawFinding` objects, each containing `Source`, `Sink`, and `TaintPath` models.
- For `FullScanResult`, the deserialization also includes `VerifiedFinding`, `RemediationGuidance`, and their nested models.
- For `HuntFuzzResult`, the deserialization includes `BridgeResult` and `CorrelationReport` from the bridge module.
- The `ScanStats` model is serialized via `serialize_model()` which may lose type information.

The plan does not specify how this deserialization will work. The DTO models in `shared/formatters/protocol.py` are `BaseModel` subclasses that should support `model_validate()`, but this has not been verified end-to-end for all scan types.

**Recommended adjustment:** The plan should specify the deserialization approach. Options:
- (a) Use `HuntResult.model_validate(json.loads(json_string))` and verify that the `serialize_models()` output is round-trip compatible with `model_validate()` for all scan types.
- (b) Store the pre-serialization DTO in memory (the runner is already in-process with the formatter registry) rather than reading the JSON file back. The subprocess writes JSON to a file; the runner parses it back into DTOs for SARIF/HTML conversion.
- (c) Add explicit `from_json()` class methods to the protocol DTOs for reliable deserialization.

Option (a) is simplest if the round-trip works. Add a test case (`test_hunt_result_json_roundtrip`, `test_full_scan_result_json_roundtrip`, etc.) that verifies `model_validate(json.loads(JsonFormatter().format_hunt(dto)))` reconstructs a valid DTO.

**M-7: HTML formatter does not implement format_hunt_fuzz() -- SARIF/HTML generation will silently fail for hunt-fuzz scans**

The plan states SARIF and HTML reports are "derived from the JSON output using the formatter registry in-process" for all scan types (lines 268-271, Acceptance Criterion 8). However, the HTML formatter (`/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/formatters/html.py`) does NOT implement `format_hunt_fuzz()`. It implements `format_hunt`, `format_full_scan`, `format_fuzz`, and `format_replay`, but not `format_hunt_fuzz`.

The SARIF formatter does implement `format_hunt_fuzz()` (confirmed at line 369 of `sarif.py`).

This means for `hunt-fuzz` scans, the runner will produce a JSON report and a SARIF report, but HTML generation will fail. The plan's fallback behavior (log a warning and continue with JSON as primary artifact, line 293) handles this gracefully at runtime, but the plan text and Acceptance Criterion 8 imply HTML will always be generated.

Known Limitation 11 in `CLAUDE.md` notes "HTML formatter not implemented for hunt-fuzz output" -- this is a pre-existing limitation, not introduced by this plan.

**Recommended adjustment:** Update Acceptance Criterion 8 and the report storage layout example (lines 76-83) to clarify that HTML reports are only generated for scan types where the HTML formatter supports the corresponding format method. Specifically, `hunt-fuzz` runs produce `hunt-fuzz.json` and `hunt-fuzz.sarif` but not `hunt-fuzz.html`. The runner should check `supports_hybrid(formatter)` before calling `format_hunt_fuzz()` on the HTML formatter.

### Minor

**m-3: DirectoryTree can expose paths outside DCS_ALLOWED_PATHS (CARRIED FORWARD)**

Still applicable. The revised plan repeats the same design: informational warning if outside allowed paths, with actual validation deferred to the subprocess (lines 389-391, 566). The UX concern remains -- the user can browse to an invalid path, configure and start a scan, then wait for it to fail.

**Recommended adjustment:** Unchanged from prior review. Consider pre-flight validation on the TargetSelectScreen before navigating to ScanConfigScreen, or restricting the DirectoryTree root when `DCS_ALLOWED_PATHS` is explicitly set.

**m-4: No handling of dcs version mismatch (CARRIED FORWARD)**

Still applicable. The plan mentions checking `dcs --version` at startup (line 532, risk table) but does not specify version comparison logic. The revised plan's `sys.executable` invocation strategy (line 286) reduces the risk (same Python environment), but does not eliminate it if the package is partially upgraded.

**Recommended adjustment:** Compare `dcs --version` output against `deep_code_security.__version__` at startup and warn if they differ.

**m-5: Platform-native opener needs error handling (CARRIED FORWARD)**

Still applicable. The revised plan describes the opener behavior in detail (lines 374-382) but does not specify error handling for missing commands or headless environments.

**Recommended adjustment:** Wrap opener subprocess calls in try/except. On failure, display a TUI notification showing the file path so the user can open it manually.

**m-8: Textual version pin has no upper bound**

The plan pins `textual>=0.70.0` (line 27, also in Task 5.1 line 832). Textual is pre-1.0 and has made breaking widget API changes between minor versions. The plan depends on specific widget classes (`DirectoryTree`, `RichLog`, `DataTable`, `RadioSet`, `SelectionList`) whose APIs may change.

**Recommended adjustment:** Add an upper bound: `textual>=0.70.0,<1.0.0`. If Textual's release cadence is fast enough to cause churn, consider a tighter bound like `<0.80.0`.

**m-9: project_name collisions across different absolute paths are acknowledged but have no mitigation path**

The plan acknowledges in Known Limitation 7 (line 925) that scanning `/home/user/a/openssl` and `/opt/vendor/openssl` produces the same project name. Their run histories merge silently. While individual runs are distinguishable by `target_path` in `meta.json`, the HistoryScreen's project selector dropdown would show a single "openssl" entry with interleaved runs from two different codebases.

**Recommended adjustment:** Consider using a hash suffix when collisions are detected. For example, if `list_runs("openssl")` returns runs with different `target_path` values, the HistoryScreen could display them as separate logical projects (e.g., by grouping runs by `target_path` within the project). Alternatively, document this as a known UX limitation and defer.

**m-10: `ScanRunner.run()` needs to handle `--output-file` path validation interaction**

The runner constructs `--output-file {run_dir}/{prefix}.json` (line 269). The `run_dir` is inside `DCS_OUTPUT_DIR` (default `~/.dcs/reports/`), but the `dcs` CLI's `_write_output()` function validates the output file path against `DCS_ALLOWED_PATHS` (line 58 of `cli.py`). If `DCS_ALLOWED_PATHS` is set to the project directory (e.g., `/Users/imurphy/projects/openssl`) and does not include `~/.dcs/`, the subprocess will reject the `--output-file` path.

**Recommended adjustment:** The runner should either:
- (a) Capture the scan's JSON output from stdout instead of using `--output-file` (remove `--output-file` and capture stdout in the runner). This avoids the path validation issue entirely.
- (b) Document that `DCS_ALLOWED_PATHS` must include `DCS_OUTPUT_DIR` (or that `DCS_OUTPUT_DIR` should be under an allowed path).
- (c) Use `--force` to ensure the output file is always written (already needed for re-runs).

Option (a) is cleanest. The runner already captures stdout; the JSON output goes to stdout by default when `--output-file` is not specified. The runner can then write the file to `run_dir` itself.

---

## Security Assessment

**No security regressions.** The revised plan maintains the same security posture as the prior version:

1. The TUI sits entirely on the user side of the trust boundary. No new trust boundaries are introduced.
2. All scanning operations are delegated to the `dcs` CLI subprocess.
3. `asyncio.create_subprocess_exec()` with list-form arguments is used exclusively. No `shell=True` anywhere.
4. `meta.json` is handled with `json.loads()` + Pydantic validation. No YAML loading. No code execution.
5. Project name sanitization uses a strict allowlist regex `[a-zA-Z0-9._-]`, rejects `..` and `/`, enforces max length 64.
6. Report file paths are constructed programmatically from sanitized components. No user-controlled path injection at the point of file opening.
7. The `os.startfile()` approach on Windows correctly avoids the `shell=True` requirement that `start` would need.
8. The in-process formatter import (Deviation D-3) accesses only `shared.formatters`, which are pure data transformers. No analysis pipeline, no sandbox execution, no untrusted data processing.
9. Deviation D-4 correctly identifies that `path_validator.py` is an MCP trust boundary mechanism that should not be applied to a local developer tool.

---

## Test Coverage Adequacy

The test plan is comprehensive for the core modules. Observations:

**Adequate coverage:**
- Model validation including edge cases (negative duration, invalid scan type)
- Storage layout creation, read/write, listing, sanitization (including `..` rejection, max length)
- Runner command construction for all scan types, all options, no shell=True assertion
- Runner stderr pattern parsing with named constants
- JSON extraction paths per scan type (hunt, full-scan, hunt-fuzz, fuzz) with fallback on malformed JSON
- Cancellation behavior (SIGTERM then SIGKILL)

**Gaps to address (non-blocking):**
- No test for `ReportStorage` behavior when `DCS_OUTPUT_DIR` is not writable (the plan mentions fallback to temp dir at line 33, Assumption 6, but no test case verifies this)
- No test for `derive_project_name` with symlinked paths
- No test for the JSON-to-DTO deserialization round-trip needed by the in-process format conversion (see M-6)
- No test for the HTML formatter `format_hunt_fuzz` absence (see M-7) -- the runner should have a test that verifies graceful fallback when a formatter lacks a method for the given scan type

---

## Breaking Changes / Backward Compatibility

**No breaking changes identified.** The revised plan's compatibility analysis is accurate:

1. Existing CLI commands are unchanged.
2. Existing MCP tools are unchanged.
3. `shared/config.py` is NOT modified (improvement over the prior plan version).
4. `textual` is an optional dependency via `[tui]` extra (confirmed: no existing optional dep group uses that name in pyproject.toml).
5. The `dcs tui` command fails gracefully without textual installed.

---

## Implementation Complexity Assessment

| Component | Realistic Estimate | Notes |
|-----------|-------------------|-------|
| Models + Storage | 1-2 days | Straightforward Pydantic + filesystem. Low risk. |
| Scan Runner | 2-3 days | Async subprocess with stderr parsing. The JSON-to-DTO round-trip (M-6) and formatter availability check (M-7) add ~0.5 day if not pre-validated. |
| TUI Screens | 3-5 days | Five screens with Textual widgets. Textual's API is straightforward but screen navigation, worker threads, and timer management add integration testing time. |
| CLI + Docs | 0.5 day | Trivial changes. |
| Testing | 2-3 days | Textual pilot tests require learning Textual's test framework. The non-Textual tests (models, storage, runner) are straightforward. |
| **Total** | **8-13 days** | Reasonable for a single developer. No red flags on complexity. |

---

## What Went Well

1. **Thorough resolution of all prior Major concerns.** Each M-1 through M-5 was addressed with specific plan text, not hand-waved. The in-process format conversion strategy (M-1) is well-justified with the Deviation D-3 pattern.
2. **Clean separation of TUI-only config.** Moving `DCS_OUTPUT_DIR` out of shared config (Deviation D-5) prevents false expectations and keeps the config singleton clean.
3. **Elimination of `extra_args`.** Removing the free-form argument pass-through closes a foot-gun without reducing functionality. Users who need custom flags use the CLI directly -- which is the correct UX.
4. **Microsecond-precision timestamps with test coverage.** The timestamp format change includes a corresponding test case that verifies uniqueness, not just a design document assertion.
5. **Explicit `findings_count` and `backend_used` extraction paths per scan type.** The plan now documents all four scan types (hunt, full-scan, hunt-fuzz, fuzz) with their correct JSON paths, making implementation unambiguous.
6. **Trust boundary analysis remains excellent.** The revised plan preserves the clear articulation of why the TUI introduces no new trust boundaries and correctly identifies each exception (formatter import, path validation bypass) with justification.

---

## Summary of Recommended Adjustments

| ID | Severity | Summary | Resolution Status |
|----|----------|---------|-------------------|
| M-1 | Major | Fix multi-invocation scan strategy | RESOLVED in revision |
| M-2 | Major | Correct fuzz findings_count JSON path | RESOLVED in revision |
| M-3 | Major | Add hunt-fuzz backend_used extraction path | RESOLVED in revision |
| M-4 | Major | Only exempt Textual-dependent files from main coverage | RESOLVED in revision |
| M-5 | Major | Add microsecond precision to timestamp directories | RESOLVED in revision |
| M-6 | Major | Specify JSON-to-DTO deserialization approach for in-process conversion | NEW -- address before implementation |
| M-7 | Major | HTML formatter lacks format_hunt_fuzz(); update plan text and acceptance criteria | NEW -- address before implementation |
| m-1 | Minor | Keep DCS_OUTPUT_DIR in TUI storage, not shared config | RESOLVED in revision |
| m-2 | Minor | Remove extra_args field | RESOLVED in revision |
| m-3 | Minor | Restrict DirectoryTree browsing when DCS_ALLOWED_PATHS is set | CARRIED FORWARD |
| m-4 | Minor | Add version mismatch detection at startup | CARRIED FORWARD |
| m-5 | Minor | Add error handling for platform-native opener commands | CARRIED FORWARD |
| m-6 | Minor | Use filename for single-file project name derivation | Acknowledged in Known Limitations |
| m-7 | Minor | Add upper bound to textual version pin | Renumbered as m-8, CARRIED FORWARD |
| m-8 | Minor | Textual version pin needs upper bound | CARRIED FORWARD (was m-7) |
| m-9 | Minor | Project name collisions across different paths | NEW |
| m-10 | Minor | --output-file path may conflict with DCS_ALLOWED_PATHS | NEW |
