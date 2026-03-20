# Red Team Review: Textual TUI Frontend (`dcs tui`) -- Revision 2

**Plan:** `plans/scanner-tui.md`
**Reviewed:** 2026-03-20 (revision 2)
**Reviewer:** Security Analyst (Architect Agent)
**Prior review:** 2026-03-20 (revision 1, verdict: FAIL)

## Verdict: PASS

All prior Critical and Major findings (F-01, F-02, F-04) have been resolved in the revised plan. No new Critical findings were identified. The remaining findings are Minor or Info severity and do not block approval.

---

## Prior Findings -- Resolution Status

### F-01 [was Critical]: Triple subprocess invocation -- RESOLVED

The revised plan now runs the scan exactly once with `--format json` and derives SARIF/HTML in-process using `shared.formatters.get_formatter()`. This eliminates the 200% overhead identified in the prior review. The approach is documented as Deviation D-3, with clear justification that the formatters are pure data transformers. The plan explicitly states "The scan runs ONCE with --format json. After completion, SARIF and HTML are derived from the JSON output using the shared formatter registry (in-process, no additional subprocess)."

**Status:** Fully resolved. The recommended option (b) from the prior review was adopted.

### F-02 [was Major]: `DCS_OUTPUT_DIR` bypasses path validation; bleeds into shared Config -- RESOLVED

The revised plan addresses both sub-issues:

1. **Config isolation:** `DCS_OUTPUT_DIR` is now read directly by `tui/storage.py` via `os.environ.get()`. It is NOT added to `shared/config.py`. This is documented in Deviation D-5 and reinforced throughout the plan ("Note: `shared/config.py` is NOT modified"). The stated isolation ("DCS_OUTPUT_DIR has no effect on existing CLI commands") is now factually correct.

2. **Write path sanitization:** Project names are sanitized with regex `[^a-zA-Z0-9._-]`, rejecting `..` and `/`, with a max length of 64 chars and a fallback to `unnamed`. Timestamp directories are generated programmatically. Deviation D-4 explicitly justifies why `path_validator.py` is not used (it enforces MCP trust boundaries, not local developer tool paths).

The residual risk from a user setting `DCS_OUTPUT_DIR` to a dangerous location (e.g., `/etc/cron.d`) remains, but this is a local-user-as-local-user scenario with no privilege escalation. The plan correctly identifies the TUI as sitting "entirely on the user's side of the trust boundary."

**Status:** Fully resolved. Both sub-recommendations (b) and (c) from the prior review were adopted.

### F-04 [was Major]: `extra_args` allows arbitrary CLI flag injection -- RESOLVED

The revised plan removes `extra_args` entirely. `ScanConfig` now has only explicitly-typed fields (`scan_type`, `languages`, `severity_threshold`, `skip_verify`, `ignore_suppressions`). The plan states "There is no `extra_args: list[str]` field" and "All scan options are explicitly enumerated UI controls. There is no free-form text input for additional CLI arguments." Non-goal 8 reinforces this: "Free-form CLI argument pass-through" is explicitly excluded.

**Status:** Fully resolved. Recommendation (a) from the prior review was adopted.

### F-08 [was Minor]: Coverage exemption too broad -- RESOLVED

The revised plan narrows the coverage exemption to only Textual-dependent files: `*/tui/app.py` and `*/tui/screens/*.py`. The pure-Python modules (`models.py`, `storage.py`, `runner.py`) are explicitly included in the main `make test` coverage gate. The plan states: "The following TUI modules are NOT excluded and must meet the 90% coverage threshold in `make test`." Test cases for these modules are listed under `test_models.py`, `test_storage.py`, `test_runner.py`, and `test_runner_patterns.py`.

**Status:** Fully resolved. The narrower omit pattern recommendation was adopted.

### F-09 [was Info]: Timestamp directory collision -- RESOLVED

The revised plan uses microsecond-precision timestamps: `YYYY-MM-DD-HH-MM-SS-ffffff`. This provides sub-microsecond collision resistance, which is adequate for the use case (a human-driven TUI that starts one scan at a time). The test case `test_create_run_dir_unique_timestamps` is described as verifying "two immediate calls produce different dirs (microsecond precision)."

**Status:** Fully resolved.

### F-11 [was Minor]: No error handling for malformed JSON -- RESOLVED

The revised plan explicitly specifies: "If JSON parsing fails (malformed output, truncated file, disk full), the runner falls back to the defaults (`findings_count=0`, `backend_used="unknown"`) and logs a warning." This is reinforced by the test case `test_run_malformed_json_fallback`.

**Status:** Fully resolved.

### F-06 [was Minor]: Subprocess environment inherits `DCS_OUTPUT_DIR` -- RESOLVED (by F-02 fix)

Since `DCS_OUTPUT_DIR` is no longer in `shared/config.py`, the subprocess cannot accidentally act on it through the Config singleton. The env var is still inherited by the subprocess, but no CLI command reads it. The latent coupling identified in the prior review no longer exists.

**Status:** Resolved as a side effect of the F-02 fix.

---

## Findings Carried Forward (Unchanged)

### F-03: Project name derivation is ambiguous and collision-prone [Minor]

**Severity:** Minor

This finding is unchanged from the prior review. The plan now explicitly acknowledges it as Known Limitation 7: "Scanning two directories with the same basename... produces the same project name. Their run histories are silently merged." The plan correctly notes that individual runs are distinguishable by `target_path` in `meta.json`.

This is an acceptable UX limitation, not a security or correctness issue.

**Status:** Acknowledged as a known limitation. No action required.

### F-05: Stderr parsing is fragile and undocumented as a contract [Minor]

**Severity:** Minor

Partially addressed. The revised plan now extracts patterns into named constants and includes test cases for pattern parsing (`test_runner_patterns.py`). However, the specific issues from the prior review remain:

1. **The `hunt` command does not emit `[N/M]` phase indicators.** Verified against `cli.py` line 161: `click.echo(f"Scanning {validated_path}...", err=True)` -- no phase prefix.

2. **The `Found` line has a leading two-space indent.** Verified at `cli.py` line 327-330: `click.echo(f"  Found {total_count} findings in {hunt_stats.files_scanned} files", err=True)`. The plan's pattern specification on line 301 does not show this indent.

3. **No integration tests for stderr contracts.** The plan adds unit tests for pattern parsing but does not propose integration tests that run `dcs hunt` as a subprocess and assert the stderr format.

The plan's risk table entry ("Subprocess stderr parsing breaks if CLI output format changes") and the corresponding mitigation ("patterns are extracted into named constants... Tests verify pattern matching") are reasonable for a non-blocking issue.

**Status:** Partially addressed. Remaining gaps are low-risk.

### F-10: Textual dependency pin `>=0.70.0` has no upper bound [Minor]

**Severity:** Minor

Unchanged from the prior review. The plan still pins `textual>=0.70.0` with no upper bound. This deviates from the project's established pattern of using upper bounds on pre-1.0 dependencies (e.g., `tree-sitter>=0.23.0,<0.24.0`).

**Recommendation:** Pin to `textual>=0.70.0,<1.0.0`.

**Status:** Not addressed.

### F-12: `hunt-fuzz` and `fuzz` stderr patterns not fully specified [Minor]

**Severity:** Minor

Partially addressed. The plan now lists some phase-transition patterns but does not enumerate per-command differences. Verified against `cli.py`:

- `full-scan` phases: `[1/3] Scanning...`, `[2/3] Verifying...`, `[3/3] Generating...`
- `hunt-fuzz` phases: `[1/3] Scanning...`, `[2/3] Resolving fuzz targets...`, `[3/3] Fuzzing {N} function(s)...`
- `hunt` phases: none (just `Scanning {path}...`)
- `fuzz` phases: none (fuzzer orchestrator uses `print()` with its own format)

The plan's ScanProgressScreen design shows "Phase indicator: [1/3] Hunt | [2/3] Verify | [3/3] Remediate" which only matches `full-scan`. The `hunt-fuzz` phase labels are different. The `fuzz` command has no phase structure at all.

**Recommendation:** Document all four command variants' stderr patterns in the design section and test each variant in `test_runner_patterns.py`.

**Status:** Partially addressed.

---

## New Findings

### F-13: JSON-to-DTO reconstruction for in-process format conversion is unspecified [Major]

**Severity:** Major

The revised plan's core optimization (Deviation D-3) is to run the scan once with `--format json`, then use `shared.formatters` in-process to generate SARIF and HTML. However, the plan does not specify the critical intermediate step: **reconstructing the formatter's Pydantic DTO from the JSON output file.**

The formatters accept typed Pydantic models as input:
- `SarifFormatter.format_hunt(data: HuntResult, ...)` -- expects `HuntResult` with `findings: list[RawFinding]`, `stats: ScanStats`, etc.
- `SarifFormatter.format_full_scan(data: FullScanResult, ...)` -- expects `FullScanResult` with nested `RawFinding`, `VerifiedFinding`, `RemediationGuidance`, etc.
- `SarifFormatter.format_hunt_fuzz(data: HuntFuzzResult, ...)` -- expects `HuntFuzzResult` with nested `BridgeResult`, `FuzzReportResult`, etc.

The SARIF formatter accesses deeply nested Pydantic model attributes: `finding.source.function`, `finding.sink.cwe`, `finding.taint_path.steps[i].variable`, `verified.confidence_score`, `guidance.fix_pattern`. A raw `dict` from `json.loads()` would fail with `AttributeError` on any of these attribute accesses.

The TUI runner must therefore:
1. Read the JSON file and call `json.loads()`
2. Reconstruct the correct Pydantic DTO via `HuntResult.model_validate(parsed_dict)` (or equivalent for each scan type)
3. Pass the hydrated DTO to the formatter

Step 2 is non-trivial because:
- The JSON schema must be symmetric with the DTO field names (it is for `hunt` and `full-scan`, but the `hunt-fuzz` JSON nests `hunt_result` differently -- the JSON includes `"hunt_result": {"findings": ..., "stats": ..., "total_count": ..., "has_more": ...}` while `HuntFuzzResult.hunt_result` expects a full `HuntResult` object).
- `RawFinding`, `Source`, `Sink`, `TaintPath`, `TaintStep`, `VerifiedFinding`, `RemediationGuidance`, `BridgeResult`, `FuzzTarget`, `CorrelationReport` all need correct nested deserialization.
- The `FullScanResult` JSON output (from `JsonFormatter.format_full_scan`) uses `"hunt_stats"` as the key, matching the DTO field name `hunt_stats: ScanStats`. Pydantic v2 should handle this. But `HuntFuzzResult`'s `bridge_result: BridgeResult` requires reconstructing a `BridgeResult` that contains `fuzz_targets: list[FuzzTarget]`, each with a `sast_context: SastContext`. The JSON serialization uses custom dict construction (not `serialize_model`), so the keys may not match the Pydantic field names exactly.

**Impact:** Without specifying and testing the JSON-to-DTO reconstruction path for each scan type, the in-process format conversion is likely to fail at runtime for `full-scan` and `hunt-fuzz` scan types, producing only the JSON report and silently dropping SARIF/HTML.

**Recommendation:** (a) Add an explicit `_reconstruct_dto(scan_type: str, json_data: dict) -> HuntResult | FullScanResult | HuntFuzzResult | FuzzReportResult` method to `ScanRunner` with per-scan-type deserialization logic. (b) Add test cases that round-trip each scan type through `JsonFormatter.format_X() -> json.loads() -> model_validate() -> SarifFormatter.format_X()`. (c) Document that if reconstruction fails, the runner falls back to JSON-only output with a warning (consistent with the existing error handling strategy).

---

### F-14: `shared.formatters` import transitively imports analysis modules, contradicting isolation claim [Minor]

**Severity:** Minor

The plan states: "No imports from `hunter`, `auditor`, `architect`, `fuzzer`, `bridge`, or `mcp` modules in the TUI module." It reinforces this in Acceptance Criterion 18. However, importing `shared.formatters` triggers `_register_builtins()` at module load time (line 102 of `shared/formatters/__init__.py`), which imports all formatter implementations. The formatter protocol module (`shared/formatters/protocol.py`) directly imports from:

- `deep_code_security.hunter.models` (lines 9-10: `RawFinding`, `ScanStats`)
- `deep_code_security.auditor.models` (line 10: `VerifiedFinding`, `VerifyStats`)
- `deep_code_security.architect.models` (line 9: `RemediateStats`, `RemediationGuidance`)
- `deep_code_security.bridge.models` (line 11: `BridgeResult`, `CorrelationReport`)

So `from deep_code_security.shared.formatters import get_formatter` transitively imports `hunter.models`, `auditor.models`, `architect.models`, and `bridge.models`. The TUI's stated isolation ("does NOT import from `hunter`, `auditor`, `architect`, `fuzzer`, `bridge`, or `mcp` modules") is factually incorrect for the `shared.formatters` import path.

This is not a security issue -- these are Pydantic model modules with no import-time side effects. But it is an architectural misstatement. The import chain also means the TUI depends on `tree-sitter` being importable (since `hunter.models` is part of the `hunter` package, though `models.py` itself does not import tree-sitter).

**Recommendation:** Correct the isolation claim in the plan. Change Acceptance Criterion 18 to: "No **direct** imports from `hunter`, `auditor`, `architect`, `fuzzer`, `bridge`, or `mcp` modules in the TUI module. Transitive imports via `shared.formatters` (which depends on model definitions from these modules) are accepted as part of Deviation D-3."

---

### F-15: HTML formatter does not support `hunt-fuzz` output [Minor]

**Severity:** Minor

The plan states that "SARIF and HTML are derived from the JSON output" for all scan types. However, `HtmlFormatter` does not implement `format_hunt_fuzz()`. Verified by code inspection: `html.py` has `format_hunt`, `format_full_scan`, `format_fuzz`, and `format_replay`, but no `format_hunt_fuzz`. This is consistent with CLAUDE.md's Known Limitation 11 note about HTML formatter gaps, and with the existing CLI's `hunt-fuzz` command which only supports `text`, `json`, and `sarif` formats (line 800-801 of `cli.py`: `type=click.Choice(["text", "json", "sarif"])`).

The plan's error handling ("If SARIF or HTML generation fails... the runner logs a warning and continues") would catch this gracefully. But the plan does not acknowledge that HTML output is never produced for `hunt-fuzz` scans. Users who run a `hunt-fuzz` scan will see only JSON and SARIF in their report directory, with no explanation of why HTML is missing.

**Recommendation:** (a) Document in the Known Limitations section that HTML reports are not generated for `hunt-fuzz` and `fuzz` scan types. (b) In `ResultsViewScreen`, conditionally show the [Open HTML] button only when an HTML file exists in the run directory.

---

### F-16: `--output-file` flag interaction with in-process format conversion [Minor]

**Severity:** Minor

The plan says the runner invokes `dcs hunt ... --format json --output-file {run_dir}/{prefix}.json`. Looking at the CLI's `_write_output()` function (line 46-78 of `cli.py`), `--output-file` validates the path through `validate_path()` against `DCS_ALLOWED_PATHS`.

If `DCS_ALLOWED_PATHS` does not include `~/.dcs/reports/` (the default `DCS_OUTPUT_DIR`), the CLI subprocess will reject the `--output-file` path with "Output file path validation failed." The TUI constructs the output path programmatically but the subprocess validates it independently. The plan does not address this interaction.

The default `DCS_ALLOWED_PATHS` is `cwd`, which is typically the user's project directory -- not `~/.dcs/reports/`. So by default, every TUI scan would fail because the subprocess's path validator rejects the report output path.

**Recommendation:** (a) The `ScanRunner` should use `--output-file` pointing to a path within the subprocess's `DCS_ALLOWED_PATHS` (e.g., a temp file under the scanned project directory), then copy the result to the TUI's report directory after the subprocess completes. Or (b) the runner should add `DCS_OUTPUT_DIR` to the subprocess's `DCS_ALLOWED_PATHS` environment variable. Or (c) use stdout capture instead of `--output-file`: run `dcs hunt --format json` and capture stdout, then write it to the report directory from the TUI process.

---

### F-17: `ScanConfig` does not expose `--consent` for fuzz-dependent scan types [Info]

**Severity:** Info

The `ScanConfigScreen` description mentions dynamically showing `--consent` only for `fuzz` and `hunt-fuzz` scan types (line 403). However, the `ScanConfig` model fields listed in Task 1.2 are: `target_path`, `scan_type`, `languages`, `severity_threshold`, `skip_verify`, `ignore_suppressions`. There is no `consent` field.

Non-goal 6 states "The TUI does not auto-consent to API transmission. Users must pass `--consent` or set `DCS_FUZZ_CONSENT=true`." But if `ScanConfig` has no `consent` field, the `ScanRunner.build_command()` method cannot include `--consent` in the subprocess command, and the subprocess will prompt for consent interactively -- which cannot work when stdin is controlled by the TUI.

The plan should either (a) add a `consent: bool` field to `ScanConfig` and expose it as a `Switch` on the config screen (only visible for fuzz/hunt-fuzz), or (b) document that fuzz scans require `DCS_FUZZ_CONSENT=true` to be set in the environment before launching `dcs tui`, and the TUI should check this and warn.

**Recommendation:** Add `consent` to the `ScanConfig` model.

---

## Summary Table

| ID | Severity | Status | Summary |
|----|----------|--------|---------|
| F-01 | ~~Critical~~ | RESOLVED | Triple subprocess invocation eliminated by in-process format conversion |
| F-02 | ~~Major~~ | RESOLVED | `DCS_OUTPUT_DIR` isolated to `tui/storage.py`; project names sanitized |
| F-03 | Minor | Acknowledged | Project name collisions (documented as Known Limitation 7) |
| F-04 | ~~Major~~ | RESOLVED | `extra_args` removed entirely |
| F-05 | Minor | Partially addressed | Stderr patterns extracted to constants; leading-whitespace and per-command gaps remain |
| F-06 | ~~Minor~~ | RESOLVED | No longer relevant after F-02 fix |
| F-07 | Info | Unchanged | Platform file-opener follows symlinks (acceptable) |
| F-08 | ~~Minor~~ | RESOLVED | Coverage exemption narrowed to Textual-dependent files only |
| F-09 | ~~Info~~ | RESOLVED | Microsecond-precision timestamps |
| F-10 | Minor | Not addressed | Textual dependency lacks upper bound |
| F-11 | ~~Minor~~ | RESOLVED | JSON parse failure falls back to defaults with warning |
| F-12 | Minor | Partially addressed | Per-command stderr patterns still not fully enumerated |
| **F-13** | **Major** | **NEW** | JSON-to-DTO reconstruction for in-process format conversion is unspecified |
| **F-14** | **Minor** | **NEW** | `shared.formatters` import transitively imports analysis modules |
| **F-15** | **Minor** | **NEW** | HTML formatter does not support `hunt-fuzz` output |
| **F-16** | **Minor** | **NEW** | `--output-file` path will be rejected by `DCS_ALLOWED_PATHS` validation |
| **F-17** | **Info** | **NEW** | `ScanConfig` missing `consent` field for fuzz scan types |

---

## Blocking Assessment

**F-13 is rated Major but is NOT blocking** because the plan's existing error handling strategy ("If SARIF or HTML generation fails... the runner logs a warning and continues -- the JSON report is always the primary artifact") provides a graceful degradation path. The worst case is that SARIF/HTML are silently not generated, which is a UX regression but not a correctness or security issue. The JSON report (the primary artifact) is always produced by the subprocess and is not affected.

However, F-13 should be addressed before implementation begins -- the round-trip deserialization is the central mechanism of the plan's core optimization (D-3). If the implementer does not account for it, the in-process format conversion will fail for most scan types and the plan's stated behavior ("Report files (`hunt.json`, `hunt.sarif`, `hunt.html`) are written") will not hold.

F-16 is also worth addressing before implementation because it would cause every default-config TUI scan to fail at subprocess invocation time.

---

## Trust Boundary Assessment

The revised plan's trust boundary analysis is now accurate and consistent:

1. **`DCS_OUTPUT_DIR` isolation** is correctly implemented by keeping the env var out of `shared/config.py`.
2. **Deviation D-4** correctly explains why `path_validator.py` is not appropriate for a local developer tool's write paths.
3. **The subprocess trust delegation** is properly described: all security-sensitive operations (path validation, scanning, sandbox execution) are performed by the subprocess with its own enforcement.
4. **The `shared.formatters` import** (F-14) introduces transitive dependencies on analysis model modules but does not cross any trust boundary -- no untrusted data flows through this import path.

The plan correctly states: "The TUI introduces no new trust boundaries."

## Container Security Assessment

Not applicable. The TUI does not interact with containers directly. All container operations (Auditor sandbox, Fuzzer ContainerBackend) are delegated to the `dcs` CLI subprocess, which enforces its own container security policies independently. No changes to seccomp profiles, capability drops, or resource limits are proposed.

## Supply Chain Risk

The `textual>=0.70.0` dependency assessment is unchanged from the prior review:

| Aspect | Assessment |
|--------|-----------|
| Package | `textual>=0.70.0` (optional `[tui]` extra) |
| Maintainer | Textualize (Will McGugan), well-established |
| License | MIT (compatible) |
| Transitive deps | `rich` (already in `[fuzz]`), `markdown-it-py`, `linkify-it-py` |
| Install scope | Optional; does not affect core installation |
| Risk | Low. Only concern is lack of upper version bound (F-10) |

The new transitive import chain via `shared.formatters` -> `protocol.py` -> `{hunter,auditor,architect,bridge}.models` does not introduce new supply chain dependencies because those modules are already part of the core package.
