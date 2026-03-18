# Review: suppressions-file.md (Second Pass)

**Plan:** `./plans/suppressions-file.md`
**Reviewed:** 2026-03-17 (second pass after revision)
**Prior review:** 2026-03-17 (first pass, verdict: PASS)
**Verdict:** PASS

---

## Conflicts with CLAUDE.md

No conflicts found. All Critical Rules (Security and Code Quality) are satisfied.

| CLAUDE.md Rule | Status | Notes |
|---|---|---|
| Never `yaml.load()` -- always `yaml.safe_load()` | Compliant | `load_suppressions()` uses `yaml.safe_load()` exclusively (line 477). Inline comment `# SECURITY: Always use yaml.safe_load() -- never yaml.load()` at line 475 reinforces the mandate. Dedicated test case `test_load_suppressions_uses_safe_load` (line 913). |
| Never `eval()`, `exec()`, `shell=True` | Compliant | No unsafe execution patterns. `_glob_match()` uses `fnmatch.fnmatch()` on individual path segments only. `matches()` uses string comparison and integer comparison. No code execution anywhere in the module. |
| All file paths validated through `mcp/path_validator.py` | Compliant | Suppression file path is `<validated_target_path>/.dcs-suppress.yaml`. The target path has already been validated through `PathValidator`. The filename is hardcoded (`_SUPPRESS_FILENAME = ".dcs-suppress.yaml"`) -- no user-controlled path component is introduced (Assumption 4, lines 27-28; Security Considerations, lines 776-778). |
| Pydantic v2 for all data-crossing models | Compliant | `SuppressionRule`, `SuppressionConfig`, `SuppressionResult` (in `shared/suppressions.py`) and `SuppressionSummary` (in `shared/formatters/protocol.py`) are all `BaseModel` subclasses with `Field()` declarations and proper validators. |
| Type hints on all public functions | Compliant | `load_suppressions(project_root: Path) -> SuppressionConfig | None` and `apply_suppressions(findings: list[RawFinding], config: SuppressionConfig, project_root: Path, today: datetime.date | None = None) -> SuppressionResult` are fully typed. `_glob_match()` (private) is also typed. All model methods (`is_expired`, `matches`) have type annotations. |
| `__all__` in `__init__.py` | Compliant | `suppressions.py` defines `__all__` with 5 exports (lines 208-215). Task 6.1 updates `shared/__init__.py`. Task 3.1 updates `shared/formatters/protocol.py` `__all__` to include `SuppressionSummary`. |
| pathlib.Path over os.path | Compliant | All file operations use `pathlib.Path`. `PurePosixPath` used for cross-platform forward-slash normalization in glob matching (line 369). No `os.path` usage. |
| No mutable default arguments | Compliant | All list/dict fields use `Field(default_factory=...)`. `SuppressionRule` has `model_config = {"frozen": True}` (line 293). `ScanStats` new fields use `Field(default=0, ge=0)` for ints and `Field(default_factory=list)` for the `suppressed_finding_ids` list (lines 646-649). |
| 90%+ test coverage | Compliant | 45+ dedicated test cases in `test_suppressions.py` (model validation, loading, glob matching, suppression application), 6 orchestrator integration tests, 2 CLI error-handling tests, and 6 formatter test updates. Acceptance criterion 13 explicitly requires `make test` with 90%+ coverage. |

---

## Historical Alignment Issues

### H-1: Consistent with output-formats formatter architecture (PASS)

The plan extends the formatter DTOs (`HuntResult`, `FullScanResult`) with optional `suppression_summary: SuppressionSummary | None = None` and `suppressed_finding_ids: list[str] = Field(default_factory=list)` fields, both defaulting to `None`/`[]`, which preserves backward compatibility. Each formatter (Text, JSON, SARIF, HTML) is updated individually, following the same pattern established in `plans/output-formats.md`. The `SuppressionSummary` DTO is placed in `shared/formatters/protocol.py`, consistent with the existing `HuntResult`, `FullScanResult`, and `FuzzReportResult` DTO location.

### H-2: Consistent with sast-to-fuzz-pipeline bridge integration (PASS)

The plan correctly identifies `hunt-fuzz` as a command that must respect suppressions (Assumption 5, line 28; Acceptance Criteria 5, line 986). Suppressed findings are filtered before they reach the Bridge module, which is correct -- the Bridge should only resolve fuzz targets for non-suppressed findings. The `HuntFuzzResult` DTO wraps `HuntResult` (via `hunt_result: HuntResult` at `protocol.py` line 147), so the `suppression_summary` field propagates naturally. The plan explicitly states this at line 731: "No separate top-level field is needed on `HuntFuzzResult`."

### H-3: Consistent with deep-code-security.md three-phase pipeline (PASS)

The plan applies suppressions after the Hunter phase and before downstream phases (Auditor, Architect, Bridge), preserving the linear pipeline. The "Suppression Semantics" section (lines 158-168) explicitly documents that suppressed findings are excluded from Auditor verification, Architect guidance, and Bridge fuzz target resolution. This was a new section added in the revision to address redteam finding F-4.

### H-4: Consistent with intraprocedural taint limitation (PASS)

The suppression matching operates on `RawFinding` fields (`sink.cwe`, `sink.file`, `sink.line`) which are populated by the intraprocedural taint tracker. No cross-function or cross-file assumptions are introduced. The plan acknowledges this scope in redteam response F-8 (source-side matching deferred as a known limitation).

### H-5: Architect output remains guidance-only (PASS)

The plan does not modify Architect behavior. Suppressed findings are simply excluded from the Architect's input set.

### H-6: Context Alignment section exists and is substantive (PASS)

The `## Context Alignment` section (lines 1128-1153) is present, substantive, and updated to reflect the revision. It maps every applicable CLAUDE.md rule to the plan's implementation, references three prior plans (`output-formats.md`, `sast-to-fuzz-pipeline.md`, `deep-code-security.md`), and documents two deviations:
1. ScanStats embedding instead of tuple expansion (the F-1 fix).
2. SARIF suppressed findings accessed via `orchestrator.last_suppression_result` rather than carried through DTOs.

### H-7: Context metadata block (PASS)

The metadata block (lines 1168-1173) is present with `claude_md_exists: true` and lists five consulted plans across `recent_plans_consulted` and `archived_plans_consulted`. No issues.

### H-8: Consistent with merge-fuzzy-wuzzy and fuzzer-container-backend (PASS)

No conflicts. The plan does not modify fuzzer execution, corpus management, or container backend behavior. Non-Goal 2 explicitly states: "Suppression of fuzzer findings... is a different problem."

### H-9: Consistent with existing ScanStats model (PASS)

Verified against codebase: `ScanStats` in `src/deep_code_security/hunter/models.py` (line 114) currently has fields `files_scanned`, `files_skipped`, `languages_detected`, `sources_found`, `sinks_found`, `taint_paths_found`, `scan_duration_ms`, `registry_version_hash`. The plan adds four new fields (`findings_suppressed`, `suppression_rules_loaded`, `suppression_rules_expired`, `suppressed_finding_ids`) all with safe defaults (`0` and `[]`). Existing serialization and deserialization will not break because Pydantic v2 handles optional fields with defaults gracefully.

---

## F-1 Fix Assessment: ScanStats Embedding Instead of 5-Tuple

The original plan proposed expanding `HunterOrchestrator.scan()` from a 4-tuple to a 5-tuple return. This was identified as Critical (redteam F-1) and Major (feasibility M-2) because:
- All six call sites (3 in `cli.py` at lines 155, 263, 758; 3 in `mcp/server.py` at lines 451, 641, 1073) would need unpacking changes.
- Python offers no compile-time protection against tuple-length mismatches.
- A missed call site would cause `ValueError: too many values to unpack` at runtime.

**The revised approach is architecturally sound.** The plan embeds suppression metadata directly into `ScanStats`, which is already the 2nd element of the 4-tuple. This means:

1. **Return type is unchanged**: `tuple[list[RawFinding], ScanStats, int, bool]` -- all existing unpacking patterns (`findings, stats, total_count, has_more = hunter.scan(...)`) continue to work without modification.
2. **Suppression metadata is available via `stats`**: Callers that need suppression counts read `stats.findings_suppressed`, `stats.suppression_rules_loaded`, etc.
3. **Detailed suppression data via property**: The `orchestrator.last_suppression_result` property (lines 633-636) provides the full `SuppressionResult` (including suppressed finding objects and per-finding reasons) for callers that need it (SARIF formatter, CLI suppression summary). This avoids bloating the return tuple or the `ScanStats` model with full finding objects.
4. **No existing test breakage**: Tests that assert `len(result) == 4` continue to pass. No unpacking changes needed in MCP server tests, bridge tests, or fuzzer tests.

This is a clean separation of concerns: lightweight metadata travels in the return value; detailed data is available on-demand via the orchestrator instance.

---

## `_glob_match()` Implementation Assessment

The `_glob_match()` function (lines 231-265) replaces the problematic `fnmatch.fnmatch()` on full path strings (redteam F-2, feasibility M-1). The implementation:

1. **Splits both pattern and path on `/`** into segments, then matches segment-by-segment using `fnmatch.fnmatch()` on individual segments. This ensures `*` cannot cross directory boundaries (because `fnmatch` is only called on a single segment like `loader.py`, never on a path like `config/sub/loader.py`).

2. **Handles `**` via a stack-based backtracking approach**: When `**` is encountered, a backtrack point is pushed. The algorithm advances `pi` past `**` and continues matching. If matching fails, it backtracks and tries consuming one more path segment with `**`. This correctly implements zero-or-more directory matching.

3. **Does not violate any security rules**: No `eval()`, no filesystem access (pure string operations), no `os.path` usage. Uses only `fnmatch.fnmatch()` (stdlib) on individual segments and list/integer operations.

4. **Edge cases covered by test plan**: 6 dedicated glob matching tests (lines 940-946) plus 8 file-matching tests in the suppression matching section (lines 922-927) cover: single `*` not crossing directories, `**` matching zero/one/many directories, exact path matching, and middle-of-pattern `**`.

5. **Path normalization is correct**: The `matches()` method converts `sink.file` to a relative path via `Path.relative_to(project_root)`, normalizes to forward slashes via `PurePosixPath`, then splits on `/`. This handles both Windows and Unix paths consistently.

No security or correctness issues found with the `_glob_match()` implementation.

---

## Prior Finding Resolution Verification

| Finding ID | Source | Severity | Status in Revised Plan |
|---|---|---|---|
| F-1 | Redteam | Critical | RESOLVED. Return type stays 4-tuple; suppression metadata in ScanStats; detail via `last_suppression_result` property. Acceptance criterion 19 explicitly states "return type remains a 4-tuple." |
| F-2 / M-1 | Redteam / Feasibility | Major | RESOLVED. `_glob_match()` with segment-aware matching replaces raw `fnmatch`. 14 test cases cover glob behavior. |
| F-3 / M-3 | Redteam / Feasibility | Major | RESOLVED. `suppressed_finding_ids: list[str]` added to `HuntResult` and `FullScanResult`. SARIF formatter gets full objects via `orchestrator.last_suppression_result`. Updated "Modified Public API" table (lines 798-808). |
| F-4 | Redteam | Major | RESOLVED. "Suppression Semantics" section (lines 158-168) explicitly documents exclusion from Auditor/Architect/Bridge and the `--ignore-suppressions` bypass. |
| F-5 / M-4 | Redteam / Feasibility | Major | RESOLVED. MCP response now reads from `ScanStats` integer fields (`stats.findings_suppressed`), eliminating the list-vs-int type mismatch (lines 686-694). |
| F-6 / m-2 | Redteam / Feasibility | Major / Minor | RESOLVED. 64 KB file size limit and 500 rule count limit added (lines 170-177, 221-222). `SuppressionLoadError` exception class. Test cases at lines 915-916. |
| F-7 | Redteam | Minor | RESOLVED. `is_expired()` uses `datetime.datetime.now(datetime.timezone.utc).date()` (line 343-345) instead of `datetime.date.today()`. |
| M-2 | Feasibility | Major | RESOLVED. Return type unchanged (see F-1 resolution). No existing test unpacking needs to change. Task 2.3 explicitly states "Existing tests do NOT need unpacking changes" (line 1035). |
| M-4 / F-13 | Feasibility / Redteam | Major / Info | RESOLVED. Plan clarifies session store only contains active findings (line 626), `total_count` is automatically correct (line 623), `taint_paths_found` reflects pre-suppression counts (line 654). MCP note about `deep_scan_verify` and `deep_scan_remediate` at lines 696-697. |
| m-1 | Feasibility | Minor | NOT ADDRESSED. Symlink resolution on `.dcs-suppress.yaml` not added. Low risk since suppression file has same trust level as scanned source. See Optional Suggestions. |
| m-4 | Feasibility | Minor | RESOLVED. MCP response reads from `ScanStats` (see F-5 resolution). |
| m-5 | Feasibility | Minor | NOT ADDRESSED. `expires` validator still accepts ISO week dates via `date.fromisoformat()`. Very low risk -- unlikely to cause real issues. |
| m-6 | Feasibility | Minor | RESOLVED. Task 6.2 (line 1095-1096) updates `CLAUDE.md`. |
| m-7 | Feasibility | Minor | RESOLVED. `hunt-fuzz` is explicitly listed in CLI options (line 816), MCP schema changes (line 824), and Acceptance Criteria 5 (line 986). `HuntFuzzResult` propagation is addressed at line 731. |
| F-8 | Redteam | Minor | ACKNOWLEDGED. Source-side suppression matching is a v2 feature, correctly out of scope for this plan. |
| F-9 | Redteam | Minor | RESOLVED. `HuntFuzzResult` propagation explicitly documented at line 731 and line 808. |
| F-11 | Redteam | Minor | RESOLVED. CLI error-handling test cases added: `test_cli_hunt_malformed_suppression_file` and `test_cli_full_scan_malformed_suppression_file` (lines 968-969). |

---

## Required Edits

None. All Critical and Major findings from the first review cycle have been addressed. The plan is well-aligned with CLAUDE.md rules, prior approved plan decisions, and established codebase patterns. No conflicts require correction before approval.

---

## Optional Suggestions

- **S-1: Symlink resolution on suppression file path.** The feasibility review raised m-1 (symlink-based suppression file injection). The revised plan does not address this. Risk is low because the suppression file contents only control which findings are hidden (no code execution), and the target directory contents are under the same trust boundary as scanned code. However, adding `suppress_path = suppress_path.resolve()` with a check that the resolved path is still under `project_root` would be a defense-in-depth measure consistent with the plan's security posture. Not blocking.

- **S-2: ISO date format strictness.** The `expires` field validator uses `datetime.date.fromisoformat()`, which on Python 3.11+ accepts ISO week dates (e.g., `2026-W01-1`) and ordinal dates (`2026-032`). The plan documents `YYYY-MM-DD` as the expected format. A post-parse re-format check (`if v != parsed.isoformat(): raise ValueError(...)`) would enforce this strictly. Very low risk -- unlikely to cause real issues.

- **S-3: `# TODO(scan-result-refactor)` comment.** The plan acknowledges that the 4-tuple return from `scan()` should eventually be replaced with a proper `ScanResult` dataclass (line 1152). Consider adding a `# TODO(scan-result-refactor)` comment in the orchestrator code when implementing, so the tech debt is discoverable via grep.

- **S-4: `HuntFuzzResult` in "Modified Public API" table.** The plan correctly states that `HuntFuzzResult` inherits suppression data transitively via `hunt_result: HuntResult` and does not need a separate field (line 808). However, the "Modified Public API" table does not list `HuntFuzzResult` at all. Adding a row with "No changes needed -- inherits via `hunt_result: HuntResult`" would make the table exhaustive and reduce implementer confusion.

---

**Reviewer:** Librarian (automated, second pass)
**Plan status:** DRAFT -- no changes required for approval.
