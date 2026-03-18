# Red Team Review: Suppressions File (.dcs-suppress.yaml) -- Revision 2

**Reviewed:** `plans/suppressions-file.md` (revised)
**Reviewer:** Security Analyst
**Date:** 2026-03-17

## Verdict: PASS

No Critical findings. The previous Critical finding (F-1: fragile 5-tuple return break) has been resolved. All previous Major findings have been adequately addressed, though some residual concerns remain at Minor severity. Several new Minor and Info findings are noted.

---

## Resolution Assessment of Prior Findings

### F-1 [was Critical] -- Fragile 5-tuple return break: RESOLVED

The revised plan embeds suppression metadata into `ScanStats` (which is already the 2nd element of the 4-tuple return). The `scan()` return type stays as `tuple[list[RawFinding], ScanStats, int, bool]`. No existing call site needs unpacking changes. Detailed suppression data (suppressed finding objects, per-finding reasons) is available via `orchestrator.last_suppression_result`, a new property. This is a clean resolution: the 6 call sites in `cli.py` (lines 155, 263, 758), the 3 in `mcp/server.py` (lines 451, 641, 1073), and the 12+ in tests all continue to work unmodified.

The test `assert len(result) == 4` at `tests/test_hunter/test_orchestrator.py:48` no longer needs updating since the return signature is unchanged. The plan adds `test_scan_return_tuple_unchanged` (line 963) to explicitly guard this invariant going forward.

### F-2 [was Major] -- `fnmatch` does not support `**` recursive glob: RESOLVED

The plan now specifies a segment-aware `_glob_match()` helper (lines 104-139) that splits paths on `/` and matches individual segments with `fnmatch.fnmatch()`. The `**` token is handled by a stack-based backtracking algorithm that matches zero or more complete path segments. Single `*` operates within one segment only (since `fnmatch` is applied per-segment, path separators are never present in the input to `fnmatch`).

Test cases cover: `*` not crossing directories (line 923), `**` matching zero dirs (line 924), one dir (line 925), and deep nesting (line 926). The algorithm is correct for all tested cases.

### F-3 [was Major] -- SARIF DTO gap for suppressed findings: RESOLVED

The plan adds `suppressed_finding_ids: list[str]` to `HuntResult` and `FullScanResult` (lines 719, 728). For SARIF output, full `RawFinding` objects are retrieved via `orchestrator.last_suppression_result.suppressed_findings` (lines 733, 1059). The "Modified Public API" table (lines 800-808) now includes both DTOs. The `HuntFuzzResult` inherits via `hunt_result: HuntResult` (line 731, 808).

### F-4 [was Major] -- Silent coverage removal from Auditor/Bridge: RESOLVED (accepted risk, documented)

The plan now includes a dedicated "Suppression Semantics" section (lines 158-168) that explicitly documents that suppressions exclude findings from Auditor, Architect, and Bridge. It provides a rationale ("spending sandbox execution time, API credits, or fuzz iterations on findings the user has explicitly marked as non-actionable is wasteful") and points to `--ignore-suppressions` for periodic verification runs (line 168). Acceptance criteria 4-5 (lines 985-986) explicitly note "This is intentional."

This is an accepted design trade-off, not an oversight. The documentation is sufficient.

### F-5 [was Major] -- MCP pseudocode uses list where `len()` needed: RESOLVED

The MCP response now reads integer fields directly from `ScanStats` (lines 688-695): `stats.findings_suppressed` (already an `int`), `stats.suppression_rules_loaded`, `stats.suppression_rules_expired`, and `stats.suppressed_finding_ids`. The type mismatch from the original plan is eliminated.

### F-6 [was Major] -- No size limit on suppression file: RESOLVED

The plan adds `_MAX_SUPPRESSION_FILE_SIZE = 65536` (64 KB) and `_MAX_SUPPRESSION_RULES = 500` (lines 221-222). File size is checked before reading (lines 460-465), rule count is checked after parsing (lines 493-500). Both raise `SuppressionLoadError`, a `ValueError` subclass (lines 225-228). Test cases cover both limits (lines 915-916).

---

## New Findings

### F-15. [Major] `_glob_match` stack growth is unbounded for adversarial patterns

**Location:** Plan lines 231-265 (the `_glob_match` function)

The stack-based backtracking algorithm can accumulate duplicate entries. For a pattern with multiple `**` segments (e.g., `**/**/**/**/*.py`) applied against a deep path, the stack can grow combinatorially. While the 500-rule limit and typical path depths (< 30 segments) make this unlikely to cause a real problem, the algorithm has O(2^n) worst-case time complexity for n consecutive `**` segments.

An attacker could craft a suppression file with patterns like `**/**/**/**/**/**/**/**/**/**` (ten consecutive `**` segments) and a codebase with deep directory nesting. With 500 rules of this form, matching could become very slow.

**Practical impact:** Low. Real suppression files will not contain patterns with 10 consecutive `**` segments, and the 64 KB file size limit constrains total content. The 500-rule limit with realistic patterns is fine.

**Recommendation:** Consider collapsing consecutive `**` segments into a single `**` during pattern preprocessing (e.g., `**/**/*.py` becomes `**/*.py`). This is a one-line optimization: `pattern_segments = [s for i, s in enumerate(pattern_segments) if s != "**" or i == 0 or pattern_segments[i-1] != "**"]`. Alternatively, add a maximum pattern depth limit (e.g., reject patterns with more than 20 segments). This is low priority and can be addressed post-merge.

---

### F-16. [Minor] `last_suppression_result` property creates coupling between orchestrator and formatter

**Location:** Plan lines 626-637 (orchestrator property), lines 733-734 (SARIF formatter access pattern)

The SARIF formatter needs full `RawFinding` objects for suppressed findings, which it retrieves via `orchestrator.last_suppression_result.suppressed_findings`. This means the formatter needs access to the orchestrator instance -- an architectural coupling that breaks the current pattern where formatters receive only DTOs.

The plan mentions passing suppressed findings "via a `context` dict or by temporarily populating a `_suppressed_findings` field on the DTO before formatting" (line 733) but does not commit to a specific mechanism. This ambiguity could lead to inconsistent implementations across CLI and MCP code paths.

**Impact:** The CLI can easily access the orchestrator. The MCP server can also access `self.hunter.last_suppression_result`. However, the SARIF formatter itself should not have knowledge of the orchestrator. The plan's vague "context dict" approach leaves the implementer to design this ad-hoc.

**Recommendation:** Commit to a specific mechanism. The cleanest option: add an optional `_suppressed_findings: list[RawFinding] = Field(default_factory=list)` field to `HuntResult` that the CLI/MCP populates before calling the formatter. This keeps the DTO self-contained while keeping it private (underscore prefix) to indicate it is an implementation detail for SARIF only. The JSON/text formatters simply ignore it.

---

### F-17. [Minor] Symlink-based suppression file injection still not addressed

**Location:** Plan Assumption 4 (line 27), Security Considerations (lines 776-782)

The previous finding F-10 noted that `<target>/.dcs-suppress.yaml` could be a symlink pointing outside the validated path tree. The plan's security section (line 778) says "no user-controlled path component is introduced" but does not address symlinks within the target directory.

The plan's `load_suppressions()` function uses `suppress_path.is_file()` (line 448) and `suppress_path.read_text()` (line 468), both of which follow symlinks. If an attacker places `.dcs-suppress.yaml` as a symlink to `/etc/passwd`, the loader would:
1. `is_file()` returns True (following the symlink)
2. `read_text()` reads the file contents
3. `yaml.safe_load()` would fail to parse `/etc/passwd` as YAML
4. The function raises `ValueError`

So the practical impact is a DoS (scanning fails with a confusing error) rather than a data exfiltration. The PathValidator resolves symlinks on the target path, but not on files within it.

However, as noted previously: the suppression file is within the same trust boundary as the scanned source code. If an attacker controls the repository contents, they also control all the source files being scanned.

**Recommendation:** Document this as an accepted risk in the Security Considerations section, or add `suppress_path = suppress_path.resolve()` and verify it is still under `project_root.resolve()`. This is consistent with how PathValidator works.

---

### F-18. [Minor] Expiration date validation does not reject past dates

**Location:** Plan lines 318-328 (expires validator), lines 339-346 (is_expired method)

The `validate_expires` field validator only checks that the string is a valid ISO date. It does not reject dates in the past. A user could add a suppression with `expires: "2020-01-01"`, which would immediately be expired and never applied. The `apply_suppressions()` function would count it as an expired rule and log a warning, but the suppression entry is still accepted into the config.

This is arguably correct behavior (the warning is informative), but it means a typo like `expires: "2025-09-01"` (meant 2026) would silently expire a suppression. The user would see "1 suppression rule(s) have expired" in the logs but might not connect it to their typo.

**Recommendation:** Consider a more specific warning message in `apply_suppressions()` that includes the rule details (e.g., "Suppression for CWE-78 in src/config/*.py expired on 2025-09-01"). This would help the user identify which rule expired and whether it was intentional. The current plan logs "N suppression rule(s) have expired" (line 538) which is not specific enough.

---

### F-19. [Minor] Session store receives only active findings, breaking `get_findings_for_ids` for suppressed findings

**Location:** Plan line 599 (`all_findings = suppression_result.active_findings`), orchestrator line 183 (`self._session_findings[scan_id] = all_findings`)

After the plan's suppression application, `all_findings` is replaced with only active findings. The session store at line 183 would then contain only non-suppressed findings. This means `get_findings_for_ids()` cannot retrieve suppressed findings by ID, and the MCP `_finding_by_id` dict (server.py lines 468-470) would also only contain non-suppressed findings.

This is probably the correct behavior for the session store (downstream phases should not operate on suppressed findings). However, if a user runs `deep_scan_hunt` with suppressions, notes a suppressed finding's ID from the suppression summary, and tries to look it up via `deep_scan_verify`, the finding would not be found in the session store.

The plan's `suppressed_finding_ids` field on `ScanStats` carries the IDs (line 649: `suppressed_finding_ids: list[str]`), but the actual finding objects are only available through `last_suppression_result`. This is not inconsistent, but it creates a subtle gap where IDs are visible in the response but the corresponding objects are not retrievable via the existing session-based lookup mechanisms.

**Recommendation:** Document this behavior explicitly. The current plan notes that `deep_scan_verify` and `deep_scan_remediate` "operate on session state and are not updated" (line 697), but does not mention that suppressed finding IDs are unretrievable via `get_findings_for_ids()`.

---

### F-20. [Minor] CLI `hunt` command does not catch `SuppressionLoadError` explicitly

**Location:** Plan Task 4.1 (lines 1069-1078)

The plan says: "Catch `ValueError` (including `SuppressionLoadError`) from malformed/oversized suppression files, report to stderr, exit(1)." However, the current CLI `hunt` command (cli.py lines 155-161) does not have a try/except around `hunter.scan()`. The plan assumes the implementer will add this error handling, but does not show the specific code change for the CLI.

If `SuppressionLoadError` (a `ValueError` subclass) is raised inside `hunter.scan()` and not caught by the CLI, it would propagate as an unhandled exception with a full traceback. The test plan includes `test_cli_hunt_malformed_suppression_file` (line 968) which should catch this gap during implementation, but the plan's task description could be more explicit about the required code change.

**Recommendation:** Add a brief pseudocode snippet to Task 4.1 showing the try/except pattern for `ValueError` around the `hunter.scan()` call, similar to how the orchestrator integration has detailed pseudocode.

---

### F-21. [Minor] `_glob_match` does not handle leading `/` in patterns

**Location:** Plan lines 150-156 (pattern splitting)

The `matches()` method splits the `file` glob pattern on `/`: `pattern_segments = self.file.split("/")`. If a user writes `file: "/src/config/*.py"` (with a leading slash), the pattern segments would be `["", "src", "config", "*.py"]`, and the empty-string first segment would never match the first segment of the relative path.

The plan does not validate or normalize the `file` field to reject leading slashes or trailing slashes. Similarly, patterns like `src/config/` (trailing slash) would produce a trailing empty segment.

**Recommendation:** Add a `field_validator` for `file` that strips leading/trailing slashes and rejects absolute paths with a helpful error message (e.g., "Suppression file patterns must be relative paths, not absolute. Remove the leading '/' from '/src/config/*.py'.").

---

### F-22. [Info] Text output format simplified from prior plan but loses pre-suppression total

**Location:** Plan line 741

The revised text output is `Scanned 50 files, found 12 findings (3 suppressed) (250ms)`. The previous review (F-14) recommended this simpler format, which was adopted. However, the pre-suppression total (15) is no longer shown anywhere in text output. Users running `--ignore-suppressions` to compare with suppressed output would need to manually add 12 + 3 to get the pre-suppression count.

This is a minor usability concern, not a correctness issue. The JSON output includes full counts.

---

### F-23. [Info] `HuntFuzzResult` does not appear in "Modified Public API" table

**Location:** Plan lines 800-808

The plan correctly states (line 808) that `HuntFuzzResult` inherits suppression data transitively via `hunt_result: HuntResult` and needs no separate field. However, the "Modified Public API" table (lines 800-806) only lists `HuntResult` and `FullScanResult`. For completeness, adding a row for `HuntFuzzResult` noting "No changes -- inherits via `hunt_result: HuntResult`" would help implementers verify they have not missed anything. This was noted in the prior F-9 finding; the revised plan addresses it in prose (line 808) but not in the table.

---

### F-24. [Info] `SuppressionConfig` allows `suppressions: []` (empty list) -- no warning

**Location:** Plan lines 386-403

A suppression file with `version: 1` and `suppressions: []` is valid. The `load_suppressions()` function would return a `SuppressionConfig` with an empty suppressions list, and `apply_suppressions()` would return all findings as active with 0 suppressed. This is fine but might confuse a user who created a suppression file with empty rules and expected something to happen.

No action needed -- this is expected behavior and the empty-file test case (line 910) covers it.

---

### F-25. [Info] Plan does not specify behavior when `target_path` is a file, not a directory

**Location:** Plan Assumption 1 (line 24)

The plan says the suppression file lives at "the root of the target project (the directory passed to `dcs hunt`)." However, `dcs hunt` can accept a single file path (e.g., `dcs hunt src/app.py`). In that case, `project_root / _SUPPRESS_FILENAME` would look for `src/app.py/.dcs-suppress.yaml`, which would never exist (since `app.py` is a file, not a directory).

The current `load_suppressions()` handles this gracefully: `suppress_path.is_file()` returns False, so it returns None and no suppressions are applied. But users might expect to scan a single file with a suppression file in the same directory.

**Recommendation:** Document this limitation in the plan. Alternatively, the loader could check `project_root.is_file()` and use `project_root.parent` in that case. This is a minor usability concern for v1.

---

## Summary

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| F-1 | was Critical | 5-tuple return break | RESOLVED |
| F-2 | was Major | fnmatch `**` support | RESOLVED |
| F-3 | was Major | SARIF DTO gap | RESOLVED |
| F-4 | was Major | Silent coverage removal | RESOLVED (documented) |
| F-5 | was Major | MCP type mismatch | RESOLVED |
| F-6 | was Major | No size limit | RESOLVED |
| F-15 | Major | `_glob_match` stack growth for adversarial patterns | NEW |
| F-16 | Minor | Formatter-orchestrator coupling for SARIF | NEW |
| F-17 | Minor | Symlink suppression file injection | RETAINED from F-10 |
| F-18 | Minor | No warning detail for expired suppressions | NEW |
| F-19 | Minor | Session store excludes suppressed findings | NEW |
| F-20 | Minor | CLI missing explicit error handling pseudocode | NEW |
| F-21 | Minor | Leading slash in file patterns breaks matching | NEW |
| F-22 | Info | Text output loses pre-suppression total | RETAINED from F-14 |
| F-23 | Info | HuntFuzzResult missing from API table | RETAINED from F-9 |
| F-24 | Info | Empty suppressions list: no warning | NEW |
| F-25 | Info | Single-file target path: suppression file not found | NEW |

The plan is well-revised and addresses all prior Critical and Major findings. The remaining F-15 is rated Major due to the theoretical adversarial potential, but its practical likelihood is low given the 500-rule and 64 KB limits. No Critical findings remain.
