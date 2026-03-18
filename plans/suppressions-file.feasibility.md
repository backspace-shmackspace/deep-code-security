# Feasibility Review (Pass 2): Suppressions File (.dcs-suppress.yaml)

**Plan:** `./plans/suppressions-file.md`
**Reviewer:** code-reviewer (agent)
**Date:** 2026-03-17
**Pass:** 2 (revision review after plan updates)
**Verdict:** PASS

---

## Overall Assessment

The revised plan adequately addresses all six prior findings (M-1/F-2, M-2/F-1, M-3/F-3, M-4/F-5, F-4, F-6). The most impactful changes -- replacing the fragile 5-tuple return with ScanStats embedding, replacing raw `fnmatch` with a segment-aware `_glob_match()` helper, and adding size/rule limits -- are well-designed and implementable. The remaining concerns below are minor refinements, not blockers.

---

## Prior Finding Resolution Audit

### F-2/M-1: fnmatch `**` issue -- segment-aware `_glob_match()` helper

**Status: RESOLVED**

The plan now includes a fully specified `_glob_match()` function using stack-based backtracking. I traced the algorithm through five representative cases:

| Pattern | Path | Expected | Result |
|---------|------|----------|--------|
| `generated/**/*.py` | `generated/foo.py` | True (zero intermediate dirs) | Correct |
| `generated/**/*.py` | `generated/a/b/c/foo.py` | True (deep nesting) | Correct |
| `src/config/*.py` | `src/config/sub/loader.py` | False (`*` must not cross dirs) | Correct |
| `**/*.py` | `foo.py` | True (zero leading dirs) | Correct |
| `src/**/test.py` | `src/test.py` | True (`**` matches zero segments) | Correct |

The algorithm correctly handles `**` as zero-or-more segments and restricts `*` to within a single segment by using `fnmatch.fnmatch()` on individual path segments only. The `matches()` method correctly splits both the pattern and the relative path on `/` before calling `_glob_match()`, and normalizes via `PurePosixPath` for cross-platform consistency.

One minor performance note: the backtracking stack can accumulate duplicate entries for deep paths with `**` patterns, leading to O(n^2) stack growth where n is path depth. This is bounded by practical path depths and is not a concern given the 500-rule limit.

### M-2/F-1: 5-tuple break -- ScanStats embedding + `last_suppression_result` property

**Status: RESOLVED**

The revised plan embeds suppression metadata (`findings_suppressed`, `suppression_rules_loaded`, `suppression_rules_expired`, `suppressed_finding_ids`) directly into the already-returned `ScanStats` object. The `scan()` return type remains `tuple[list[RawFinding], ScanStats, int, bool]` -- a 4-tuple unchanged from the current codebase.

I verified against the actual code:
- `ScanStats` in `hunter/models.py` is NOT frozen (no `model_config = {"frozen": True}` on it), so adding and setting fields post-construction is valid.
- All six production call sites (3 in `cli.py` lines 155/263/758, 3 in `mcp/server.py` lines 451/641/1073) unpack as a 4-tuple and will continue to work without modification.
- All test call sites (`test_orchestrator.py` lines 47/57/69/80/84/94/100/117/127/135/154/165, `test_cli_format.py` line 87/175, `test_hunt_fuzz.py` lines 140/189/302, integration tests) also unpack 4-tuples and will not break.
- The `assert len(result) == 4` in `test_orchestrator.py` line 48 remains correct.
- Task 2.3 correctly states "Existing tests do NOT need unpacking changes."

The `last_suppression_result` property provides detailed suppression data (suppressed finding objects, per-finding reasons) for callers that need it (SARIF formatter, CLI summary), keeping the core return signature clean. This is a sound design.

### M-3/F-3: SARIF DTO gap -- `suppressed_finding_ids` on DTOs

**Status: RESOLVED**

The plan now adds `suppressed_finding_ids: list[str] = Field(default_factory=list)` to both `HuntResult` and `FullScanResult`. The SARIF formatter receives the actual suppressed `RawFinding` objects through `orchestrator.last_suppression_result.suppressed_findings` rather than through the DTO, keeping the DTOs lean. The "Modified Public API" table is updated to include both DTOs and the new `suppressed_finding_ids` field.

The plan also explicitly addresses `HuntFuzzResult`: "HuntFuzzResult inherits suppression data transitively via its `hunt_result: HuntResult` field. No separate suppression field is needed." I verified that `HuntFuzzResult` in `protocol.py` (line 147) contains `hunt_result: HuntResult`, confirming this propagation works.

### M-4/F-5: MCP pseudocode bug -- reads from ScanStats integer fields

**Status: RESOLVED**

The MCP response now reads directly from `ScanStats` fields:
```python
"suppressed_count": stats.findings_suppressed,
"total_rules": stats.suppression_rules_loaded,
"expired_rules": stats.suppression_rules_expired,
"suppressed_finding_ids": stats.suppressed_finding_ids,
```

All four fields are typed correctly: `int`, `int`, `int`, `list[str]`. The original bug (using `suppression_result.suppressed_findings` which is a `list[RawFinding]` instead of `len(...)`) is eliminated because `stats.findings_suppressed` is already an `int`.

### F-4: Silent removal from Auditor/Bridge coverage

**Status: RESOLVED**

The plan now includes a dedicated "Suppression Semantics" section that explicitly documents:
1. Suppressed findings do NOT consume Auditor sandbox slots.
2. Suppressed findings do NOT generate Architect remediation guidance.
3. Suppressed findings are NOT passed to the Bridge for fuzz target resolution.
4. `--ignore-suppressions` bypasses all suppression logic for verification runs.

The rationale (avoiding wasteful sandbox execution and API credits on user-acknowledged non-issues) is clearly stated. The MCP section adds a note clarifying session-store interaction: "Suppression is applied at the Hunt phase only. The MCP session store reflects the findings from the most recent Hunt invocation."

### F-6: Size limits -- 64KB file + 500 rules max

**Status: RESOLVED**

The plan adds `_MAX_SUPPRESSION_FILE_SIZE = 65536` (64 KB) and `_MAX_SUPPRESSION_RULES = 500`. The file size is checked before `read_text()`, and the rule count is checked after `yaml.safe_load()`. `SuppressionLoadError` (subclass of `ValueError`) is raised with actionable messages. Test cases `test_load_suppressions_file_too_large` and `test_load_suppressions_too_many_rules` are specified. This follows the existing pattern of `DCS_MAX_FILES`, `DCS_MAX_RESULTS`, etc.

---

## Critical Concerns

None.

---

## Major Concerns

None. All prior Major findings are resolved.

---

## Minor Concerns

### m-1: `last_suppression_result` not documented as immediately-consume-after-scan

**Location:** Plan section "Integration Points, 1. Hunter Orchestrator" -- `last_suppression_result` property.

The `last_suppression_result` property stores the result of the most recent `scan()` call. The plan shows CLI and MCP handlers reading it immediately after `scan()` returns. This is safe in the current architecture because:
- CLI calls are sequential (single-threaded).
- MCP stdio transport processes one request at a time; `scan()` is synchronous and blocks the event loop.

However, the plan does not document this "read immediately after scan" contract. If a future change introduced true concurrent scanning (e.g., asyncio `run_in_executor` for `scan()`), the property would race. The `_handle_hunt_fuzz` handler is the closest risk: it runs `scan()` synchronously, then spawns a background thread. If a second request arrived between scan completion and the property read, the result could be overwritten. In practice, the MCP stdio transport serializes requests, so this cannot happen today.

**Recommendation:** Add a one-line docstring note to the property: "Must be read immediately after scan() before the next scan() call. Not thread-safe across concurrent scan invocations." This documents the contract for future maintainers. Not a blocking concern.

### m-2: Symlink resolution on suppression file path still unaddressed

**Location:** `load_suppressions()` function.

The prior feasibility review (m-1) and redteam review (F-10) both flagged that `.dcs-suppress.yaml` could be a symlink pointing outside the validated target path. The revised plan does not address this. The plan's Security Considerations section states "no user-controlled path component is involved beyond the already-validated target," but a symlink within the target directory introduces a controlled escape.

The risk remains low because:
1. The suppression file only controls which findings are hidden (no code execution).
2. The target directory's contents are already in the same trust boundary as the scanned code -- an attacker who can place a symlink in the repo can also modify the source code being scanned.

**Recommendation:** Add `suppress_path = suppress_path.resolve()` and verify `suppress_path.is_relative_to(project_root)` before reading. Add a test case. This is defense-in-depth, not a blocking concern.

### m-3: `expires` validation still accepts ISO week dates

**Location:** `SuppressionRule.validate_expires()`.

The prior feasibility review (m-5) noted that `datetime.date.fromisoformat()` on Python 3.11+ accepts non-calendar ISO formats like `"2026-W01-1"` (ISO week dates). The revised plan's validator parses with `date.fromisoformat(v)` but does not re-validate the format. A user writing `expires: "2026-W01-1"` would get accepted but the resulting date would be unexpected.

**Recommendation:** Add a round-trip check: `parsed = date.fromisoformat(v); if v != parsed.isoformat(): raise ValueError(...)`. This ensures only `YYYY-MM-DD` is accepted. Very low priority.

### m-4: `_glob_match` does not handle edge case of trailing `**`

**Location:** `_glob_match()` function.

The pattern `src/**` (trailing `**`, no further segments) should match any file under `src/`. Tracing the algorithm:
- path_segments = ["src", "a", "b.py"], pattern_segments = ["src", "**"]
- pi=0,si=0: match -> pi=1,si=1
- pi=1: "**" -> stack.append((1,2)), pi=2. continue.
- pi=2 >= 2 (end of pattern), si=1 < 3: while condition is True (si < len).
- Not "**" check (pi not < len), not fnmatch check (pi not < len).
- Stack: pop (1,2). pi=1,si=2. push (1,3). continue.
- pi=1: "**" -> stack.append((1,3)), pi=2. continue.
- pi=2>=2, si=2<3: same pattern.
- Pop (1,3). pi=1,si=3. push (1,4). 3<=3, so push. continue.
- pi=1: "**" -> stack.append((1,4)), pi=2.
- pi=2>=2, si=3>=3: loop ends. Return 2>=2 and 3>=3: True. Correct.

The trailing `**` case works. This concern is withdrawn -- the algorithm is correct. But note that the test plan does not include a test case for trailing `**`.

**Recommendation:** Add a test case for `src/**` matching `src/a/b/c.py` to the glob matching tests.

### m-5: Test plan does not cover `SuppressionLoadError` propagation through CLI

**Location:** Plan Test Plan section.

The revised plan adds `test_cli_hunt_malformed_suppression_file` and `test_cli_full_scan_malformed_suppression_file` (addressing redteam F-11). These test that `ValueError` from malformed files results in CLI exit code 1 with a user-friendly error. However, `SuppressionLoadError` (the subclass raised for size/rule limit violations) is not explicitly tested at the CLI level. Since `SuppressionLoadError` is a `ValueError` subclass, existing error handling should catch it, but an explicit test case would confirm the error message is actionable.

**Recommendation:** Add `test_cli_hunt_oversized_suppression_file` that verifies the "exceeds maximum size of 64KB" error message reaches stderr. Low priority since `SuppressionLoadError` inherits from `ValueError`.

---

## Complexity Assessment (Revised)

| Component | Estimated Effort | Plan Accuracy |
|-----------|-----------------|---------------|
| Core suppression module (models, loader, matcher, `_glob_match`) | Small-Medium | Accurate -- fully specified with production-ready code |
| Hunter orchestrator integration | Small | Accurate -- insertion point is clear, ScanStats embedding avoids breaking changes |
| CLI integration | Small | Accurate |
| MCP server integration | Small | Accurate -- reads from ScanStats fields directly |
| Formatter DTO changes | Small | Accurate -- `suppressed_finding_ids` on DTOs, SARIF gets objects via property |
| TextFormatter update | Trivial | Accurate |
| JsonFormatter update | Small | Accurate |
| SarifFormatter update | Medium | Improved -- data flow now specified via `orchestrator.last_suppression_result` |
| HtmlFormatter update | Medium | Accurate |
| Test suite | Medium | Adequate -- 46+ test cases specified, existing tests need no unpacking changes |

**Total estimated effort:** 2-3 days for a developer familiar with the codebase. Unchanged from pass 1.

---

## Dependency and Library Assessment

No changes from pass 1:
- **No new runtime dependencies.** The plan uses stdlib (`fnmatch`, `datetime`, `pathlib`, `re`) and existing deps (`pydantic`, `pyyaml`).
- **`fnmatch` is now used per-segment only**, inside the custom `_glob_match()` helper. This eliminates the `fnmatch` `**` limitation.
- **PyYAML `yaml.safe_load()`** is already used throughout the codebase.

---

## Security Assessment (Revised)

The plan's security posture is strong and unchanged in substance:

1. `yaml.safe_load()` exclusively. Tested explicitly.
2. No `eval()`, `exec()`, `os.system()`, or `subprocess.run(shell=True)`.
3. Suppression file path derived from already-validated target path with hardcoded filename.
4. Glob matching uses pure string operations via `_glob_match()`. No filesystem access.
5. `SuppressionRule` is frozen (immutable).
6. File size (64 KB) and rule count (500) limits prevent DoS.

The symlink concern (m-2) remains unaddressed but is low risk given the threat model (attacker controls the repo contents, including source code being scanned). See m-2 recommendation above.

---

## Verdict: PASS

All six prior findings (M-1/F-2, M-2/F-1, M-3/F-3, M-4/F-5, F-4, F-6) are adequately resolved. The revised plan is technically sound, security-compliant, and ready for implementation. The remaining minor concerns (m-1 through m-5) are refinements that can be addressed during implementation without requiring another plan revision.

### Summary of Remaining Recommendations

| ID | Category | Action |
|----|----------|--------|
| m-1 | Minor | Document `last_suppression_result` as read-immediately-after-scan; note it is not thread-safe across concurrent scans |
| m-2 | Minor | Add `suppress_path.resolve()` + `is_relative_to()` check for symlink defense-in-depth |
| m-3 | Minor | Tighten `expires` validation to reject ISO week dates via round-trip check |
| m-4 | Minor | Add test case for trailing `**` pattern (e.g., `src/**` matching `src/a/b/c.py`) |
| m-5 | Minor | Add CLI-level test for `SuppressionLoadError` (oversized file) error message |
