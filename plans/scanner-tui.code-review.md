# Code Review: scanner-tui (Textual TUI Frontend)

**Plan:** `plans/scanner-tui.md`
**Reviewer:** code-reviewer agent v1.0.0
**Date:** 2026-03-20
**Verdict:** REVISION_NEEDED

## Code Review Summary

The TUI implementation is well-structured and follows the plan's architecture closely. Security posture is strong: no `shell=True`, no imports from analysis modules, proper path sanitization, and correct use of `asyncio.create_subprocess_exec`. However, there are two critical correctness bugs -- `meta.json` is never persisted after a scan completes, and the scan progress screen never navigates to the results view -- that make the end-to-end workflow non-functional. There are also several major issues around asyncio lifecycle management and lint failures.

## Critical Issues (Must Fix)

### C-1: `meta.json` is never written after scan completion

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/scan_progress.py` (lines 164-167)

The `_run_scan` method creates a `run_dir` via `storage.create_run_dir()`, runs the scan via `runner.run()` which returns a `RunMeta`, but never calls `storage.write_meta(run_dir, meta)`. This means:

- The history screen will never find any runs (no `meta.json` files exist).
- The report directory layout is incomplete per plan requirement (Acceptance Criterion 9).
- The report files (JSON, SARIF, HTML) are orphaned in a directory with no metadata.

**Recommendation:** After `meta = loop.run_until_complete(runner.run())`, add `storage.write_meta(run_dir, meta)`.

### C-2: Scan progress screen never navigates to ResultsViewScreen

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/scan_progress.py` (lines 187-199)

The `_on_scan_complete` method logs "Press Escape to view results" but pressing Escape pops the progress screen, returning to the scan config screen -- not to a `ResultsViewScreen`. The plan specifies "On completion -> ResultsViewScreen" in the screen flow diagram. Neither the `run_meta` nor `run_dir` are ever passed to `ResultsViewScreen`.

**Recommendation:** After scan completion, push `ResultsViewScreen` with the completed `RunMeta` and `run_dir`. This requires storing `run_dir` as an instance variable (it is currently a local variable in the worker thread).

## Major Issues (Should Fix)

### M-1: Asyncio lifecycle issues in ScanProgressScreen

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/scan_progress.py` (lines 161-175, 214-223)

Two problems with asyncio usage:

1. **`_run_scan` creates `asyncio.new_event_loop()` in a `@work(thread=True)` worker.** While this works, it means the `ScanRunner` (which uses `asyncio.create_subprocess_exec`) runs in a completely separate event loop from Textual's. This is functional but fragile -- particularly for the cancel flow.

2. **`action_cancel_scan` calls `asyncio.get_event_loop()` and `asyncio.ensure_future(self._runner.cancel())`.** This is called from the UI thread, but `self._runner.cancel()` is a coroutine that needs the same event loop where the subprocess was created (the one in the worker thread, which may have already closed). `asyncio.ensure_future` in the UI thread's loop will fail because the `Process` object is bound to the worker thread's loop.

**Recommendation:** Store the worker loop reference and use `asyncio.run_coroutine_threadsafe(runner.cancel(), worker_loop)` for cross-thread cancellation. Alternatively, use a threading `Event` flag that the worker checks.

### M-2: HistoryScreen creates redundant ReportStorage instances during row loading

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/history.py` (lines 164-183)

The `_load_runs` method has an O(N*M) lookup to find run directories: for each of N runs returned by `list_runs()`, it iterates through all M directories in the project folder, reading and parsing each `meta.json` to match by `run_id`. Additionally, it creates a new `ReportStorage()` instance (line 178) on every iteration, which reads `DCS_OUTPUT_DIR` from the environment each time instead of reusing `self._storage`.

**Recommendation:** The `list_runs()` method already iterates through directories. Consider having `list_runs()` return `(RunMeta, Path)` tuples, or add a method that returns run metadata paired with their directory paths. At minimum, replace `ReportStorage()` on line 178 with `self._storage`.

### M-3: HistoryScreen row key mapping is likely broken

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/history.py` (lines 180, 192-198)

`table.add_row()` returns a `RowKey` object (not a plain string). The code stores it with `self._row_dirs[str(row_key)]` but later looks it up with `str(table.cursor_row)` where `table.cursor_row` is an integer (the row index), not a `RowKey`. These will never match, so the [View] button will silently do nothing.

**Recommendation:** Use `table.cursor_row` as an integer index consistently, or use `table.get_row_key(table.cursor_row)` and store by `RowKey`.

### M-4: Lint failures in TUI code

**Files:** Multiple TUI source and test files

10 lint errors are introduced by this change:

| File | Error | Issue |
|------|-------|-------|
| `tui/__init__.py:38` | E402 | Module import not at top of file |
| `tui/runner.py:21` | UP035 | Import `Callable` from `collections.abc` |
| `tui/runner.py:306` | UP017 | Use `datetime.UTC` alias |
| `tui/runner.py:338` | UP041 | Replace `asyncio.TimeoutError` with `TimeoutError` |
| `tui/storage.py:82` | UP017 | Use `datetime.UTC` alias |
| `test_runner.py:3` | I001 | Unsorted imports |
| `test_runner.py:234` | E741 | Ambiguous variable name `l` |
| `test_runner.py:273` | F841 | Unused variable `meta` |
| `test_storage.py:6` | F401 | Unused import `os` |
| `test_storage.py:7` | F401 | Unused import `time` |

The plan's Acceptance Criterion 21 requires `make lint` to pass. While 74 pre-existing lint errors exist in the codebase, these 10 are newly introduced and should be fixed.

**Recommendation:** Fix all 10 lint issues. Most are auto-fixable.

### M-5: ScanConfigScreen uses f-string with `self._target_path` in compose

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/scan_config.py` (line 133)

```python
yield Static(
    f"Target: {self._target_path}",
    id="target-display",
)
```

The `target_path` originates from user input in the `TargetSelectScreen` input widget. While this is a display-only context (Textual `Static` widget, not a subprocess command), it could contain Rich markup sequences that would be interpreted by Textual's rendering engine. This is not a security vulnerability (it is the user's own terminal) but could cause rendering glitches with paths containing brackets like `[red]`.

**Recommendation:** Escape the path or use `markup=False` on the Static widget to prevent accidental Rich markup interpretation.

### M-6: `app.py` `push_screen` override signature diverges from Textual base class

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/app.py` (lines 75-105)

The `push_screen` override changes the signature to accept `kwargs: dict | None` and `callback: object = None`, with `# type: ignore[override]`. The `callback` parameter is accepted but silently ignored -- Textual's `push_screen` uses `callback` for screen result handling. Callers in `target_select.py` (line 181) and `scan_config.py` (line 246) pass `(screen_name, kwargs_dict)` as positional arguments, which could break if Textual changes its signature.

**Recommendation:** Consider using a separate method name (e.g., `push_screen_with_kwargs`) rather than overriding the base class method with an incompatible signature.

## Minor Issues (Consider)

### m-1: `datetime` imported inside method body in runner.py

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/runner.py` (line 303)

`from datetime import datetime, timezone` is imported inside `run()` despite `datetime` already being imported at the top of `storage.py`. This is not wrong but is inconsistent -- the import should be at module level.

### m-2: Duration formatting duplicated across three screens

**Files:** `scan_progress.py` (lines 111-116), `results_view.py` (lines 133-136), `history.py` (lines 143-147)

The HH:MM:SS formatting logic for `duration_seconds` is copy-pasted in three places. Consider extracting to a shared utility function in `models.py` or a separate helper.

### m-3: `ScanRunner._derive_project_name` duplicates `ReportStorage.derive_project_name`

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/runner.py` (lines 472-487)

The `_derive_project_name` method wraps `ReportStorage.derive_project_name` with a fallback, but the fallback path has simpler sanitization (no special character stripping, no `..` rejection, no max-length truncation). Since `ReportStorage` is always importable (no textual dependency), the try/except ImportError is unnecessary.

### m-4: `test_create_run_dir_unique_timestamps` relies on timing

**File:** `/Users/imurphy/projects/deep-code-security/tests/test_tui/test_storage.py` (lines 31-35)

The test assumes two consecutive `create_run_dir` calls will produce different microsecond timestamps. While this works in practice, it is technically a race condition that could fail on extremely fast systems or under time virtualization.

### m-5: `scan_progress.py` has a stale "Work Group 2" reference in docstring

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/scan_progress.py` (lines 123-125)

The docstring mentions "If the runner is unavailable (Work Group 2 not yet integrated)" -- this is a development-time note that should be removed now that all work groups are integrated.

### m-6: `test_app.py` has inconsistent `@pytest.mark.asyncio` usage

**File:** `/Users/imurphy/projects/deep-code-security/tests/test_tui/test_app.py`

Some tests use `@pytest.mark.asyncio` (without parentheses) while the runner tests use `@pytest.mark.asyncio()` (with parentheses). Both work, but consistency is preferred.

## What Went Well

1. **Security posture is clean.** No `shell=True`, no `yaml.load()`, no `eval()`, no imports from analysis modules (hunter, auditor, architect, fuzzer, bridge, mcp). The TUI correctly delegates all security-sensitive operations to the `dcs` subprocess. This is exactly what the plan's trust boundary analysis requires.

2. **Path sanitization in `derive_project_name` is thorough.** The regex-based character stripping, `..` rejection, max-length truncation, and fallback to `unnamed` are all implemented correctly and well-tested with 11 test cases covering edge cases (root path, empty result, special characters, trailing slash, file targets).

3. **`ScanRunner.build_command()` is well-designed.** It uses `sys.executable` for subprocess invocation, list-form arguments only, and no free-form argument injection. The `ScanConfig` model correctly omits any `extra_args` field. Test coverage for command building is excellent with 14 test cases.

4. **Format conversion is correctly non-fatal.** The `_convert_format` method catches all exceptions and returns `False`, ensuring JSON is always the primary artifact. This matches the plan's requirement that SARIF/HTML are best-effort.

5. **Pydantic models are well-structured.** `RunMeta` and `ScanConfig` use proper `Field` definitions, `default_factory` for lists, `ge=0.0` constraints, `Literal` types for scan type and severity, and `field_validator` for normalization. Test coverage is 100% for models.

6. **`ReportStorage` is solid.** 100% test coverage, correct use of `json.loads()` (not yaml), proper Pydantic validation on read, microsecond-precision timestamps, and graceful handling of missing/invalid `meta.json` files.

7. **Test suite is comprehensive.** 114 tests covering models, storage, runner command building, runner subprocess mocking, stderr pattern parsing, and Textual app smoke tests. The pure-Python modules achieve 95%+ coverage.

8. **Plan adherence is strong.** The `DCS_OUTPUT_DIR` is correctly kept out of `shared/config.py`, the `tui` dependency is correctly optional in `pyproject.toml`, the `dcs tui` CLI command has proper lazy import with graceful error handling, and CLAUDE.md is updated with the new command, environment variable, and architecture entry.

9. **Platform file opener implementation is correct.** `os.startfile()` on Windows (avoiding `cmd.exe` `start` which would require `shell=True`), `open` on macOS, `xdg-open` on Linux -- all using `asyncio.create_subprocess_exec` with list-form arguments.

## Verdict

**REVISION_NEEDED**

Two critical correctness bugs (C-1: `meta.json` never written, C-2: no navigation to results screen) make the end-to-end scan workflow non-functional. The history feature cannot work without C-1 being fixed. The asyncio lifecycle issues in M-1 could cause cancel to silently fail or raise. The `HistoryScreen` row key mapping in M-3 means the [View] button will never work. These issues must be addressed before the feature can ship.

### Required fixes before PASS:
- **C-1**: Add `storage.write_meta(run_dir, meta)` call after scan completion
- **C-2**: Navigate to `ResultsViewScreen` with `run_meta` and `run_dir` after scan completes
- **M-1**: Fix asyncio cross-thread cancellation (or document limitation and add a threading flag)
- **M-3**: Fix `HistoryScreen` row key -> cursor row type mismatch
- **M-4**: Fix 10 introduced lint errors (Acceptance Criterion 21)

### Recommended but not blocking:
- **M-2**: Fix O(N*M) directory lookup in HistoryScreen
- **M-5**: Escape target path in ScanConfigScreen display
- **M-6**: Clean up push_screen override
