# Code Review: scanner-tui (Textual TUI Frontend) -- Revision Round

**Plan:** `plans/scanner-tui.md`
**Reviewer:** code-reviewer agent v1.0.0
**Date:** 2026-03-20
**Round:** Revision (verifying fixes for C-1, C-2, M-1 through M-6)
**Verdict:** PASS

## Code Review Summary

The revision addresses both critical findings and all blocking major findings from the initial review. The `meta.json` persistence gap (C-1) and missing results navigation (C-2) are fixed correctly. The asyncio cross-thread cancellation (M-1) now uses `run_coroutine_threadsafe` with proper error handling. The HistoryScreen row key mapping (M-3) and redundant storage instantiation (M-2) are fixed. The `push_screen` override (M-6) was replaced with a clean `push_screen_with_kwargs` method. Six lint errors remain (down from 10), but only one is in production code and all are auto-fixable style issues, not correctness or security concerns. No new critical or major issues were introduced.

## Prior Findings Resolution

### C-1: `meta.json` is never written after scan completion -- RESOLVED

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/scan_progress.py` (line 172)

The `_run_scan` method now calls `storage.write_meta(run_dir, meta)` immediately after `runner.run()` completes. The comment `# C-1: Persist meta.json to the run directory` explicitly documents the fix. The history screen can now discover runs via `meta.json` files.

### C-2: Scan progress screen never navigates to ResultsViewScreen -- RESOLVED

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/scan_progress.py` (lines 210-215)

The `_on_scan_complete` method now imports `ResultsViewScreen` and calls `self.app.push_screen(ResultsViewScreen(run_meta=meta, run_dir=run_dir))`. The `run_dir` and `meta` are passed from the worker thread via `self.app.call_from_thread(self._on_scan_complete, meta, run_dir)` on line 176. The `ResultsViewScreen` constructor correctly accepts `run_meta` and `run_dir` parameters (lines 87-97 of `results_view.py`).

### M-1: Asyncio lifecycle issues in ScanProgressScreen -- RESOLVED

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/scan_progress.py` (lines 234-244)

The fix follows the reviewer's recommendation: `self._worker_loop` stores a reference to the worker thread's event loop (line 167). The `action_cancel_scan` method validates the loop is an `AbstractEventLoop` and is still running before calling `asyncio.run_coroutine_threadsafe(self._runner.cancel(), loop)` (lines 238-241). The entire block is wrapped in `try/except Exception: pass` for best-effort semantics, and the `self._cancelled` flag (line 224-226) prevents double-cancellation. A `threading.Event` (line 89) is also set as a secondary signal.

The TOCTOU between checking `self._worker_loop is not None` and calling `run_coroutine_threadsafe` is benign: the finally block (lines 183-185) sets `self._worker_loop = None` after `loop.close()`, and the exception handler catches `RuntimeError` from scheduling on a closed loop. This is the correct pattern for best-effort cross-thread asyncio cancellation.

### M-2: HistoryScreen creates redundant ReportStorage instances -- RESOLVED

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/history.py` (lines 148-157)

The `_load_runs` method now builds a `run_id_to_dir` mapping in a single pass over the project directory using `self._storage` (not a new `ReportStorage()` instance). The comment `# Build a run_id -> directory mapping in a single pass (M-2 fix)` documents the change. The complexity is now O(N) for building the map + O(N) for populating the table, down from the original O(N*M) with redundant storage instantiation.

### M-3: HistoryScreen row key mapping is broken -- RESOLVED

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/history.py` (lines 72, 159, 181-183, 192-195)

The `_row_dirs` type was changed from `dict[str, Path]` to `dict[int, Path]` (line 72). The table population uses `enumerate(runs)` and stores with `self._row_dirs[row_index]` (lines 159, 181-183). The `on_button_pressed` handler looks up `table.cursor_row` (an integer) directly in `self._row_dirs` (lines 193-195). Integer keys now match consistently.

### M-4: Lint failures in TUI code -- PARTIALLY RESOLVED

4 of the original 10 lint errors have been fixed:
- `tui/__init__.py:38` E402 (module import not at top) -- fixed
- `tui/runner.py:21` UP035 (`Callable` import location) -- fixed, now imports from `collections.abc`
- `tui/runner.py:306` UP017 (`datetime.UTC` alias) -- fixed in `runner.py`
- `tui/runner.py:338` UP041 (`asyncio.TimeoutError` -> `TimeoutError`) -- fixed, now uses `TimeoutError`

6 lint errors remain:

| File | Error | Status |
|------|-------|--------|
| `storage.py:82` | UP017 | `datetime.now(timezone.utc)` should use `datetime.UTC` alias |
| `test_runner.py:3` | I001 | Import block unsorted |
| `test_runner.py:234` | E741 | Ambiguous variable name `l` |
| `test_runner.py:273` | F841 | Unused variable `meta` |
| `test_storage.py:6` | F401 | Unused import `os` |
| `test_storage.py:7` | F401 | Unused import `time` |

All 6 are auto-fixable style issues (4 in test code, 1 in production code). None affect correctness or security. Downgraded from Major to Minor for this revision since the production code lint count dropped from 4 to 1, and the overall count dropped from 10 to 6.

### M-5: ScanConfigScreen uses f-string with target_path in compose -- RESOLVED

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/scan_config.py` (line 135)

The `Static` widget now includes `markup=False`, preventing Rich markup interpretation of user-supplied paths:
```python
yield Static(
    f"Target: {self._target_path}",
    id="target-display",
    markup=False,
)
```

### M-6: `app.py` push_screen override diverges from Textual base class -- RESOLVED

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/app.py` (lines 75-92)

The `push_screen` override was replaced with a separate method `push_screen_with_kwargs(self, screen_name: str, kwargs: dict)` that constructs the screen instance via `_build_screen` and then calls the unmodified base class `self.push_screen(screen_instance)`. Callers in `target_select.py` (line 180) and `scan_config.py` (line 247) were updated to call `self.app.push_screen_with_kwargs(...)`. The base class `push_screen` signature is no longer overridden, so Textual's callback plumbing works correctly. A similar `switch_to_screen` method (lines 94-106) handles the results-to-target navigation without overriding `switch_screen`.

## Critical Issues (Must Fix)

None.

## Major Issues (Should Fix)

None.

## Minor Issues (Consider)

### m-1: Six remaining lint errors (style-only)

**Files:** `storage.py`, `test_runner.py`, `test_storage.py`

Six lint warnings remain (detailed in M-4 resolution above). All are auto-fixable with `ruff check --fix`. The one production code issue (`storage.py:82` UP017) is a style preference for `datetime.UTC` over `timezone.utc`.

**Recommendation:** Run `ruff check --fix src/deep_code_security/tui/ tests/test_tui/` and manually fix the E741 (`l` -> `line` in test helper).

### m-2: Duration formatting duplicated across three screens

**Files:** `scan_progress.py` (lines 117-121), `results_view.py` (lines 133-136), `history.py` (lines 160-164)

The HH:MM:SS formatting logic for `duration_seconds` is copy-pasted in three places. This was noted in the prior review and remains unchanged.

**Recommendation:** Extract to a utility function (e.g., `format_duration(seconds: float) -> str` in `models.py` or a `tui/utils.py`).

### m-3: `_derive_project_name` fallback in runner.py has weaker sanitization

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/runner.py` (lines 473-488)

The fallback path (when `ReportStorage` import fails) uses a simple `p.name` without character stripping, `..` rejection, or max-length truncation. Since `ReportStorage` has no `textual` dependency, the `ImportError` path is effectively dead code. The `try/except ImportError` is unnecessary.

**Recommendation:** Remove the try/except and call `ReportStorage.derive_project_name()` directly.

### m-4: `datetime` imported inside method body in runner.py

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/runner.py` (line 304)

`from datetime import UTC, datetime` is imported inside the `run()` method body. This is not wrong but is inconsistent with the module-level import style used elsewhere.

**Recommendation:** Move to module-level imports.

### m-5: `_build_summary` in ResultsViewScreen uses f-strings with meta.target_path in markup-enabled Static

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/results_view.py` (line 104, 145)

The summary text includes `f"Target: {meta.target_path}"` and is rendered in a `Static` widget with default `markup=True`. A path containing Rich markup brackets could cause rendering glitches. The widget needs markup enabled for `[green]Success[/green]` styling. This is purely a display issue in the user's own terminal, not a security concern.

**Recommendation:** Escape the `target_path` value with `rich.markup.escape()` before interpolation, or separate the styled and unstyled portions into distinct widgets.

### m-6: HistoryScreen reads each meta.json twice

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/history.py` (lines 143-157)

The `list_runs()` call (line 144) reads all `meta.json` files, and the `run_id_to_dir` loop (lines 152-157) reads them again. Both passes are O(N), so this is not a performance concern for typical usage. A future refactor could add a `list_runs_with_dirs()` method returning `list[tuple[RunMeta, Path]]` to eliminate the double read.

## What Went Well

1. **All critical findings properly fixed.** C-1 (`meta.json` persistence) and C-2 (results navigation) are both correct and well-commented with explicit references to the finding IDs.

2. **Asyncio cancellation rewrite is solid.** The M-1 fix correctly uses `run_coroutine_threadsafe` with loop lifecycle checks and exception handling. The TOCTOU between checking `self._worker_loop` and scheduling is benign due to the exception handler. This is the idiomatic pattern for cross-thread asyncio coordination.

3. **`push_screen_with_kwargs` is a clean design.** Rather than overriding Textual's `push_screen` with an incompatible signature, the code uses a separate method name. This preserves the base class contract and avoids `# type: ignore[override]`.

4. **Security posture remains clean.** No `shell=True`, no `yaml.load()`, no `eval()`, no imports from analysis modules. All subprocess invocations use `asyncio.create_subprocess_exec` with list-form arguments. Path sanitization in `derive_project_name` is thorough (regex character stripping, `..` rejection, max-length truncation, `unnamed` fallback). Platform file opener uses `os.startfile()` on Windows to avoid `cmd.exe` `start` builtin.

5. **Test coverage is comprehensive.** 114+ tests covering models, storage, runner command building, runner subprocess mocking, stderr pattern parsing, and Textual app smoke tests. The test structure correctly separates Textual-dependent tests (`test_app.py` with `pytest.importorskip`) from pure-Python tests.

6. **Plan adherence is strong.** All acceptance criteria verifiable from code inspection are met: `dcs tui` CLI command with lazy import (cli.py:1126-1139), `textual` as optional dependency (pyproject.toml:43), `DCS_OUTPUT_DIR` read by `tui/storage.py` only (not `shared/config.py`), `make test-tui` target in Makefile, CLAUDE.md updated with new command/env var/architecture entry, no free-form `extra_args` on `ScanConfig`, `markup=False` on target path display.

7. **Pydantic models are well-structured.** `RunMeta` and `ScanConfig` use proper `Field` definitions, `default_factory` for lists, `ge=0.0` constraints, `Literal` types, and `field_validator` for normalization. Serialization roundtrip is tested.

## Verdict

**PASS**

All critical findings (C-1, C-2) are resolved. All blocking major findings (M-1, M-2, M-3, M-5, M-6) are resolved. M-4 (lint) is partially resolved (10 -> 6 errors, only 1 in production code) and the remaining issues are auto-fixable style warnings, downgraded to minor. No new critical or major issues were identified. The code is ready to proceed.
