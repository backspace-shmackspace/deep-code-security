# QA Report: scanner-tui (Textual TUI Frontend)

**Plan:** `plans/scanner-tui.md`
**Date:** 2026-03-20
**Verdict:** FAIL

## Summary

The implementation delivers a structurally complete TUI module with all 18 plan-specified files created, comprehensive test coverage (95.33% on TUI modules, 90.91% overall), and correct data models, storage, and runner logic. However, two blocking defects prevent the scan workflow from functioning end-to-end: (1) `meta.json` is never written to disk after scan completion, and (2) the `ResultsViewScreen` is unreachable from the normal scan flow. Additionally, `make lint` introduces 10 new lint violations in TUI code.

---

## Acceptance Criteria Coverage

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | `pip install deep-code-security[tui]` installs the `textual` dependency | MET | `pyproject.toml` line 43: `tui = ["textual>=0.70.0"]` |
| 2 | `dcs tui` launches the Textual application without error | MET | `cli.py` lines 1125-1139 implement the command; `test_app_startup` passes |
| 3 | `dcs tui` displays a clear error message if `textual` is not installed | MET | `cli.py` lines 1130-1136: `ImportError` caught, user-facing message with install instructions, `sys.exit(1)` |
| 4 | `TargetSelectScreen` shows directory tree browser and accepts manual path input | MET | `target_select.py`: `DirectoryTree` widget + `Input` widget with `on_input_changed` handler |
| 5 | `ScanConfigScreen` allows selection of scan type, language filter, severity threshold, and scan options via explicitly enumerated UI controls | MET | `scan_config.py`: `RadioSet` for scan type, `SelectionList` for languages, `Select` dropdown for severity, `Switch` toggles for skip-verify and ignore-suppressions. No free-form `Input` for extra arguments. |
| 6 | `ScanProgressScreen` streams stderr output from a running `dcs hunt` scan in real time | MET | `scan_progress.py`: `RichLog` widget receives lines via `on_stderr_line` callback from `ScanRunner`. Verified by `test_run_captures_stderr`. |
| 7 | `ScanProgressScreen` allows cancellation via [Cancel] button or Ctrl+C | MET | `scan_progress.py` lines 32-33: `BINDINGS = [("ctrl+c", "cancel_scan", ...)]`; line 225-228: `on_button_pressed` for Cancel button; `action_cancel_scan` calls `runner.cancel()` |
| 8 | Scan runs ONCE with `--format json`. SARIF/HTML derived in-process. Report files written to report directory. | PARTIALLY MET | Runner correctly builds command with `--format json --output-file`. In-process conversion via `_convert_format` uses `shared.formatters.get_formatter()`. However, `meta.json` is not written (see AC #9). Report files (JSON, SARIF, HTML) are written correctly to `run_dir`. |
| 9 | `meta.json` file is written with accurate metadata | **NOT MET** | **Blocking defect.** Neither `ScanRunner.run()` nor `ScanProgressScreen._run_scan()` calls `storage.write_meta(run_dir, meta)`. The `RunMeta` object is constructed and returned but never serialized to `meta.json`. The `_run_scan` method (scan_progress.py line 165) stores the meta in `self._completed_meta` and calls `self._on_scan_complete(meta)`, but `write_meta` is never invoked. This breaks the entire history feature. |
| 10 | `findings_count` for fuzz scans extracted from `output["summary"]["unique_crash_count"]` | MET | `runner.py` line 363-364: `return int(output["summary"]["unique_crash_count"])`. Verified by `test_run_findings_count_fuzz`. |
| 11 | `backend_used` for hunt-fuzz scans extracted from `output["hunt_result"]["stats"]["scanner_backend"]` | MET | `runner.py` line 387: correct extraction path. Verified by `test_run_backend_used_hunt_fuzz`. |
| 12 | `ResultsViewScreen` displays scan summary and provides [Open] buttons | **NOT MET** | **Blocking defect.** The `ResultsViewScreen` is implemented but unreachable from the normal scan flow. The plan's flow diagram specifies "On completion -> ResultsViewScreen", but `ScanProgressScreen._on_scan_complete()` (line 187-199) only updates the UI text and says "Press Escape to view results." Pressing Escape pops back to `ScanConfigScreen`, not to `ResultsViewScreen`. No code path in the application pushes `ResultsViewScreen`. |
| 13 | [Open] button uses `os.startfile()` on Windows, `["open", path]` on macOS, `["xdg-open", path]` on Linux. No `shell=True`. | MET | `results_view.py` lines 200-213 and `history.py` lines 210-221 implement correct platform-specific openers. No `shell=True` used. |
| 14 | `HistoryScreen` displays a `DataTable` of past runs sorted by date descending | PARTIALLY MET | Implementation is correct (`history.py` loads from `ReportStorage.list_runs()`, renders `DataTable` with correct columns, sorted descending). However, since `meta.json` is never written (AC #9), the history will always be empty in practice. |
| 15 | `HistoryScreen` correctly reads and displays `meta.json` from multiple projects | PARTIALLY MET | Code logic is correct (tested via `populated_storage` fixture). But since `meta.json` is never written, the feature is non-functional end-to-end. |
| 16 | `DCS_OUTPUT_DIR` env var overrides default. Read by `tui/storage.py` only, not by `shared/config.py`. | MET | `storage.py` line 70: `os.environ.get("DCS_OUTPUT_DIR", ...)`. `shared/config.py` is unmodified (`git diff main` is empty). Verified by `test_output_dir_from_env`, `test_output_dir_default`, `test_output_dir_expanduser`. |
| 17 | No `shell=True` anywhere in the TUI module | MET | Grep for `shell=True` finds only comments/docstrings. All subprocess calls use `asyncio.create_subprocess_exec()` with list-form arguments. |
| 18 | No imports from `hunter`, `auditor`, `architect`, `fuzzer`, `bridge`, or `mcp` modules | MET | Grep confirms zero matches. Only `shared.config`, `shared.formatters`, and `__version__` are imported. |
| 19 | `make test` passes with 90%+ coverage. TUI screen/app files excluded; models/storage/runner included. | MET | `make test` passes (1033 passed, 14 skipped, 90.91% coverage). `pyproject.toml` coverage omits: `*/tui/app.py`, `*/tui/screens/*.py`. `models.py` (100%), `storage.py` (100%), `runner.py` (95%) are included. |
| 20 | `make test-tui` passes | MET | 114 tests passed, 95.33% coverage in 0.58s. |
| 21 | `make lint` passes | **NOT MET** | `make lint` exits with code 1 (96 total errors). Approximately 85 are pre-existing (E501, B007, etc.), but the TUI introduces 10 new violations: F401 (unused imports in test_storage.py), E741 (ambiguous variable `l` in test_runner.py), F841 (unused variable in test_runner.py), UP017 (use `datetime.UTC`), UP035 (import `Callable` from `collections.abc`), UP041 (use `TimeoutError`), I001 (import sorting), E402 (module-level import). |

### Summary: 14 MET, 2 PARTIALLY MET, 3 NOT MET

---

## Blocking Defects

### B-1: `meta.json` never written to disk (AC #9)

**Location:** `src/deep_code_security/tui/screens/scan_progress.py` lines 144-175

After `runner.run()` returns a `RunMeta` at line 165, the code stores it in `self._completed_meta` and calls `self._on_scan_complete(meta)`, but never calls `storage.write_meta(run_dir, meta)`. The `ReportStorage` instance and `run_dir` are both in scope. A single missing line breaks the entire history and report browsing feature.

**Impact:** AC #9 fails. AC #14 and #15 are partially broken (the code logic works but there is no data to display). The entire report storage layout is effectively dead.

**Fix:** Add `storage.write_meta(run_dir, meta)` between lines 165 and 166 in `_run_scan()`.

### B-2: `ResultsViewScreen` unreachable from scan flow (AC #12)

**Location:** `src/deep_code_security/tui/screens/scan_progress.py` lines 187-199

The plan specifies: "On completion -> ResultsViewScreen". The `_on_scan_complete` method updates the phase indicator to "Scan complete", disables the cancel button, logs a summary, and says "Press Escape to view results." But pressing Escape pops back to `ScanConfigScreen` (the previous screen on the stack), not to `ResultsViewScreen`. No code anywhere in the application pushes `ResultsViewScreen`.

**Impact:** AC #12 fails. Users cannot see the scan summary with report file links after a scan completes. The `ResultsViewScreen` implementation is complete but orphaned.

**Fix:** After scan completion, push `ResultsViewScreen` with `self.app.push_screen("results_view", {"run_meta": meta, "run_dir": run_dir})`.

---

## Non-Blocking Issues

### N-1: 10 new lint violations (AC #21)

While `make lint` was already failing before the TUI changes (85 pre-existing errors), the TUI adds 10 new violations. These are all auto-fixable style issues (6 of 10 fixable with `ruff --fix`) plus 2 substantive ones:

- `tests/test_tui/test_runner.py:234` -- E741 ambiguous variable name `l` (rename to `line`)
- `tests/test_tui/test_runner.py:273` -- F841 unused variable `meta` (prefix with `_`)
- `tests/test_tui/test_storage.py:6-7` -- F401 unused imports `os`, `time`

### N-2: `ScanProgressScreen._run_scan()` creates a new event loop in a worker thread

**Location:** `src/deep_code_security/tui/screens/scan_progress.py` lines 161-175

The `_run_scan()` method (decorated with `@work(thread=True)`) creates a new `asyncio.new_event_loop()` to run the async `runner.run()` coroutine. This works but is architecturally unusual -- Textual provides `run_worker()` with coroutine support. The current approach is functional but may cause issues if Textual's event loop integration changes.

### N-3: `HistoryScreen._load_runs()` creates redundant `ReportStorage()` instances

**Location:** `src/deep_code_security/tui/screens/history.py` line 176

When resolving row keys to run directories, the code creates a new `ReportStorage()` instance inside a loop (`for child in ...`). It should reuse `self._storage` which already holds the `ReportStorage` instance.

### N-4: Test `test_run_writes_meta_json` is misnamed

**Location:** `tests/test_tui/test_runner.py` line 280

The test is named `test_run_writes_meta_json` but it only verifies that `RunMeta` is returned with correct fields. It does NOT verify that `meta.json` is written to disk (which, as identified in B-1, never happens). The test name is misleading.

---

## Test Coverage Analysis

| Module | Coverage | Plan Target | Status |
|--------|----------|-------------|--------|
| `tui/models.py` | 100% | Included in `make test` 90% gate | PASS |
| `tui/storage.py` | 100% | Included in `make test` 90% gate | PASS |
| `tui/runner.py` | 95% | Included in `make test` 90% gate | PASS |
| `tui/__init__.py` | 44% | Included in `make test` 90% gate | ACCEPTABLE (9 stmts, 5 missed are the `_check_textual_available` function which is a utility not called by tests) |
| `tui/app.py` | Excluded | Excluded from `make test` (Textual-dependent) | N/A |
| `tui/screens/*.py` | Excluded | Excluded from `make test` (Textual-dependent) | N/A |

### Missing Test Cases (from plan's test list)

All test cases specified in the plan's Test Cases section are present and passing:

- **Models tests:** 11 tests covering required fields, defaults, serialization, validation, scan types, languages, no extra_args
- **Storage tests:** 22 tests covering create_run_dir, write_meta, read_meta, list_projects, list_runs, derive_project_name variants, output_dir env var handling
- **Runner tests:** 34 tests covering build_command variants, run captures, format conversion, findings_count extraction, backend_used extraction, cancel behavior, static extraction methods
- **Patterns tests:** 22 tests covering all stderr pattern constants and parse_stderr_line function
- **App tests:** 5 tests covering startup, initial screen, quit binding, title version, escape on initial screen

### Missing Edge Case Tests

1. No test verifies that `meta.json` is actually written to disk end-to-end (relates to B-1)
2. No test for `ResultsViewScreen` navigation from `ScanProgressScreen` (relates to B-2)
3. No test for `ScanConfig` with `fuzz` scan type to verify `--consent` is added AND `--ignore-suppressions` is NOT added simultaneously

---

## Security Verification

| Check | Status |
|-------|--------|
| No `yaml.load()` in TUI module | PASS |
| No `eval()`, `exec()`, `os.system()` in TUI module | PASS |
| No `shell=True` in TUI module | PASS |
| No imports from analysis modules (hunter, auditor, etc.) | PASS |
| Project name sanitization strips `[^a-zA-Z0-9._-]`, rejects `..` and `/`, max 64 chars | PASS |
| `DCS_OUTPUT_DIR` not in `shared/config.py` | PASS |
| `shared/config.py` unmodified | PASS |
| File paths for platform opener are deterministic (not user-controlled at invocation) | PASS |
| `meta.json` read via `json.loads()` + Pydantic validation (not `yaml.load()`) | PASS |
| All subprocess calls use list-form arguments | PASS |

---

## Files Reviewed

**Source files:**
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/__init__.py`
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/models.py`
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/storage.py`
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/runner.py`
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/app.py`
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/__init__.py`
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/target_select.py`
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/scan_config.py`
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/scan_progress.py`
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/results_view.py`
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/tui/screens/history.py`

**Modified files:**
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/cli.py` (lines 1125-1139)
- `/Users/imurphy/projects/deep-code-security/pyproject.toml` (line 43, lines 120-122)
- `/Users/imurphy/projects/deep-code-security/Makefile` (lines 1-2, 74-78)
- `/Users/imurphy/projects/deep-code-security/CLAUDE.md` (architecture, CLI, env vars, dev commands)

**Test files:**
- `/Users/imurphy/projects/deep-code-security/tests/test_tui/__init__.py`
- `/Users/imurphy/projects/deep-code-security/tests/test_tui/conftest.py`
- `/Users/imurphy/projects/deep-code-security/tests/test_tui/test_models.py`
- `/Users/imurphy/projects/deep-code-security/tests/test_tui/test_storage.py`
- `/Users/imurphy/projects/deep-code-security/tests/test_tui/test_runner.py`
- `/Users/imurphy/projects/deep-code-security/tests/test_tui/test_runner_patterns.py`
- `/Users/imurphy/projects/deep-code-security/tests/test_tui/test_app.py`

---

## Recommendation

**FAIL.** Two blocking defects must be resolved before this can ship:

1. **B-1:** Add `storage.write_meta(run_dir, meta)` to `ScanProgressScreen._run_scan()` after `runner.run()` returns, and pass `run_dir` to the scan complete handler.
2. **B-2:** Push `ResultsViewScreen` automatically on scan completion instead of relying on Escape (which navigates back, not forward).

After fixing B-1 and B-2, the 10 lint violations (N-1) should also be cleaned up to meet AC #21 fully. Alternatively, if `make lint` was already failing before this change, AC #21 could be reclassified as pre-existing with only the new TUI violations needing fixes.
