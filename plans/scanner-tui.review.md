# Review: scanner-tui.md (Revision 2)

**Plan:** `./plans/scanner-tui.md`
**Reviewed:** 2026-03-20 (revision 2)
**Prior review:** 2026-03-20 (revision 1) -- PASS with 2 required edits (R-1, R-2)
**Verdict:** PASS

---

## Prior Required Edits -- Resolution Status

### R-1: Acknowledge Windows `start` command deviation -- RESOLVED

The revised plan now explicitly specifies `os.startfile(file_path)` on Windows (plan line 378), explains why it is preferred over `start` (which is a `cmd.exe` builtin, not a standalone executable -- plan lines 379-380), and confirms no `shell=True` is used on any platform (plan line 382). The Platform File Opener section (lines 374-382) fully addresses the concern.

### R-2: Acknowledge `DCS_OUTPUT_DIR` path validation deviation -- RESOLVED

The revised plan adds Deviation D-4 (plan lines 961-963) explicitly acknowledging that `DCS_OUTPUT_DIR` write paths bypass `path_validator.py`. The justification is clear: `path_validator.py` enforces the MCP trust boundary, the TUI is a local tool with no external trust boundary, and write paths are programmatically constructed from sanitized project names (regex `[^a-zA-Z0-9._-]`, no `..`, no `/`, max 64 chars) and generated timestamps.

---

## Conflicts with CLAUDE.md

None found. All rules are satisfied.

| CLAUDE.md Rule | Status | Notes |
|---|---|---|
| Never `yaml.load()` -- always `yaml.safe_load()` | Compliant | TUI uses `json.loads()` for `meta.json`. No YAML loading anywhere in the TUI module. |
| Never `eval()`, `exec()`, `shell=True` | Compliant | `ScanRunner` uses `asyncio.create_subprocess_exec()` with list-form arguments. Windows file opener uses `os.startfile()` (stdlib, no subprocess). No `shell=True` on any platform. |
| All subprocess calls use list-form arguments | Compliant | `build_command()` returns `list[str]`. Acceptance criterion 17 explicitly prohibits `shell=True`. macOS/Linux file openers use `create_subprocess_exec("open", path)` / `create_subprocess_exec("xdg-open", path)`. |
| All file paths validated through `mcp/path_validator.py` | Acknowledged deviation (D-4) | Scan target paths are validated by the `dcs` subprocess (delegated correctly). Report storage write paths under `DCS_OUTPUT_DIR` bypass `path_validator.py` -- justified because that module enforces the MCP trust boundary, not local tool writes. Write paths are programmatically constructed from sanitized inputs. |
| All container operations enforce full security policy | N/A | TUI does not interact with containers. |
| Jinja2 SandboxedEnvironment for PoC templates | N/A | TUI does not render PoC templates. |
| `mcp/input_validator.py` validates RawFinding fields | N/A | TUI does not process RawFinding objects. |
| Pydantic v2 for all data-crossing models | Compliant | `RunMeta` and `ScanConfig` are Pydantic `BaseModel` subclasses with `Field()` definitions. |
| Type hints on all public functions | Compliant | All public methods in `ReportStorage`, `ScanRunner`, and `DCSApp` are fully typed (documented in plan with return types and parameter types). |
| `__all__` in `__init__.py` files | Compliant | Both `tui/__init__.py` and `tui/screens/__init__.py` specified with exports (Task 1.1). |
| pathlib.Path over os.path | Compliant | All path handling uses `Path`. `DCS_OUTPUT_DIR` uses `Path.expanduser()`. |
| No mutable default arguments | Compliant | All list fields use `Field(default_factory=list)`. |
| 90%+ test coverage | Compliant | Textual-dependent files (`app.py`, `screens/*.py`) excluded from main coverage. Pure-Python TUI files (`models.py`, `storage.py`, `runner.py`) are included in main `make test` coverage gate. Separate `make test-tui` target for Textual-dependent tests. |
| `models.py` per phase | Compliant | `tui/models.py` contains `RunMeta` and `ScanConfig`. |
| `orchestrator.py` per phase | Acknowledged deviation | TUI entry point is `app.py`, not `orchestrator.py`. The TUI is a presentation layer, not an analysis phase. Justified and noted in Context Alignment section. |
| Registries in YAML files, never hardcoded | N/A | No new registries. |

---

## Historical Alignment Issues

- **Context Alignment section is substantive (PASS).** Contains a 12-item CLAUDE.md patterns checklist, a 4-entry Prior Plans list (output-formats.md, sast-to-fuzz-pipeline.md, semgrep-scanner-backend.md, suppressions-file.md), and a 5-entry Deviations list (D-1 through D-5), each with justification.
- **Context metadata block present (PASS).** Includes `claude_md_exists: true`, `recent_plans_consulted` (3 plans), `archived_plans_consulted` (2 plans).
- **Consistent with output-formats.md (PASS).** The TUI reuses the existing formatter registry. The revised plan now runs the scan once with `--format json` and derives SARIF/HTML in-process via `shared.formatters.get_formatter()` (Deviation D-3). The `supports_hybrid()` helper in `shared/formatters/__init__.py` exists to check `format_hunt_fuzz` availability before calling it, which the runner should use since `HtmlFormatter` lacks `format_hunt_fuzz()`.
- **Consistent with sast-to-fuzz-pipeline.md (PASS).** `hunt-fuzz` supported as a scan type. `--consent` flag handling documented.
- **Consistent with suppressions-file.md (PASS).** `--ignore-suppressions` exposed as a `Switch` toggle in `ScanConfigScreen`.
- **Consistent with semgrep-scanner-backend.md (PASS).** `backend_used` extracted from `output["stats"]["scanner_backend"]` (hunt), `output["hunt_stats"]["scanner_backend"]` (full-scan), `output["hunt_result"]["stats"]["scanner_backend"]` (hunt-fuzz). Verified against `shared/formatters/json.py` -- all extraction paths are correct.
- **Architect output remains guidance-only (PASS).** Non-goal: "Editing source code or applying patches."
- **MCP deployment not affected (PASS).** Non-goal: "New MCP tools."
- **Fuzzer consent handling consistent (PASS).** Non-goal: "The TUI does not auto-consent to API transmission."
- **No contradiction with conditional-assignment-sanitizer.md (PASS).** No overlap with hunter/taint tracker logic.
- **CLAUDE.md update task present (PASS).** Task 5.3 covers architecture diagram, CLI commands, env vars, and dev commands updates.
- **`DCS_OUTPUT_DIR` vs `DCS_FUZZ_OUTPUT_DIR` naming (Informational).** Both exist with different defaults (`~/.dcs/reports/` vs `./fuzzy-output`) and scopes (TUI-only vs fuzzer). Not a conflict but worth documenting the distinction in Task 5.3.
- **Prior C-3 (extra_args) eliminated (PASS).** The revised plan removes `extra_args` entirely from `ScanConfig`, adds "Free-form CLI argument pass-through" as an explicit non-goal (plan line 23), and documents "No free-form `extra_args`" as a key design decision (plan line 296). Prior S-4 suggestion is no longer applicable.
- **Prior S-1 (single-invocation) adopted (PASS).** The revised plan runs the scan once with `--format json` and converts to SARIF/HTML in-process using `shared.formatters` (Deviation D-3). This eliminates the 200% time penalty identified in the prior review.
- **JSON extraction paths verified against codebase (PASS).** `findings_count` paths: `output["total_count"]` (hunt), `output["total_count"]` (full-scan), `output["hunt_result"]["total_count"]` (hunt-fuzz), `output["summary"]["unique_crash_count"]` (fuzz) -- all match `shared/formatters/json.py`. `backend_used` paths: `output["stats"]["scanner_backend"]` (hunt), `output["hunt_stats"]["scanner_backend"]` (full-scan), `output["hunt_result"]["stats"]["scanner_backend"]` (hunt-fuzz) -- all match `shared/formatters/json.py`.

---

## Required Edits

None.

---

## Optional Suggestions

### S-1: Use `supports_hybrid()` before calling `format_hunt_fuzz()`

The runner should call `shared.formatters.supports_hybrid(formatter)` before invoking `format_hunt_fuzz()` on a formatter instance. Currently `HtmlFormatter` does not implement `format_hunt_fuzz()`, so calling it on the HTML formatter for hunt-fuzz scans would raise `AttributeError`. The plan acknowledges format conversion can fail (plan line 294: "the runner logs a warning and continues"), so the try-except fallback handles this. However, using the existing `supports_hybrid()` check is cleaner than relying on exception handling for expected cases. This is a minor implementation concern, not a plan-level issue.

### S-2: Add `DCS_OUTPUT_DIR` to `dcs status` output

Carried forward from prior review. The `dcs status` command reports registry paths, allowed paths, and backend info. Adding `DCS_OUTPUT_DIR` (resolved path) would help users debug report storage issues.

### S-3: Document `DCS_OUTPUT_DIR` vs `DCS_FUZZ_OUTPUT_DIR` distinction

Carried forward from prior review. In the CLAUDE.md update task (Task 5.3), add a note in the environment variables table clarifying that `DCS_OUTPUT_DIR` is for TUI report history while `DCS_FUZZ_OUTPUT_DIR` is for fuzzer corpus and runtime output.

---

**Reviewer:** Librarian (automated)
**Plan status:** DRAFT -- approved for implementation. No required edits remain.
