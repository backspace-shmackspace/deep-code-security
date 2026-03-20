# Review: c-func-param-taint-sources.md (Round 2)

**Round:** 2 (revised plan)
**Reviewer:** Claude (automated plan review)
**Date:** 2026-03-20
**Verdict:** PASS

## Verification of Round 1 Required Edits

### RE-1: `src/deep_code_security/hunter/__init__.py` added to Files to Modify

**Status:** RESOLVED

Evidence:
- Files to Modify table, row #14: `src/deep_code_security/hunter/__init__.py` with change description "Add `param_source_extractor` to imports and `__all__`".
- WG1 (Core Logic) work group includes File #14, correctly grouped with the other hunter package files.
- Context Alignment table row for `__all__` in `__init__.py` pattern explicitly states: "New module `param_source_extractor.py` has `__all__`; `hunter/__init__.py` updated to include it."

All three locations are consistent and complete.

### RE-2: TUI scan config integration added to Non-Goals with explicit deferral

**Status:** RESOLVED

Evidence:
- Non-Goals section includes a dedicated bullet: "**TUI scan config integration.** The `--c-param-sources` CLI flag works when the TUI invokes CLI commands via subprocess, but the TUI scan configuration screen (`src/deep_code_security/tui/screens/`) will not expose a toggle for library mode. Users can set `DCS_C_PARAM_SOURCES=on` in their environment to activate the feature through the TUI. Adding a TUI checkbox is deferred because the TUI wraps CLI via subprocess and the environment variable path works without TUI code changes."
- The rationale is sound: the TUI wraps CLI via subprocess (confirmed by CLAUDE.md architecture section), so the environment variable path provides full functionality without TUI code changes.

### RE-3: `DCS_C_PARAM_SOURCES` description lists accepted truthy values

**Status:** RESOLVED

Evidence:
- Goals section (line 8): "...when set to `on`, `true`, `yes`, or `1`..."
- Proposed Design Section 1 (lines 42-45): "Any value not in the truthy set (`on`, `true`, `yes`, `1`, case-insensitive) is treated as off."
- Code snippet (lines 51-53): `.lower() in ("1", "true", "yes", "on")` -- matches the documented values.
- Environment Variable table (lines 540-542): Dedicated "Accepted Truthy Values" column with "`on`, `true`, `yes`, `1` (case-insensitive)".
- Default is described as "(empty/off)" -- consistent across all three locations.

The Round 1 inconsistency (table said "off" as default but code just treated anything not in the truthy set as off) is fully resolved. The description is now precise and self-consistent in all locations.

## CLAUDE.md Compliance

| CLAUDE.md Rule | Plan Compliance | Status |
|---|---|---|
| `yaml.safe_load()` only | No new YAML loading code. Existing registry loading uses `yaml.safe_load()`. New Semgrep rule file (`param-sources.yaml`) is loaded by the Semgrep CLI, not by Python code. | PASS |
| Never `eval()`, `exec()`, `os.system()`, `subprocess.run(shell=True)` | No new eval/exec/system usage. No new subprocess calls. The Semgrep backend's existing `subprocess.run()` call (list-form) is extended with an additional `--config` argument, not a new subprocess invocation. | PASS |
| All subprocess calls use list-form arguments | No new subprocess calls. The Semgrep backend modification adds `--config` as a list element to the existing list-form command. | PASS |
| All file paths validated through `mcp/path_validator.py` | The `c_param_sources` MCP parameter is a boolean, not a path. No new file path handling in MCP tools. File paths in the hunter pipeline use the existing validated pipeline. | PASS |
| Pydantic v2 for data-crossing models | No new models. Uses existing `Source` model with new `category` value `"func_param"`. The `Source.category` field already accepts arbitrary strings. | PASS |
| Type hints on all public functions | All new public functions in the code snippets have full type hints: `extract_param_sources(tree: Any, file_path: str) -> list[Source]`, etc. | PASS |
| `__all__` in `__init__.py` files | New module `param_source_extractor.py` defines `__all__ = ["extract_param_sources"]`. Plan includes File #14 to update `hunter/__init__.py` with the new module in `__all__`. | PASS |
| `pathlib.Path` over `os.path` | The `extract_param_sources()` function accepts `file_path: str` because the existing `Source.file` field is `str`. This is a pragmatic choice to match the downstream model, not a violation of the `pathlib.Path` preference. No `os.path` calls are introduced. | PASS (minor note) |
| No mutable default arguments | All default arguments in new code are immutable (`False`, `None`). The `sources` parameter in internal functions is passed by the caller, not defaulted. | PASS |
| Registries in YAML files, never hardcoded in Python | New Semgrep rule in `registries/semgrep/c-param-sources/param-sources.yaml`. No hardcoded source/sink definitions in Python code. The `_MIN_PARAM_NAME_LENGTH` constant and `argc` exclusion are configuration constants, not registry data. | PASS |
| `models.py` per phase | No new models created. Existing `Source` model reused. | PASS |
| 90%+ test coverage | Comprehensive test plan: 16 unit tests, 10 integration tests, 3 config tests, 2 CLI tests, 3 node-type verification tests. All new code paths covered. | PASS |
| Intraprocedural taint only (v1) | Explicitly stated in Non-Goals: "This plan stays within the v1 intraprocedural boundary." Parameter sources seed taint within the declaring function only. | PASS |
| `orchestrator.py` per phase | Changes to `hunter/orchestrator.py` follow the existing pattern (new parameter passed through to backend). | PASS |
| Test fixtures in `tests/fixtures/` | Three new fixtures in correct locations: `tests/fixtures/vulnerable_samples/c/lib_parser.c`, `tests/fixtures/vulnerable_samples/c/lib_logger.c`, `tests/fixtures/safe_samples/c/lib_safe.c`. | PASS |
| Environment variable pattern | `DCS_C_PARAM_SOURCES` follows the established `DCS_` prefix convention. Parsing in `shared/config.py` follows the same pattern as other boolean env vars. | PASS |
| Container security (seccomp, no-new-privileges, cap-drop) | Not applicable -- this plan does not touch container operations. | N/A |
| Jinja2 SandboxedEnvironment | Not applicable -- this plan does not touch PoC template rendering. | N/A |
| `mcp/input_validator.py` validates RawFinding fields | Not applicable -- `c_param_sources` is a boolean parameter, not a finding field. MCP input validation is unchanged. | N/A |

## New Issues (if any)

No new CLAUDE.md conflicts were introduced by the revisions. The three additions (File #14 in Files to Modify and WG1, TUI non-goal, truthy value documentation) are all clean and consistent with CLAUDE.md rules and existing project patterns.

One observation on the revisions that does NOT constitute a conflict:
- The TUI non-goal entry (line 24) is notably thorough -- it explains both why the feature works without TUI changes (environment variable path) and why a TUI checkbox is deferred (subprocess wrapping makes env vars sufficient). This level of detail in Non-Goals is appreciated and reduces future ambiguity.

## Optional Suggestions

These are carried forward from Round 1 where still applicable. None block PASS.

- **Conditional-assignment sanitizer interaction note.** The plan does not mention that parameter-source findings for CWE-119/CWE-120/CWE-190 will interact correctly with the existing conditional-assignment sanitizer (bounds clamps between parameter declaration and sink reduce confidence from "confirmed" to "likely"). This interaction is correct by construction but a one-sentence note in the Risks section would improve clarity for implementers.

- **Future-proofing `ScannerBackend.scan_files()` protocol.** The plan acknowledges adding `c_param_sources` as a feature-specific parameter to the protocol. If future plans add similar flags (Go parameter sources, cross-file analysis), a `ScanOptions` dataclass bundling all optional scan parameters would be a cleaner protocol extension. Not required for this plan.

- **`file_path: str` vs `Path` in `extract_param_sources()`.** The function accepts `str` because `Source.file` is `str`. Accepting `Path` and converting at `Source` construction would be marginally more consistent with the `pathlib.Path` preference, but this is a stylistic preference, not a rule violation.
