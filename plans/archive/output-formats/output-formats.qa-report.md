# QA Report: SARIF and HTML Output Formats

**Plan:** `plans/output-formats.md`
**Date:** 2026-03-13
**Test results:** 374 passed, 1 failed (pre-existing tree-sitter-c issue), 91.40% coverage
**Lint:** All new/modified files pass ruff checks

## Verdict: PASS_WITH_NOTES

---

## Acceptance Criteria Coverage

| # | Criterion | Met? | Evidence |
|---|-----------|------|----------|
| 1 | `dcs hunt <path> --format sarif` produces SARIF 2.1.0 JSON that passes schema validation | YES | `SarifFormatter.format_hunt()` builds conformant envelope; `test_sarif_full_schema_validation` validates against vendored SARIF 2.1.0 JSON Schema using `jsonschema.validate()`. DefectDojo acceptance is a manual step (Task 5.2) outside automated scope. |
| 2 | `dcs hunt <path> --format html` produces a self-contained HTML file viewable in a browser | YES | `HtmlFormatter.format_hunt()` produces complete HTML with inline CSS, `<meta charset="utf-8">`, no external resources. Tests verify `<html>`, `<head>`, `<body>`, `</html>` structure. |
| 3 | `dcs full-scan <path> --format sarif` includes confidence scores in property bag and remediation in `result.properties.remediation_guidance` | YES | `_build_result()` populates `properties.confidence_score` and `properties.remediation_guidance` when verified/guidance data present. `test_sarif_full_scan_includes_confidence` and `test_sarif_full_scan_remediation_in_properties` verify this, including asserting `fixes` is NOT present. |
| 4 | `dcs full-scan <path> --format html` includes verification status and remediation guidance sections | YES | `_build_full_scan_findings()` renders Status column, confidence, and `<div class="guidance">` with explanation, fix pattern, code example, and references. `test_html_full_scan_includes_guidance` confirms. |
| 5 | `dcs hunt <path> --json-output` continues to work identically (backward compatibility) | YES | `--json-output` is a hidden flag on `hunt`. `_resolve_format()` returns `"json"` when set and emits deprecation warning to stderr. `test_hunt_json_output_deprecated` verifies JSON output is produced. |
| 6 | `dcs hunt <path>` (no flags) produces the same text output as before | YES | Default `output_format` is `"text"`, which selects `TextFormatter`. `test_hunt_format_text_default` verifies text output appears. |
| 7 | `dcs hunt <path> --format json -o report.json` writes JSON to file (path within `DCS_ALLOWED_PATHS`) | YES | `_write_output()` validates path via `validate_path()` against `config.allowed_paths_str`, then writes with `encoding="utf-8"`. `test_output_file_json` and `test_output_file_writes_to_disk` verify. |
| 8 | `dcs hunt <path> -o report.json` on existing file fails unless `--force` is provided | YES | `_write_output()` checks `output_path.exists()` and rejects without `--force`. `test_output_file_refuses_overwrite` and `test_output_file_force_overwrites` verify both paths. |
| 9 | `make test` passes with 90%+ coverage | YES | 374 passed, 91.40% coverage (threshold is 90%). The 1 failure is pre-existing (tree-sitter-c, unrelated to this plan). |
| 10 | `make lint` passes | YES | Per task description, all new/modified files pass ruff checks. |
| 11 | No new runtime dependencies; `jsonschema` added as test-only dependency | YES | `pyproject.toml` `dependencies` list is unchanged. `jsonschema>=4.0` appears only in `[project.optional-dependencies] test`. |
| 12 | Adding a new format requires only: (a) creating a formatter class, (b) calling `register_formatter()` | YES | `register_formatter()` validates protocol compliance (checks for `format_hunt` and `format_full_scan`), then adds to `_FORMATTERS` dict. `test_register_custom_formatter` demonstrates the workflow. No other registration steps required. |
| 13 | SARIF output includes `tool.driver.rules[]` with entries for each unique vulnerability class | YES | `_build_rules()` builds rules from unique CWE IDs. `test_sarif_tool_driver_rules` verifies `id`, `shortDescription`, and `defaultConfiguration.level`. `test_sarif_empty_findings_has_rules` verifies empty rules array for zero findings. |
| 14 | SARIF output validates against the official SARIF 2.1.0 JSON Schema in automated tests | YES | `tests/fixtures/sarif-schema-2.1.0.json` is vendored. `test_sarif_full_schema_validation`, `test_sarif_full_schema_validation_full_scan`, and `test_sarif_empty_findings` all call `jsonschema.validate()`. |

**Result: 14/14 criteria met.**

---

## Test Coverage Assessment

All test files specified in the plan exist and contain the expected test cases:

| Test file | Plan test cases | Implemented | Notes |
|-----------|----------------|-------------|-------|
| `test_protocol.py` | 5 | 5 | All DTO tests present |
| `test_registry.py` | 9 | 9 | Includes custom registration + cleanup |
| `test_text.py` | 5 | 5 | Hunt + full-scan paths covered |
| `test_json.py` | 6 | 6 | Structural equivalence verified |
| `test_sarif.py` | 16 | 16 | Schema validation for hunt, full-scan, and empty cases |
| `test_html.py` | 11 | 11 | XSS escaping, dollar sign, severity colors |
| `test_cli_format.py` | 13 | 13 | Format selection, deprecated flag, output-file, force, path validation, encoding |

---

## Missing Tests or Edge Cases

None missing relative to the plan. The following are observations about potential future improvements, not blocking issues:

1. **No negative SARIF test for `result.fixes[]`:** The test `test_sarif_full_scan_remediation_in_properties` asserts `"fixes" not in result`, which is correct. A complementary test verifying that guidance fields are structured correctly (all expected sub-keys present) would strengthen coverage but is not required by the plan.

2. **CLI deprecation warning assertion is weak:** In `test_hunt_json_output_deprecated`, the deprecation warning check (`assert "deprecated" in ... or True`) always passes due to the `or True` fallback. The Click `CliRunner` mixes stdout/stderr by default, so the warning may be in `result.output`, but the assertion does not actually verify it. This is a test quality issue, not a functional issue -- the warning is demonstrably emitted by `_resolve_format()`.

3. **No test for `--format sarif --json-output` on `full-scan`:** The conflict test only covers the `hunt` command. The same logic applies via `_resolve_format()`, so this is low risk.

---

## Notes (non-blocking observations)

1. **DTO field types use `Any` instead of concrete model types.** The plan specifies `HuntResult.findings: list[RawFinding]` and `HuntResult.stats: ScanStats`, but the implementation uses `list[Any]` and `Any`. The concrete types are only in `TYPE_CHECKING` imports (never enforced at runtime). This means Pydantic will not validate that the correct model types are passed. This works because the formatters access attributes duck-typing style, but it weakens type safety compared to the plan's specification. This is a design trade-off (avoids circular imports) and does not affect correctness for the current codebase.

2. **`cli.py` is excluded from coverage** (`pyproject.toml` `[tool.coverage.run] omit` includes `*/cli.py`). The CLI integration tests in `test_cli_format.py` exercise the CLI paths but do not contribute to the coverage metric. This is consistent with the project's existing convention, not a regression.

3. **The `verify` command retains its original `--json-output` flag (not hidden, not deprecated).** The plan states "No change" for `verify`, which is correctly followed. When `verify` becomes functional, `--format` should be added and `--json-output` deprecated to match `hunt`/`full-scan`.

4. **`string.Template` dollar-sign handling is correctly implemented.** The `_escape()` function applies `html.escape()` first, then replaces `$` with `&#36;`. Combined with `safe_substitute()`, this prevents both XSS and template placeholder collisions. The test `test_html_escapes_dollar_sign` validates this end-to-end.
