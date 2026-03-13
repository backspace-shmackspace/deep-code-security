# Feasibility Review: SARIF and HTML Output Formats (Second Review)

**Plan:** `plans/output-formats.md`
**Reviewer:** code-reviewer agent
**Date:** 2026-03-13
**Review round:** 2

## Verdict: PASS

All four Major concerns from the first review (M1-M4) and all six Minor concerns (m1-m6) have been resolved in the revised plan. The remaining concerns below are new findings from the second review. None are blocking.

---

## Resolution of Previous Concerns

| Previous ID | Status | How Resolved |
|-------------|--------|-------------|
| M1 (string.Template insufficient) | **Resolved** | Plan now specifies hybrid approach: skeleton-only template with programmatic section construction using `html.escape()`. |
| M2 (SARIF fixes[] misused) | **Resolved** | Remediation mapped to `result.properties.remediation_guidance` with clear rationale against `fixes[]`. |
| M3 (Missing SARIF rules[]) | **Resolved** | Detailed `tool.driver.rules[]` specification added with `id`, `shortDescription`, `defaultConfiguration.level`, and `properties.tags`. |
| M4 ($ in user content) | **Resolved** | Plan specifies `$` -> `&#36;` replacement after `html.escape()`, plus `safe_substitute()` as defense-in-depth. Repeating sections bypass template entirely. |
| m1 (SUPPORTED_FORMATS mutation) | **Resolved** | Replaced with `get_supported_formats()` computed dynamically from registry. |
| m2 (Adversarial HTML tests) | **Resolved** | Added `test_html_escapes_quotes`, `test_html_escapes_ampersand`, `test_html_escapes_dollar_sign`. |
| m3 (No --format on verify) | **Resolved** | Noted in CLI Option Changes table with explicit "when verify becomes functional" note. |
| m4 (byte-identical JSON) | **Resolved** | Changed to "structurally equivalent" with explicit note about key ordering. |
| m5 (encoding) | **Resolved** | `encoding="utf-8"` specified for `Path.write_text()` and `<meta charset="utf-8">` in HTML output. |
| m6 (OSError handling) | **Resolved** | Added to CLI integration: catch `OSError`, report to stderr with non-zero exit code. |

---

## Critical Concerns

None.

---

## Major Concerns

None.

---

## Minor Concerns

### m1. Formatter Protocol signature lacks `target_path` parameter

**Problem:** The plan states that SARIF and HTML formatters need `target_path` (for relative URIs and report headers), and that DTOs intentionally omit it. The plan says formatters "receive it separately via the formatter method signature (see CLI Integration below)." However, the `Formatter` Protocol definition shows:

```python
def format_hunt(self, data: HuntResult) -> str: ...
def format_full_scan(self, data: FullScanResult) -> str: ...
```

Neither method accepts a `target_path` parameter. The CLI Integration section (Task 4.1) does not show the revised signature either. This is an interface gap: the SARIF formatter needs target_path to compute `run.originalUriBaseIds` and relative artifact URIs, and the HTML formatter needs it for the report header.

**Recommendation:** Either add `target_path: str | None = None` to the Protocol method signatures, or add it to the DTOs as an optional field. The former is cleaner since it preserves the DTO's data-only nature (target_path is context, not scan data). Update the Protocol definition in the plan to match.

### m2. `register_formatter` error message references nonexistent `override=True` parameter

**Problem:** The `register_formatter` function raises `ValueError` with the message "Use override=True to replace it" but the function signature has no `override` parameter. This will confuse callers who read the error message and try to pass `override=True`.

**Recommendation:** Either add an `override: bool = False` parameter to enable re-registration, or change the error message to instruct callers to use a different name or to document how to replace a built-in formatter.

### m3. `_register_builtins()` at module import time may conflict with test isolation

**Problem:** `_register_builtins()` is called at module scope in `__init__.py`, and `register_formatter()` rejects duplicate names. If tests reload the module, monkeypatch the registry, or import it from multiple test files in the same process, the duplicate check will raise `ValueError`. The `test_register_duplicate_raises` test case verifies this behavior, but it also means test cleanup must explicitly remove entries from `_FORMATTERS` after custom registration tests.

**Recommendation:** Consider making `register_formatter()` idempotent when re-registering the same class (only raise on registering a *different* class under the same name). Alternatively, document that tests needing a clean registry should save/restore `_FORMATTERS` in a fixture.

### m4. `click.Choice` hardcodes format names instead of using `get_supported_formats()`

**Problem:** The CLI shows `type=click.Choice(["text", "json", "sarif", "html"])` rather than `type=click.Choice(get_supported_formats())`. This means custom formatters registered via `register_formatter()` will not appear in the CLI choices, undermining the extensibility claim.

**Recommendation:** Use `get_supported_formats()` as the source for `click.Choice`. Note that Click evaluates the `type` argument at decoration time, so this works correctly as long as `_register_builtins()` has already run (which it does at import time). This is a minor ergonomic improvement and does not block approval.

### m5. `--force` flag is meaningless without `--output-file`

**Problem:** The plan adds `--force` to both `hunt` and `full-scan` commands, but `--force` only governs overwrite behavior for `--output-file`. When `--force` is provided without `--output-file`, it silently does nothing. This is mildly confusing.

**Recommendation:** Either make `--force` a sub-option of `--output-file` (Click does not natively support this, but you can validate in the callback), or document that `--force` is ignored without `--output-file`. The simplest approach is to emit a warning to stderr if `--force` is used without `--output-file`.

---

## What the Plan Gets Right

1. **All previous concerns comprehensively addressed.** Each of the four Major and six Minor concerns from the first review was resolved with specific, well-reasoned changes rather than dismissals.

2. **HTML template architecture is now realistic.** The hybrid approach (skeleton via `string.Template`, repeating sections built programmatically) accurately describes what the implementation will look like. The dollar-sign escaping sequence (`html.escape()` first, then `$` -> `&#36;`, then `safe_substitute()`) is correct and well-ordered.

3. **SARIF specification is now DefectDojo-ready.** The addition of `tool.driver.rules[]`, the move from `fixes[]` to `result.properties.remediation_guidance`, and the CWE taxa reference together form a complete SARIF mapping that should import cleanly into DefectDojo.

4. **Security posture remains strong.** Output path validation through `PathValidator`, `html.escape()` on all interpolated values, no new runtime dependencies, and the `Jinja2 SandboxedEnvironment` deviation rationale are all sound.

5. **Backward compatibility handling is thorough.** The `--json-output` deprecation path, the "structurally equivalent" JSON standard, and the explicit note about not adding `target_path` to DTOs to avoid breaking changes demonstrate careful thinking about existing consumers.

6. **Test plan is comprehensive and adversarial.** The addition of HTML escaping tests for quotes, ampersands, and dollar signs addresses the XSS surface area. The SARIF schema validation test against the vendored JSON Schema is the right approach.

7. **Memory analysis is well-scoped.** The table of typical/maximum output sizes per format provides concrete evidence that the single-string return pattern is acceptable at `DCS_MAX_RESULTS=100`.

---

## Complexity Estimates

| Task | Plan Implies | Realistic Estimate | Notes |
|------|-------------|-------------------|-------|
| Protocol + Registry + DTOs | Small | Small | Straightforward. The `target_path` gap (m1) adds a minor design decision but no significant work. |
| TextFormatter | Small | Small | Direct extraction from `cli.py` lines 81-93 and 231-237. |
| JsonFormatter | Small | Small | Wraps existing `serialize_model`/`serialize_models`. |
| SarifFormatter | Medium | Medium | Now well-specified with `rules[]`, `codeFlows`, `taxa`, and property bag. The specification reduces implementation ambiguity compared to the first draft. |
| HtmlFormatter | Medium | Medium | The hybrid approach is realistic. Main effort is the programmatic row construction with proper escaping. |
| CLI refactor | Small | Small-Medium | Click option changes are simple. DTO construction from existing scan results requires mapping the inline logic from `cli.py`. |

Overall complexity estimates are now realistic. The plan improvements from the first review have reduced implementation ambiguity, particularly for the SARIF and HTML formatters.

---

## Recommended Adjustments

1. **[m1]** Add `target_path: str | None = None` to the `format_hunt` and `format_full_scan` Protocol signatures, or add it as an optional field on the DTOs.
2. **[m2]** Fix the `register_formatter` error message to not reference a nonexistent `override` parameter.
3. **[m3]** Make `register_formatter` idempotent for same-class re-registration, or document test fixture requirements for registry cleanup.
4. **[m4]** Use `get_supported_formats()` in the `click.Choice` definition for consistency with the extensibility design.
5. **[m5]** Add a note that `--force` without `--output-file` is ignored (or emit a warning).
