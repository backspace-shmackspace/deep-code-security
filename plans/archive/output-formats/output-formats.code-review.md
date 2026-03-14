# Code Review: SARIF and HTML Output Formats

**Reviewer:** code-reviewer agent v1.0.0
**Date:** 2026-03-13
**Plan:** `plans/output-formats.md` (APPROVED)

## Verdict: REVISION_NEEDED

The implementation is solid overall and follows the plan faithfully. The security-relevant areas (HTML escaping, path validation, output file handling) are well-implemented. However, there are several Major findings around type safety deviations from the plan and a correctness issue in the SARIF formatter that should be addressed before merging.

---

## Critical Findings (Must Fix)

None.

---

## Major Findings (Should Fix)

### M1. DTOs use `Any` instead of typed fields as specified in the plan

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/formatters/protocol.py`, lines 22-40

The plan specifies typed Pydantic models:

```python
findings: list[RawFinding] = Field(default_factory=list)
stats: ScanStats
```

The implementation uses `Any` for all fields:

```python
findings: list[Any] = Field(default_factory=list)
stats: Any = None
```

This eliminates Pydantic's runtime validation, which is the entire point of using Pydantic DTOs for "data crossing boundaries" (per CLAUDE.md). A malformed dict passed as `stats` would not be caught until it reaches a formatter and causes an `AttributeError` deep in rendering code, producing an unhelpful error message.

The `TYPE_CHECKING` guard on the imports suggests this was done to avoid circular imports, but the actual model types (`RawFinding`, `ScanStats`, etc.) are in `hunter/models.py`, `auditor/models.py`, and `architect/models.py` -- none of which import from `shared/formatters/`, so there is no circular dependency risk. The imports should be unconditional and the types should be concrete.

**Recommendation:** Remove the `TYPE_CHECKING` guard and use the concrete Pydantic types as specified in the plan. At minimum, `stats: ScanStats` (not `Any = None`) since the TextFormatter unconditionally accesses `data.stats.files_scanned` and will crash with `AttributeError: 'NoneType' has no attribute 'files_scanned'` if `stats` is `None`.

### M2. SARIF `originalUriBaseIds` URI construction is platform-dependent

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/formatters/sarif.py`, lines 261-264

```python
run["originalUriBaseIds"] = {
    "SRCROOT": {
        "uri": "file:///" + target_path.lstrip("/") + "/",
    }
}
```

This produces `file:///tmp/project/` on Unix, which is correct. However, on Windows the path would be something like `C:\Users\...` which would produce `file:///C:\Users\...` -- an invalid `file:` URI. While the project currently targets Unix containers, the SARIF spec requires valid URIs. More critically, `os.path.relpath` in `_make_relative_uri` (line 54) also uses OS-native separators which are then converted via `replace(os.sep, "/")`, but the base URI is not handled symmetrically.

**Recommendation:** Use `pathlib.PurePosixPath` or `urllib.parse.urljoin` to construct the file URI properly. This also aligns with the CLAUDE.md mandate of "`pathlib.Path` over `os.path` where appropriate."

### M3. `_make_relative_uri` uses `os.path.relpath` instead of `pathlib`

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/formatters/sarif.py`, lines 49-57

```python
def _make_relative_uri(file_path: str, target_path: str) -> str:
    ...
    rel = os.path.relpath(file_path, target_path)
    return rel.replace(os.sep, "/")
```

CLAUDE.md states: "`pathlib.Path` over `os.path` where appropriate." This is a good fit for `pathlib` since `Path.relative_to()` or `PurePosixPath` would be clearer. Additionally, `os.path.relpath` can produce paths starting with `..` if the file is outside the target directory, which would create misleading SARIF URIs.

**Recommendation:** Use `pathlib.Path(file_path).relative_to(target_path)` with a try/except fallback, and validate the result does not escape the target root.

### M4. `register_formatter` error message mentions `override=True` parameter that does not exist

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/formatters/__init__.py`, lines 25-29

```python
raise ValueError(
    f"Formatter {name!r} is already registered. "
    f"Use override=True to replace it."
)
```

The `register_formatter` function has no `override` parameter. This is misleading to users who read the error message.

**Recommendation:** Either add the `override` parameter or change the error message to remove the reference.

---

## Minor Findings (Consider)

### m1. `get_formatter` return type annotation missing on `shared/__init__.py` wrapper

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/__init__.py`, line 20

```python
def get_formatter(name: str):  # noqa: ANN201
```

The `noqa` suppresses the missing return type warning. The function should return `Formatter` (from the protocol module). The `noqa` is a code smell -- either add the type or document why it cannot be added.

### m2. `test_hunt_json_output_deprecated` does not actually verify the deprecation warning

**File:** `/Users/imurphy/projects/deep-code-security/tests/test_shared/test_formatters/test_cli_format.py`, line 146

```python
assert "deprecated" in (result.output + str(result.exception or "")).lower() or True
```

The `or True` at the end makes this assertion always pass. The test name says it verifies the deprecation warning but it does not. The Click `CliRunner` mixes stdout and stderr by default, so the warning may appear in `result.output`, but this needs to be verified without the `or True` escape hatch.

### m3. Hardcoded CWE taxonomy version in SARIF output

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/formatters/sarif.py`, line 252

```python
"version": "4.13",
```

CWE version 4.13 is hardcoded. This is not incorrect but could become stale. Consider making it a constant at module level for easier updates.

### m4. HTML `<td colspan='5'>` uses single quotes inconsistently

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/formatters/html.py`, lines 188 and 275

The HTML uses `colspan='5'` (single-quoted) while other attributes use double quotes. Functionally equivalent, but inconsistent.

### m5. `_FORMATTERS` dict is a mutable module-level global with no thread safety

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/formatters/__init__.py`, line 16

The `_FORMATTERS` dict is mutated by `register_formatter()` and read by `get_formatter()`. In a multi-threaded context this could produce race conditions. For a CLI tool this is unlikely to matter, but worth a comment.

### m6. `test_register_custom_formatter` accesses private `_FORMATTERS` for cleanup

**File:** `/Users/imurphy/projects/deep-code-security/tests/test_shared/test_formatters/test_registry.py`, lines 51-57

The test directly imports and mutates `_FORMATTERS` for cleanup. This couples the test to internal implementation. Consider adding an `unregister_formatter` function or using `monkeypatch`.

---

## Positives

1. **HTML escaping is thorough.** The `_escape()` function in `html.py` correctly applies `html.escape(str(value), quote=True)` and then handles `$` replacement for template safety. Every interpolated value in the HTML builder methods passes through `_escape()`. The adversarial test cases for `<script>`, quotes, ampersands, and dollar signs are excellent.

2. **`string.Template.safe_substitute()` used correctly.** The plan's hybrid approach (skeleton template + programmatic sections) is implemented as specified. `safe_substitute()` is used exclusively, never `substitute()`.

3. **Output file path validation.** The `_write_output` function in `cli.py` correctly validates the output path through `PathValidator`, refuses overwrite without `--force`, catches `OSError`, and uses `encoding="utf-8"`. Test coverage for these security-relevant paths is comprehensive.

4. **SARIF structure is well-designed.** The severity mapping, codeFlows construction, CWE taxonomy references, and remediation-in-property-bag (not `fixes[]`) all follow the plan's rationale correctly. Schema validation tests against the vendored SARIF 2.1.0 schema provide strong confidence in structural correctness.

5. **Backward compatibility maintained.** `--json-output` is preserved as a hidden deprecated alias, `_resolve_format` handles the precedence correctly, and `JsonFormatter` delegates to existing `serialize_model`/`serialize_models` to maintain structural equivalence.

6. **Registry design is clean.** The formatter registry with protocol validation, dynamic `get_supported_formats()`, and lazy builtin registration follows the plan precisely. Test coverage for error cases (unknown format, duplicate registration, invalid class) is thorough.

7. **`jsonschema` added as test-only dependency.** Correctly placed under `[project.optional-dependencies] test` rather than as a runtime dependency, matching the plan requirement.

8. **No security anti-patterns.** No `yaml.load()`, no `shell=True`, no `eval()`, no Jinja2 for HTML rendering. The formatter code is appropriately low-risk from a security perspective since it only formats our own scan output data.
