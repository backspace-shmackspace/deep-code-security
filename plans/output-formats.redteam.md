# Red Team Review (Round 2): SARIF and HTML Output Formats

**Reviewed:** `plans/output-formats.md`
**Reviewer:** Security Analyst (security-analyst v1.0.0)
**Date:** 2026-03-13
**Prior Review:** Round 1 (2026-03-13)

## Verdict: PASS

All Critical and Major findings from Round 1 have been adequately addressed. No new Critical findings were introduced. Several Minor issues remain or were introduced by the revision.

---

## Resolution Status of Round 1 Findings

### R1-1. [Critical] `--output-file` Without Path Validation -- RESOLVED

The revised plan (lines 248-254) now validates `--output-file` through `PathValidator` using `DCS_ALLOWED_PATHS`. The plan also adds `--force` to prevent accidental overwrites of existing files. The threat model rationale is explicitly stated: MCP clients may pass attacker-influenced output paths. This is a correct and complete fix.

### R1-2. [Major] Backward Compatibility Claim for JsonFormatter -- RESOLVED

The revised plan removes `target_path` from the DTOs entirely (lines 86-103). A note on line 105 explicitly documents why `target_path` is absent and how it should be introduced in the future (alongside a schema version). The "byte-identical" claim has been softened to "structurally equivalent" (line 302), acknowledging that key ordering may vary across Pydantic versions. Test case `test_format_hunt_no_target_path` (line 385) explicitly verifies the field is absent.

### R1-3. [Major] HTML Template via `string.Template` -- RESOLVED

The revised plan (lines 219-225) now explicitly describes a hybrid approach: `string.Template` with `safe_substitute()` is used only for the outermost page skeleton (a small, fixed set of placeholders), while repeating sections are built programmatically in Python with `html.escape()`. The plan also addresses `$` collision by replacing `$` with `&#36;` in user content before template context, and mandates `safe_substitute()` exclusively. This is a realistic and honest description of what the code will actually do.

### R1-4. [Major] No SARIF Schema Validation in Tests -- RESOLVED

The revised plan adds `test_sarif_full_schema_validation` (line 391) that validates complete output against the vendored SARIF 2.1.0 JSON Schema. The `jsonschema` library is added as a test-only dependency (line 438). The schema is vendored into `tests/fixtures/sarif-schema-2.1.0.json`. This is exactly what was recommended.

### R1-5. [Major] No Handling of Large Output / Memory Pressure -- RESOLVED

The revised plan (lines 306-315) adds a "Memory and Large Output" section with a size estimation table for typical and maximum output across all formats. The maximum case (100 findings, HTML) is estimated at ~1 MB, which is well within acceptable bounds for a CLI tool. Streaming output is explicitly deferred with rationale. The `Formatter` protocol docstring (lines 57-63) documents this decision.

### R1-6. [Minor] `SUPPORTED_FORMATS` Mutable List -- RESOLVED

Replaced with `get_supported_formats()` function (line 147) that computes dynamically from the registry. `register_formatter()` now rejects duplicate registrations (lines 125-129).

### R1-7. [Minor] `register_formatter()` No Input Validation -- RESOLVED

The revised `register_formatter()` (lines 119-136) validates that the class implements both `format_hunt` and `format_full_scan` methods and raises `TypeError` on failure. Duplicate registrations raise `ValueError`.

### R1-8. [Minor] CLI `--format` and `--json-output` Interaction -- RESOLVED

The revised plan (line 244) explicitly states: "When both `--format <X>` and `--json-output` are provided, `--json-output` wins and a deprecation warning is emitted." A test case `test_format_sarif_with_json_output_conflict` (line 426) is included.

### R1-9. [Minor] `verify` Command Left Inconsistent -- RESOLVED

The revised plan (line 279) adds a note: "When `verify` becomes functional, `--format` must be added." This is a sufficient breadcrumb for future implementers.

### R1-10. [Minor] Rollout Plan Is Too Thin -- NOT RESOLVED (Downgraded to Info)

The rollout plan remains three bullet points plus a manual DefectDojo test. No documentation, changelog, or CI pipeline tasks are mentioned. However, given the actual scope of this feature (additive, no breaking changes, MCP output unchanged), this is an acceptable gap. Downgraded from Minor to Info.

### R1-11. [Info] SARIF `result.fixes[]` Usage -- RESOLVED

The revised plan (line 183-187) moves remediation guidance to `result.properties.remediation_guidance` in the property bag, with explicit rationale for why `fixes[]` is inappropriate. Test case `test_sarif_full_scan_remediation_in_properties` (line 404) verifies this.

### R1-12. [Info] No Consideration of Output Encoding -- RESOLVED

The revised plan specifies `encoding="utf-8"` for `Path.write_text()` calls (line 509), `<meta charset="utf-8">` in HTML output (line 217), and includes a test case `test_output_file_utf8_encoding` (line 434).

---

## New Findings (Round 2)

### 1. [Minor] `register_formatter` Error Message References `override=True` That Does Not Exist

**Location:** Lines 125-129

The error message in `register_formatter` says "Use override=True to replace it" but the function signature shown on line 119 has no `override` parameter. This will confuse callers who encounter the error and try to pass `override=True`.

**Recommendation:** Either add the `override` parameter to the function signature, or remove the misleading reference from the error message.

---

### 2. [Minor] `click.Choice` Hardcodes Format Names Instead of Using Registry

**Location:** Lines 233-236

The CLI option uses `click.Choice(["text", "json", "sarif", "html"])` with a hardcoded list, while the formatter registry is designed to be dynamically extensible via `register_formatter()`. If a third-party plugin registers a new format, the CLI will reject it because `click.Choice` does not query the registry.

This is a minor inconsistency. In practice, third-party format plugins would need to modify the CLI option anyway (Click choices are validated at parse time, before application code runs). But the extensibility story in the plan (Acceptance Criterion 12: "Adding a new output format requires only creating a class and calling `register_formatter()`") is incomplete -- it also requires modifying the `click.Choice` list.

**Recommendation:** Either use `get_supported_formats()` to populate `click.Choice` dynamically (note: this requires the registry to be initialized before Click parses arguments, which it is since `_register_builtins()` runs at import time), or document that CLI registration is a third step beyond what Acceptance Criterion 12 states.

---

### 3. [Minor] SARIF `ruleId` Extraction via Regex Is Under-Specified

**Location:** Line 195

The plan says `id` in `tool.driver.rules[]` uses "The CWE identifier extracted from the vulnerability class (regex `CWE-\d+` from `sink.cwe` or `vulnerability_class`)." This is ambiguous about what happens when:

- A finding has no CWE identifier (the regex matches nothing).
- Multiple CWE identifiers appear in the same string.
- The `vulnerability_class` string contains no CWE reference at all (e.g., "Hardcoded Secret").

SARIF requires `ruleId` to be present and non-empty for each result. If the regex fails to extract a CWE, the plan does not specify the fallback `ruleId` value.

**Recommendation:** Specify a fallback rule ID scheme. For example, use the `vulnerability_class` string itself (slugified) as the `ruleId` when no CWE can be extracted. Add a test case for findings without CWE identifiers.

---

### 4. [Minor] No Test for Malicious Content in SARIF Output

**Location:** Test Plan, SarifFormatter tests

The SARIF test plan covers schema validation and field mapping but does not include a test with adversarial input -- for example, a finding where `source.file` contains characters that could break JSON serialization (null bytes, control characters, very long strings). While `json.dumps()` handles most of these correctly, a dedicated test would verify no edge cases slip through.

**Recommendation:** Add a test case `test_sarif_adversarial_file_paths` that uses findings with file paths containing null bytes, unicode characters, and path-traversal sequences to verify the SARIF output remains valid JSON and passes schema validation.

---

### 5. [Info] `--force` Flag Is Only Documented for Overwrite Protection, Not for Other Safety Checks

**Location:** Lines 253-254, 503-504

The `--force` flag is introduced solely to allow overwriting existing output files. The name `--force` is generic and could be overloaded with other meanings in the future (e.g., bypassing other safety checks). This is not a problem today, but naming it `--overwrite` would be more self-documenting.

**Recommendation:** Consider naming the flag `--overwrite` instead of `--force` to make the intent explicit and avoid future semantic overloading.

---

### 6. [Info] Rollout Plan Still Lacks Documentation and Changelog Tasks

**Location:** Lines 289-296

As noted in R1-10, the rollout plan does not mention updating `--help` descriptions beyond Click auto-generation, README updates, or changelog entries. For an additive feature with no breaking changes, this is acceptable but not ideal.

---

## Container Security Assessment

Not applicable to this plan. The output formatters do not interact with containers. The sandbox architecture remains unchanged.

## Supply Chain Risk

The plan adds one new dependency: `jsonschema` as a test-only dependency. This is a well-established PyPI package with wide adoption. Since it is test-only (not a runtime dependency), the attack surface is limited to developer machines and CI pipelines. This is acceptable.

No tree-sitter grammars or registry changes are involved.

## Trust Boundary Analysis

The primary trust boundary concern for this plan is the flow of attacker-influenced data from scan results into output formatters:

```
Untrusted Source Code --> Hunter (AST parse) --> RawFinding fields --> Formatter --> Output File
```

The revised plan addresses this adequately:
- **HTML:** `html.escape()` on all interpolated values; `$` replaced with `&#36;` before `string.Template` context; `safe_substitute()` only.
- **SARIF/JSON:** `json.dumps()` handles escaping; no raw string interpolation.
- **Output path:** Validated through `PathValidator` with `DCS_ALLOWED_PATHS`; overwrite protection via `--force`.

The output file path validation (R1-1 fix) correctly addresses the MCP agent threat model where an attacker could influence the output path via prompt injection.
