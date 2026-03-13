# Review: output-formats (Revision 2)

**Plan:** `./plans/output-formats.md`
**Reviewed:** 2026-03-13
**Prior review:** 2026-03-13 (first pass)
**Verdict:** PASS

---

## Conflicts with CLAUDE.md

- **None found.** All Critical Rules (Security and Code Quality) are satisfied.

| CLAUDE.md Rule | Status | Notes |
|---|---|---|
| Never `eval()`, `exec()`, `shell=True` | Compliant | No unsafe patterns introduced |
| Pydantic v2 for data-crossing models | Compliant | `HuntResult`, `FullScanResult` use `BaseModel` with `Field(default_factory=list)` |
| Type hints on all public functions | Compliant | Protocol methods and registry functions fully typed |
| `__all__` in `__init__.py` | Compliant | Task 4.2 updates `shared/__init__.py` exports |
| pathlib.Path over os.path | Compliant | Output file uses `Path.write_text()` |
| No mutable default arguments | Compliant | `Field(default_factory=list)` throughout |
| All file paths validated through `mcp/path_validator.py` | Compliant | `--output-file` validated via `PathValidator` against `DCS_ALLOWED_PATHS` (lines 248-254) |
| Jinja2 SandboxedEnvironment for PoC templates | N/A | Rule applies to Auditor exploit templates, not report output. Deviation justified in Context Alignment (line 573) |
| 90%+ test coverage | Compliant | Seven test modules, dedicated test classes per formatter, CLI integration tests |
| Architect output is guidance only, not patches | Compliant | Remediation mapped to `result.properties.remediation_guidance`, explicitly NOT `result.fixes[]` (lines 183-187) |

## Historical Alignment Issues

- **Prior review incorrectly described SARIF remediation mapping.** The first review (line 33) stated the plan "correctly maps `RemediationGuidance` to SARIF `result.fixes[]`." The revised plan explicitly rejects `result.fixes[]` in favor of `result.properties.remediation_guidance` with a clear rationale (lines 183-187). The revised approach is the correct one -- it aligns with CLAUDE.md Key Design Decisions ("Apply-ready patches are frequently wrong; guidance avoids trust erosion") and avoids misleading SARIF consumers like DefectDojo into rendering empty "Apply Fix" buttons.
- **Prior review flagged PathValidator as a deviation.** The revised plan now validates `--output-file` through `PathValidator` (lines 248-254, 562). The deviation no longer exists.
- **Prior review flagged `SUPPORTED_FORMATS` mutability.** The revised plan replaces the module-level list with `get_supported_formats()` (lines 147-152). Addressed.
- **Prior review flagged `--output-file` stderr behavior.** The revised plan explicitly states "progress messages still go to stderr" when `--output-file` is used (line 246). Addressed.

## Required Edits

- None.

## Optional Suggestions

- **`register_formatter` error message mentions `override=True`** (line 128) but the function signature does not accept an `override` parameter. Either add the parameter or remove the hint from the error message to avoid confusing callers.
- **SARIF `result.properties.remediation_guidance` structure**: The plan states remediation goes in the property bag as "a structured object containing the guidance text, code examples, and references" (line 187) but does not specify the exact schema of that object. Consider defining the property bag structure (e.g., keys like `text`, `code_examples`, `references`) to ensure consistency between the formatter and any downstream consumers.

---

**Reviewer:** Librarian (automated)
**Plan status:** DRAFT -- no changes required for approval.
