# Plan: SARIF and HTML Output Formats

## Status: APPROVED

## Goals

1. Add SARIF 2.1.0 output format for import into DefectDojo and other SARIF-consuming tools.
2. Add HTML output format for human-readable reports suitable for sharing with stakeholders.
3. Introduce an extensible formatter architecture so new output formats can be added by implementing a single class.
4. Replace the `--json-output` flag with a `--format` option (`text`, `json`, `sarif`, `html`) across both `hunt` and `full-scan` commands.
5. Maintain backward compatibility: `--json-output` continues to work as an alias for `--format json`.

## Non-Goals

- Adding PDF output (no dependency-free PDF generation in stdlib).
- Adding JUnit XML output (not requested; can be added later via the extensible architecture).
- Changing MCP server output format (MCP tools always return JSON via Pydantic serialization).
- Adding Jinja2 as a dependency for HTML rendering (Jinja2 is only in the private `dcs-verification` plugin).
- Changing the data models (`RawFinding`, `VerifiedFinding`, `RemediationGuidance`).

## Assumptions

1. SARIF 2.1.0 is a well-defined JSON schema; no external library is needed to produce conformant output.
2. HTML reports use programmatic string construction with `html.escape()` on all interpolated values. `string.Template` is used only for the outermost page skeleton (header, body wrapper, footer); all repeating sections (findings table rows, expandable detail blocks) are built in Python code. See the HTML Format section for details.
3. The formatter receives the same structured data that `--json-output` currently serializes (Pydantic model dicts).
4. Output goes to stdout by default, with an optional `--output-file` flag to write to a file. Output file paths are validated through `PathValidator` (see Output File Path Validation).
5. All HTML content derived from scan results is escaped to prevent XSS if the report is served over HTTP.

## Proposed Design

### Architecture: Formatter Protocol + Registry

The design introduces a `Formatter` protocol (Python `typing.Protocol`) and a registry of format names to formatter classes. Each formatter implements two methods: `format_hunt` and `format_full_scan`. The CLI selects the formatter by name and calls the appropriate method.

```
src/deep_code_security/shared/
    formatters/
        __init__.py          # FormatterRegistry, get_formatter()
        protocol.py          # Formatter protocol definition
        text.py              # TextFormatter (current human-readable output)
        json.py              # JsonFormatter (current --json-output behavior)
        sarif.py             # SarifFormatter (SARIF 2.1.0)
        html.py              # HtmlFormatter (standalone HTML report)
```

### Formatter Protocol

```python
# shared/formatters/protocol.py
from __future__ import annotations
from typing import Any, Protocol

class Formatter(Protocol):
    """Protocol for output formatters.

    Every formatter must implement both format_hunt (for the hunt command)
    and format_full_scan (for the full-scan command). Each returns a string
    ready to be written to stdout or a file.

    Note on memory: formatters return a single `str`. For v1, this is
    acceptable given DCS_MAX_RESULTS=100 (typical output is under 5 MB
    for SARIF, under 10 MB for HTML). Streaming output is deferred to a
    future version if real-world usage reveals memory pressure.
    """

    def format_hunt(self, data: HuntResult) -> str:
        """Format hunt phase results."""
        ...

    def format_full_scan(self, data: FullScanResult) -> str:
        """Format full-scan (all three phases) results."""
        ...
```

### Data Transfer Objects

Rather than passing raw dicts, the formatters receive typed Pydantic models that aggregate the results from each command. This keeps the formatter interface stable even if CLI internals change.

```python
# shared/formatters/protocol.py (continued)
from pydantic import BaseModel, Field
from deep_code_security.hunter.models import RawFinding, ScanStats
from deep_code_security.auditor.models import VerifiedFinding, VerifyStats
from deep_code_security.architect.models import RemediationGuidance, RemediateStats

class HuntResult(BaseModel):
    """Aggregated results from the hunt command."""
    findings: list[RawFinding] = Field(default_factory=list)
    stats: ScanStats
    total_count: int = 0
    has_more: bool = False

class FullScanResult(BaseModel):
    """Aggregated results from the full-scan command."""
    findings: list[RawFinding] = Field(default_factory=list)
    verified: list[VerifiedFinding] = Field(default_factory=list)
    guidance: list[RemediationGuidance] = Field(default_factory=list)
    hunt_stats: ScanStats
    verify_stats: VerifyStats | None = None
    remediate_stats: RemediateStats | None = None
    total_count: int = 0
    has_more: bool = False
```

**Note:** The DTOs do not include a `target_path` field. The current `--json-output` structure does not include `target_path`, and adding it would break the backward compatibility guarantee. The SARIF and HTML formatters that need target path information receive it separately via the formatter method signature (see CLI Integration below). If a `target_path` field is needed in the DTOs in the future, it should be introduced alongside an explicit JSON output schema version.

### Formatter Registry

```python
# shared/formatters/__init__.py
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from deep_code_security.shared.formatters.protocol import Formatter

_FORMATTERS: dict[str, type[Formatter]] = {}

def register_formatter(name: str, cls: type[Formatter]) -> None:
    """Register a formatter class by name.

    Raises ValueError if the name is already registered (use
    override=True to replace a built-in formatter).
    """
    if name in _FORMATTERS:
        raise ValueError(
            f"Formatter {name!r} is already registered. "
            f"Use override=True to replace it."
        )
    # Validate that cls implements the Formatter protocol
    for method in ("format_hunt", "format_full_scan"):
        if not callable(getattr(cls, method, None)):
            raise TypeError(
                f"Formatter class {cls.__name__} must implement {method}()"
            )
    _FORMATTERS[name] = cls

def get_formatter(name: str) -> Formatter:
    """Get a formatter instance by name. Raises ValueError for unknown formats."""
    if name not in _FORMATTERS:
        raise ValueError(
            f"Unknown output format: {name!r}. "
            f"Available: {', '.join(sorted(_FORMATTERS))}"
        )
    return _FORMATTERS[name]()

def get_supported_formats() -> list[str]:
    """Return sorted list of registered format names.

    Computed dynamically from the registry to avoid stale module-level state.
    """
    return sorted(_FORMATTERS.keys())

def _register_builtins() -> None:
    from deep_code_security.shared.formatters.text import TextFormatter
    from deep_code_security.shared.formatters.json import JsonFormatter
    from deep_code_security.shared.formatters.sarif import SarifFormatter
    from deep_code_security.shared.formatters.html import HtmlFormatter

    register_formatter("text", TextFormatter)
    register_formatter("json", JsonFormatter)
    register_formatter("sarif", SarifFormatter)
    register_formatter("html", HtmlFormatter)

_register_builtins()
```

**Changes from prior draft:** `SUPPORTED_FORMATS` module-level list replaced with `get_supported_formats()` function that computes from the registry dynamically. `register_formatter()` now validates that the class implements the protocol methods and rejects duplicate registrations.

### SARIF 2.1.0 Format

The SARIF formatter produces a conformant SARIF 2.1.0 JSON document. Key mapping decisions:

| DCS Concept | SARIF Concept |
|---|---|
| `RawFinding` / `VerifiedFinding` | `result` |
| `Source` + `Sink` | `result.locations[]` (sink) + `result.relatedLocations[]` (source) |
| `TaintPath` | `result.codeFlows[].threadFlows[].locations[]` |
| `vulnerability_class` | `result.ruleId` (CWE ID extracted) |
| `severity` | `result.level` (error/warning/note mapping) |
| `confidence_score` | `result.properties.confidence_score` (property bag) |
| `verification_status` | `result.properties.verification_status` (property bag) |
| `RemediationGuidance` | `result.properties.remediation_guidance` (property bag -- see rationale below) |
| Tool identity | `tool.driver` with name="deep-code-security", version from package |
| Rule definitions | `tool.driver.rules[]` (one entry per unique vulnerability class) |

**Remediation in property bag, not `fixes[]`:** SARIF `fix` objects are intended for machine-applicable patches (`fix.artifactChanges[].replacements[]`). This project produces guidance, not apply-ready patches (see CLAUDE.md Key Design Decisions). Using `fixes[]` with only a `description` would mislead SARIF consumers (e.g., DefectDojo may render empty "Apply Fix" buttons). Instead, remediation guidance is placed in `result.properties.remediation_guidance` as a structured object containing the guidance text, code examples, and references. The property bag is the SARIF-standard location for tool-specific metadata.

Severity mapping:
- `critical` / `high` -> SARIF `level: "error"`
- `medium` -> SARIF `level: "warning"`
- `low` -> SARIF `level: "note"`

**`tool.driver.rules[]` array:** Each unique `vulnerability_class` encountered in the scan results produces an entry in `tool.driver.rules[]` with:
- `id`: The CWE identifier extracted from the vulnerability class (regex `CWE-\d+` from `sink.cwe` or `vulnerability_class`).
- `shortDescription.text`: The vulnerability class name (e.g., "SQL Injection").
- `fullDescription.text`: Description from the registry YAML if available.
- `defaultConfiguration.level`: The default SARIF level for this rule, derived from severity mapping above.
- `properties.tags`: Including the CWE ID for taxonomy cross-reference.

This is required by DefectDojo and most SARIF importers; without `rules[]`, import produces degraded results or fails.

The SARIF output uses relative file paths (`result.locations[].physicalLocation.artifactLocation.uri`) computed relative to the scan target path, with `run.originalUriBaseIds` set to the absolute target path. This is the standard DefectDojo expectation.

CWE is included as `result.taxa[]` referencing the CWE taxonomy, which DefectDojo uses for automatic CWE mapping.

### HTML Format

The HTML formatter produces a self-contained HTML file (all CSS inline, no external resources). Structure:

1. **Header** -- tool name, scan date, target path, summary stats.
2. **Summary table** -- total findings, by severity, by verification status (if full-scan).
3. **Findings table** -- sortable by severity, with columns: Severity, CWE, File:Line, Vulnerability Class, Confidence, Status.
4. **Finding details** (expandable) -- taint path, remediation guidance (if full-scan), code example.
5. **Footer** -- tool version, generation timestamp.

All user-derived content (file paths, variable names, code snippets) is HTML-escaped using `html.escape()` from the standard library. CSS is minimal and embedded in a `<style>` block. No JavaScript is required (details use `<details>/<summary>` HTML5 elements). The HTML document includes `<meta charset="utf-8">`.

**Template architecture:** The HTML formatter uses a hybrid approach:

1. **Page skeleton** uses `string.Template` with `safe_substitute()` for the outermost structure (HTML head, body wrapper, footer). This template has a small, fixed set of placeholders (`$title`, `$summary_html`, `$findings_html`, `$footer_html`).
2. **Repeating sections** (findings table rows, expandable detail blocks, summary breakdowns) are built programmatically in Python using f-strings with `html.escape()` on every interpolated value.
3. **Dollar sign handling:** Before any user-derived content is passed to a `string.Template` context, `$` characters are replaced with `&#36;` (HTML entity) to prevent collisions with template placeholders. This is applied after `html.escape()` (which does not cover `$`). The `safe_substitute()` method is used exclusively (never `substitute()`) as a defense-in-depth measure.

This approach is realistic about `string.Template`'s limitations (no loops, no conditionals) while still using it for the static page chrome where it provides clean separation of HTML structure from Python logic.

### CLI Changes

The `--format` option replaces the role of `--json-output`:

```python
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["text", "json", "sarif", "html"]),
    default="text",
    help="Output format (default: text).",
)
@click.option("--json-output", is_flag=True, hidden=True,
              help="[DEPRECATED] Use --format json instead.")
@click.option("--output-file", "-o", type=click.Path(),
              help="Write output to file instead of stdout.")
```

The `--json-output` flag is preserved but hidden. When set, it overrides `--format` to `json` and emits a deprecation warning to stderr. When both `--format <X>` and `--json-output` are provided, `--json-output` wins and a deprecation warning is emitted.

When `--output-file` is used, progress messages still go to stderr. Output file writes use `encoding="utf-8"` explicitly. `OSError` from file writes (permission denied, directory not found, disk full) is caught and reported as a user-friendly error message to stderr with a non-zero exit code.

### Output File Path Validation

The `--output-file` path is validated through `PathValidator` using `DCS_ALLOWED_PATHS`. This tool is designed to be invoked by MCP clients (Claude Code agents), not only by direct human users. When an agent orchestrates a scan, the output path may be influenced by attacker-controlled input (e.g., a malicious repository's README suggesting a specific output path). Without validation, this creates an arbitrary file write primitive.

The `DCS_ALLOWED_PATHS` allowlist is extended to cover both read (scan target) and write (output file) operations. By default, `DCS_ALLOWED_PATHS` is the current working directory, which means output files can be written anywhere under cwd -- the typical use case. Users who need to write reports to a different directory can add that directory to `DCS_ALLOWED_PATHS`.

Additionally, `--output-file` refuses to overwrite existing files unless `--force` is also provided. This prevents accidental data loss regardless of path validation.

## Interfaces / Schema Changes

### New Public API

| Module | Symbol | Type | Description |
|---|---|---|---|
| `shared.formatters.protocol` | `Formatter` | Protocol | Formatter interface |
| `shared.formatters.protocol` | `HuntResult` | Pydantic model | Hunt output DTO |
| `shared.formatters.protocol` | `FullScanResult` | Pydantic model | Full-scan output DTO |
| `shared.formatters` | `get_formatter(name)` | function | Formatter factory |
| `shared.formatters` | `register_formatter(name, cls)` | function | Registration hook |
| `shared.formatters` | `get_supported_formats()` | function | Available format names (dynamic) |
| `shared.formatters.text` | `TextFormatter` | class | Human-readable output |
| `shared.formatters.json` | `JsonFormatter` | class | JSON output |
| `shared.formatters.sarif` | `SarifFormatter` | class | SARIF 2.1.0 output |
| `shared.formatters.html` | `HtmlFormatter` | class | HTML report output |

### CLI Option Changes

| Command | Old | New | Notes |
|---|---|---|---|
| `hunt` | `--json-output` flag | `--format` choice + `--output-file` path + `--force` | `--json-output` kept as hidden deprecated alias |
| `full-scan` | `--json-output` flag | `--format` choice + `--output-file` path + `--force` | Same |
| `verify` | `--json-output` flag | No change | Command is a stub (exits immediately). When `verify` becomes functional, `--format` must be added. |

### MCP Server

No changes. The MCP tools return Pydantic-serialized JSON via the MCP protocol. Output formatting is a CLI concern only.

## Data Migration

None. No persistent state is affected.

## Rollout Plan

This is a single-release feature addition with no phased rollout needed.

1. **Implement** all formatter classes and CLI changes in a single branch.
2. **Test** with `make test` (unit + coverage) and SARIF schema validation test (see Test Plan).
3. **Manual SARIF import** into DefectDojo to verify end-to-end (Task 5.2).
4. **Release** as part of the next version bump.

### Backward Compatibility

- `--json-output` continues to work identically to `--format json`.
- Default behavior (no flags) is `--format text`, which matches current no-flag behavior.
- JSON output structure is structurally equivalent to current `--json-output` output (same keys and values when parsed; key ordering may vary across Pydantic versions). The DTOs do not add new fields to the JSON output.

## Memory and Large Output

Formatters return a single `str` from `format_hunt()` and `format_full_scan()`. Given the default `DCS_MAX_RESULTS=100`, typical output sizes are:

| Format | Typical (20 findings) | Maximum (100 findings) |
|--------|----------------------|----------------------|
| JSON   | ~50 KB               | ~250 KB              |
| SARIF  | ~100 KB              | ~500 KB (with codeFlows) |
| HTML   | ~200 KB              | ~1 MB (with expandable details) |
| Text   | ~10 KB               | ~50 KB               |

These sizes are well within acceptable memory bounds for a CLI tool. Streaming output (e.g., returning an iterator or writing directly to a file-like object) is deferred to a future version if real-world usage reveals memory pressure. This is documented in the `Formatter` protocol docstring.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| SARIF schema drift between DefectDojo versions | Low | Medium | Pin to SARIF 2.1.0 which is the stable standard; include schema version in output; validate against official schema in tests |
| HTML XSS if report served over HTTP | Low | High | All interpolated values go through `html.escape()`; no raw string insertion |
| HTML template string becomes unmaintainable | Medium | Low | Keep template minimal (no JS); skeleton-only template with programmatic section construction |
| `$` in user content collides with `string.Template` placeholders | Low | Low | Replace `$` with `&#36;` in user content before template context; use `safe_substitute()` exclusively; repeating sections bypass template entirely |
| New format breaks 90% coverage threshold | Low | Medium | Each formatter has dedicated test class; DTOs have model validation tests |
| Output file write fails (permissions, disk) | Low | Low | Catch `OSError`, report to stderr with non-zero exit code |

## Test Plan

### Test Command

```bash
make test
```

This runs `pytest tests/ -v --cov=src/deep_code_security --cov-report=term-missing --cov-fail-under=90 --ignore=tests/test_integration`.

### Test Structure

All new tests go in `tests/test_shared/test_formatters/`:

```
tests/test_shared/
    test_formatters/
        __init__.py
        conftest.py            # Shared SARIF schema fixture (downloaded/vendored)
        test_protocol.py       # HuntResult/FullScanResult model validation
        test_registry.py       # get_formatter, register_formatter, unknown format error
        test_text.py           # TextFormatter matches current CLI output
        test_json.py           # JsonFormatter matches current --json-output structure
        test_sarif.py          # SARIF schema conformance, severity mapping, codeFlows
        test_html.py           # HTML structure, escaping, completeness
```

### Test Cases by Formatter

**Registry (`test_registry.py`):**
- `test_get_formatter_text` -- returns TextFormatter instance
- `test_get_formatter_json` -- returns JsonFormatter instance
- `test_get_formatter_sarif` -- returns SarifFormatter instance
- `test_get_formatter_html` -- returns HtmlFormatter instance
- `test_get_formatter_unknown_raises` -- ValueError with helpful message
- `test_register_custom_formatter` -- custom class can be registered and retrieved
- `test_register_duplicate_raises` -- ValueError when registering over existing name
- `test_register_invalid_class_raises` -- TypeError when class lacks required methods
- `test_get_supported_formats` -- returns sorted list of all four names

**Protocol DTOs (`test_protocol.py`):**
- `test_hunt_result_construction` -- valid HuntResult from fixtures
- `test_full_scan_result_construction` -- valid FullScanResult from fixtures
- `test_hunt_result_empty_findings` -- empty findings list is valid
- `test_full_scan_result_no_verify_stats` -- verify_stats=None is valid
- `test_hunt_result_no_target_path` -- HuntResult has no target_path field

**TextFormatter (`test_text.py`):**
- `test_format_hunt_single_finding` -- output contains severity, file, line
- `test_format_hunt_empty` -- no findings produces summary only
- `test_format_hunt_has_more` -- includes pagination hint
- `test_format_full_scan_with_verified` -- output contains confirmed/likely counts
- `test_format_full_scan_skip_verify` -- handles no verify_stats

**JsonFormatter (`test_json.py`):**
- `test_format_hunt_valid_json` -- output parses as valid JSON
- `test_format_hunt_structure` -- has `findings`, `stats`, `total_count`, `has_more` keys
- `test_format_hunt_no_target_path` -- parsed output does not contain `target_path` key
- `test_format_hunt_structurally_equivalent` -- parsed structure matches current `--json-output`
- `test_format_full_scan_valid_json` -- output parses as valid JSON
- `test_format_full_scan_structure` -- has all expected keys

**SarifFormatter (`test_sarif.py`):**
- `test_sarif_full_schema_validation` -- validates complete output against the official SARIF 2.1.0 JSON Schema (vendored in `tests/fixtures/sarif-schema-2.1.0.json`)
- `test_sarif_schema_version` -- `$schema` and `version` fields present and correct
- `test_sarif_tool_driver` -- `tool.driver.name` is "deep-code-security"
- `test_sarif_tool_driver_rules` -- `tool.driver.rules[]` contains entries for each unique vulnerability class with `id`, `shortDescription`, `defaultConfiguration.level`
- `test_sarif_result_count` -- number of results matches findings count
- `test_sarif_severity_mapping_critical` -- critical -> error
- `test_sarif_severity_mapping_medium` -- medium -> warning
- `test_sarif_severity_mapping_low` -- low -> note
- `test_sarif_code_flows` -- taint path produces threadFlow with correct locations
- `test_sarif_relative_uris` -- artifact URIs are relative to target path
- `test_sarif_cwe_taxa` -- CWE referenced in taxa
- `test_sarif_valid_json` -- output parses as valid JSON
- `test_sarif_full_scan_includes_confidence` -- property bag has confidence_score
- `test_sarif_full_scan_remediation_in_properties` -- remediation guidance in `result.properties.remediation_guidance`, NOT in `result.fixes[]`
- `test_sarif_empty_findings` -- valid SARIF with zero results, still passes schema validation
- `test_sarif_empty_findings_has_rules` -- empty results still produces valid `rules[]` array (empty)

**HtmlFormatter (`test_html.py`):**
- `test_html_valid_structure` -- output contains `<html>`, `<head>`, `<body>`, `</html>`
- `test_html_meta_charset` -- output contains `<meta charset="utf-8">`
- `test_html_contains_finding_data` -- file path and line number appear in output
- `test_html_escapes_special_chars` -- `<script>` in file path is escaped
- `test_html_escapes_quotes` -- `"` and `'` in attribute contexts are escaped
- `test_html_escapes_ampersand` -- `&` in finding descriptions is escaped
- `test_html_escapes_dollar_sign` -- `$HOME` in file path rendered as `&#36;HOME`, not substituted
- `test_html_severity_colors` -- critical/high/medium/low have distinct styling
- `test_html_full_scan_includes_guidance` -- remediation section present
- `test_html_empty_findings` -- produces valid report with "no findings" message
- `test_html_summary_stats` -- scan stats appear in header

**CLI integration (`test_cli_format.py` in `tests/test_shared/test_formatters/`):**
- `test_hunt_format_json` -- `--format json` produces valid JSON
- `test_hunt_format_sarif` -- `--format sarif` produces valid SARIF
- `test_hunt_format_text_default` -- no flag defaults to text
- `test_hunt_json_output_deprecated` -- `--json-output` still works, warns on stderr
- `test_format_sarif_with_json_output_conflict` -- `--format sarif --json-output` uses json, warns on stderr
- `test_full_scan_format_html` -- `--format html` produces HTML
- `test_output_file_writes_to_disk` -- `--output-file` writes and stdout is empty
- `test_output_file_json` -- `--output-file` + `--format json` writes JSON to file
- `test_output_file_validated_by_path_validator` -- `--output-file` outside `DCS_ALLOWED_PATHS` is rejected
- `test_output_file_refuses_overwrite` -- existing file not overwritten without `--force`
- `test_output_file_force_overwrites` -- `--force` allows overwriting existing file
- `test_output_file_write_error` -- unwritable path produces user-friendly stderr error
- `test_output_file_utf8_encoding` -- output file is written with UTF-8 encoding

### SARIF Schema Validation

The official SARIF 2.1.0 JSON Schema is vendored into `tests/fixtures/sarif-schema-2.1.0.json` (downloaded from the OASIS SARIF TC GitHub repository). The `test_sarif_full_schema_validation` test uses `jsonschema` (added as a test-only dependency in `pyproject.toml` under `[project.optional-dependencies] test`) to validate the complete formatter output against this schema. This catches structural errors (wrong nesting, missing required fields, extra fields in wrong locations) that per-field unit tests would miss.

## Acceptance Criteria

1. `dcs hunt <path> --format sarif` produces SARIF 2.1.0 JSON that passes schema validation and that DefectDojo accepts.
2. `dcs hunt <path> --format html` produces a self-contained HTML file viewable in a browser.
3. `dcs full-scan <path> --format sarif` includes confidence scores in property bag and remediation in `result.properties.remediation_guidance`.
4. `dcs full-scan <path> --format html` includes verification status and remediation guidance sections.
5. `dcs hunt <path> --json-output` continues to work identically (backward compatibility).
6. `dcs hunt <path>` (no flags) produces the same text output as before.
7. `dcs hunt <path> --format json -o report.json` writes JSON to `report.json` (path must be within `DCS_ALLOWED_PATHS`).
8. `dcs hunt <path> -o report.json` on an existing `report.json` fails unless `--force` is provided.
9. `make test` passes with 90%+ coverage.
10. `make lint` passes.
11. No new runtime dependencies added to `pyproject.toml`. `jsonschema` is added as a test-only dependency.
12. Adding a new output format requires only: (a) creating a new formatter class implementing `Formatter`, and (b) calling `register_formatter()`.
13. SARIF output includes `tool.driver.rules[]` with entries for each unique vulnerability class.
14. SARIF output validates against the official SARIF 2.1.0 JSON Schema in automated tests.

## Task Breakdown

### Phase 1: Formatter Protocol and Registry (Foundation)

**Task 1.1: Create formatter protocol and DTOs**
- Create: `src/deep_code_security/shared/formatters/__init__.py`
- Create: `src/deep_code_security/shared/formatters/protocol.py`
- Contents: `Formatter` protocol, `HuntResult` model (no `target_path`), `FullScanResult` model (no `target_path`), registry functions with validation

**Task 1.2: Create test infrastructure**
- Create: `tests/test_shared/test_formatters/__init__.py`
- Create: `tests/test_shared/test_formatters/conftest.py` (SARIF schema fixture)
- Create: `tests/test_shared/test_formatters/test_protocol.py`
- Create: `tests/test_shared/test_formatters/test_registry.py`
- Vendor: `tests/fixtures/sarif-schema-2.1.0.json` (SARIF 2.1.0 JSON Schema)
- Add: `jsonschema` to `[project.optional-dependencies] test` in `pyproject.toml`

### Phase 2: Port Existing Output to Formatters

**Task 2.1: Implement TextFormatter**
- Create: `src/deep_code_security/shared/formatters/text.py`
- Create: `tests/test_shared/test_formatters/test_text.py`
- Logic: Extract current human-readable output from `cli.py` into `TextFormatter.format_hunt()` and `TextFormatter.format_full_scan()`.

**Task 2.2: Implement JsonFormatter**
- Create: `src/deep_code_security/shared/formatters/json.py`
- Create: `tests/test_shared/test_formatters/test_json.py`
- Logic: Extract current `--json-output` serialization from `cli.py` into `JsonFormatter`. Must produce structurally equivalent output to current implementation (same keys and values when parsed; key ordering is not guaranteed across Pydantic versions). The formatter must NOT include `target_path` in its output.

### Phase 3: New Formats

**Task 3.1: Implement SarifFormatter**
- Create: `src/deep_code_security/shared/formatters/sarif.py`
- Create: `tests/test_shared/test_formatters/test_sarif.py`
- Logic: Build SARIF 2.1.0 JSON structure. Populate `tool.driver.rules[]` from unique vulnerability classes. Map severity levels. Build codeFlows from taint paths. Include CWE taxa. For full-scan results, include confidence in property bag and remediation in `result.properties.remediation_guidance` (NOT `result.fixes[]`). Validate against vendored SARIF schema in tests.

**Task 3.2: Implement HtmlFormatter**
- Create: `src/deep_code_security/shared/formatters/html.py`
- Create: `tests/test_shared/test_formatters/test_html.py`
- Logic: Produce self-contained HTML with inline CSS and `<meta charset="utf-8">`. Page skeleton via `string.Template` with `safe_substitute()`; repeating sections (findings rows, detail blocks) built programmatically with `html.escape()` on all interpolated values. Replace `$` with `&#36;` in user content before template context. Use `<details>/<summary>` for expandable finding details.

### Phase 4: CLI Integration

**Task 4.1: Refactor CLI to use formatters**
- Modify: `src/deep_code_security/cli.py`
  - Add `--format` option (choice of `text`, `json`, `sarif`, `html`) to `hunt` and `full-scan` commands.
  - Add `--output-file` option to `hunt` and `full-scan` commands. Validate output path through `PathValidator`. Refuse overwrite unless `--force` is provided.
  - Add `--force` flag to `hunt` and `full-scan` commands.
  - Keep `--json-output` as hidden deprecated alias. When both `--format` and `--json-output` are provided, `--json-output` wins.
  - Replace inline output logic with formatter calls.
  - Construct `HuntResult` / `FullScanResult` DTOs and pass to selected formatter.
  - Catch `OSError` on file write and report user-friendly error to stderr.
  - Use `encoding="utf-8"` for all `Path.write_text()` calls.
- Create: `tests/test_shared/test_formatters/test_cli_format.py`

**Task 4.2: Update `__init__.py` exports**
- Modify: `src/deep_code_security/shared/__init__.py` -- add `get_formatter`, `get_supported_formats` to `__all__`.

### Phase 5: Verification and Cleanup

**Task 5.1: Run full test suite and fix coverage gaps**
- Run: `make test` and `make lint`
- Fix any coverage gaps to maintain 90%+ threshold.

**Task 5.2: Manual SARIF validation**
- Import SARIF output into DefectDojo (manual step, not automated).
- Verify CWE mapping, severity, `rules[]` entries, and file locations render correctly.
- Verify that remediation guidance appears in the property bag (not as empty "Apply Fix" buttons).

### Files Summary

| Action | File |
|---|---|
| Create | `src/deep_code_security/shared/formatters/__init__.py` |
| Create | `src/deep_code_security/shared/formatters/protocol.py` |
| Create | `src/deep_code_security/shared/formatters/text.py` |
| Create | `src/deep_code_security/shared/formatters/json.py` |
| Create | `src/deep_code_security/shared/formatters/sarif.py` |
| Create | `src/deep_code_security/shared/formatters/html.py` |
| Modify | `src/deep_code_security/shared/__init__.py` |
| Modify | `src/deep_code_security/cli.py` |
| Modify | `pyproject.toml` (add `jsonschema` to test dependencies) |
| Create | `tests/fixtures/sarif-schema-2.1.0.json` |
| Create | `tests/test_shared/test_formatters/__init__.py` |
| Create | `tests/test_shared/test_formatters/conftest.py` |
| Create | `tests/test_shared/test_formatters/test_protocol.py` |
| Create | `tests/test_shared/test_formatters/test_registry.py` |
| Create | `tests/test_shared/test_formatters/test_text.py` |
| Create | `tests/test_shared/test_formatters/test_json.py` |
| Create | `tests/test_shared/test_formatters/test_sarif.py` |
| Create | `tests/test_shared/test_formatters/test_html.py` |
| Create | `tests/test_shared/test_formatters/test_cli_format.py` |

No files are deleted. `shared/json_output.py` is NOT removed -- it remains available for MCP server usage and any internal callers. The `JsonFormatter` delegates to `serialize_model`/`serialize_models` from that module.

## Context Alignment

### CLAUDE.md Patterns Followed

- **Pydantic v2 for data-crossing models**: `HuntResult` and `FullScanResult` are Pydantic BaseModel subclasses.
- **Type hints on all public functions**: All formatter methods and registry functions are fully typed.
- **`__all__` in `__init__.py`**: The formatters `__init__.py` exports `get_formatter`, `register_formatter`, `get_supported_formats`.
- **pathlib.Path over os.path**: Output file handling uses `Path.write_text()`.
- **No mutable default arguments**: DTOs use `Field(default_factory=list)`.
- **Security rules**: No `eval`/`exec`/`shell=True`. HTML escaping via `html.escape()`. `string.Template.safe_substitute()` for HTML page skeleton (no code execution). Output file paths validated through `PathValidator`.
- **All file paths validated through `mcp/path_validator.py`**: `--output-file` paths are validated against `DCS_ALLOWED_PATHS`, consistent with the CLAUDE.md mandate that "all file paths validated through `mcp/path_validator.py`."
- **90%+ test coverage**: Comprehensive test plan with dedicated test classes per formatter.
- **`models.py` per phase / `orchestrator.py` per phase**: Formatter protocol lives in `shared/formatters/protocol.py` following the models-in-their-own-file pattern.
- **Existing shared/ module for cross-cutting utilities**: Formatters are a cross-cutting concern, placed under `shared/formatters/`.

### Prior Plans

- **`plans/deep-code-security.md` (APPROVED)**: This plan builds on the approved architecture. The original plan specifies "Must produce structured JSON at every phase for agent consumption" -- this feature adds additional output formats for human and tooling consumption without changing the JSON-first MCP interface. The original plan does not mention SARIF or HTML, so this is an additive feature.

### Deviations from Established Patterns

- **`string.Template` instead of Jinja2 for HTML**: CLAUDE.md mandates `SandboxedEnvironment` for PoC template rendering, but that rule applies to the Auditor phase where untrusted finding data is interpolated into executable code. For HTML output, the input is our own scan results (not untrusted code to execute), and `html.escape()` + `string.Template.safe_substitute()` is sufficient. Adding Jinja2 as a public dependency is explicitly a non-goal per the user's requirements. The template is limited to the page skeleton; repeating sections are built programmatically.

<!-- Context Metadata
discovered_at: 2026-03-13T00:00:00Z
claude_md_exists: true
recent_plans_consulted: plans/deep-code-security.md
archived_plans_consulted: none
-->
