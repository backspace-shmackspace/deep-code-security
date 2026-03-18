# Plan: Suppressions File (.dcs-suppress.yaml)

## Status: DRAFT

## Goals

1. Allow projects to suppress known false positive SAST findings via a `.dcs-suppress.yaml` file in the scanned project root.
2. Support matching suppressions by file path (glob), CWE rule, line range, and combinations thereof.
3. Track suppressed findings separately -- they are removed from the reported results but counted in scan statistics so users know suppressions are active.
4. Support an `--ignore-suppressions` CLI flag and MCP parameter to run without applying suppressions.
5. Support expiration dates on suppressions for time-limited acceptance of known issues.
6. Ensure suppressed findings are visible in all output formats (text, JSON, SARIF, HTML) via a suppression summary.

## Non-Goals

- Inline code comments for suppression (e.g., `# dcs-suppress CWE-89`). This is a separate feature that would require parser integration.
- Suppression of fuzzer findings. The fuzzer operates on runtime crash data, not static findings. Fuzzer crash triage is a different problem.
- A `dcs suppress` CLI command for interactive suppression management. Users edit the YAML file directly.
- Suppression inheritance from parent directories (`.dcs-suppress.yaml` in parent directories). Only the file at the scanned project root is loaded.
- Automatic suppression suggestion (e.g., "this looks like a false positive, suppress it?"). This requires confidence-based heuristics that are out of scope.

## Assumptions

1. The `.dcs-suppress.yaml` file lives at the root of the target project (the directory passed to `dcs hunt` / `dcs full-scan` / `dcs hunt-fuzz`, or via the `path` parameter to `deep_scan_hunt` / `deep_scan_full` / `deep_scan_hunt_fuzz` MCP tools).
2. The file is optional. If absent, no suppressions are applied and no warning is emitted.
3. The file is loaded with `yaml.safe_load()` per the CLAUDE.md security mandate.
4. The file path does NOT bypass the `PathValidator`. The suppression file is always at `<target_path>/.dcs-suppress.yaml`, and `target_path` has already been validated through `PathValidator`. The suppression file path is constructed by joining the validated target path with the fixed filename -- no user-controlled path component is involved beyond the already-validated target.
5. Suppression matching is performed after the Hunter phase produces `RawFinding` objects and after deduplication, but before pagination. This means suppressions reduce the total count and the findings list that downstream phases (Auditor, Architect, Bridge) operate on.
6. File path globs in suppressions are relative to the scanned project root, matching the relative portion of `RawFinding.sink.file` (the path to the file where the vulnerability sink is located).

## Proposed Design

### Suppression File Format

```yaml
# .dcs-suppress.yaml
version: 1

suppressions:
  # Suppress all CWE-22 findings in config loaders (admin-controlled paths)
  - rule: CWE-22
    file: "src/config/*.py"
    reason: "Config file paths come from admin-controlled environment variables, not user input"
    expires: "2026-09-01"

  # Suppress a specific false positive on a known line range
  - rule: CWE-78
    file: "scripts/deploy.py"
    lines: [42, 55]
    reason: "subprocess.run uses a hardcoded command list, taint tracker sees false source"

  # Suppress all findings in generated code
  - file: "generated/**/*.py"
    reason: "Auto-generated code, not maintained by this team"

  # Suppress a specific CWE across the entire project (use sparingly)
  - rule: CWE-134
    reason: "Format string usage is safe in this project's logging framework"
    expires: "2026-06-15"
```

### Suppression Schema

Each entry in the `suppressions` list has the following fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rule` | `string` | No | CWE identifier to match (e.g., `CWE-78`, `CWE-89`). If omitted, matches all rules. |
| `file` | `string` | No | Glob pattern for file paths, relative to project root. Supports `*` (single directory level) and `**` (recursive directory matching). If omitted, matches all files. |
| `lines` | `[int, int]` | No | Inclusive line range `[start, end]`. Matches if the sink line falls within this range. If omitted, matches all lines. |
| `reason` | `string` | **Yes** | Human-readable explanation of why this suppression exists. Required for auditability. |
| `expires` | `string` (ISO date) | No | Expiration date in `YYYY-MM-DD` format. Suppression is ignored after this date. If omitted, suppression never expires. |

**Validation rules:**
- At least one of `rule` or `file` must be present. A suppression with neither would suppress everything, which is almost certainly a mistake.
- `rule` must match the pattern `CWE-\d+` if provided.
- `lines` must be a two-element list where `lines[0] <= lines[1]`, both >= 1.
- `reason` must be a non-empty string.
- `expires` must be a valid ISO date string if provided.
- `version` must be `1`. This allows future schema changes.

### Suppression Matching Algorithm

A suppression matches a `RawFinding` if ALL of the following are true:

1. **Rule match**: If the suppression has a `rule` field, the finding's `sink.cwe` must equal the suppression's `rule`. If no `rule` field, this condition is automatically satisfied.
2. **File match**: If the suppression has a `file` field, the finding's `sink.file` (as a path relative to the scan root) must match the glob pattern using segment-aware glob matching (see "Glob Matching Implementation" below). If no `file` field, this condition is automatically satisfied.
3. **Line match**: If the suppression has a `lines` field `[start, end]`, the finding's `sink.line` must satisfy `start <= sink.line <= end`. If no `lines` field, this condition is automatically satisfied.
4. **Expiration check**: If the suppression has an `expires` field, the current date (UTC) must be on or before the expiration date. Expired suppressions are skipped (the finding is not suppressed) and a warning is logged.

A finding is suppressed if ANY suppression entry matches it (logical OR across entries). The first matching suppression is recorded as the suppression reason.

### Glob Matching Implementation

The `file` glob pattern uses segment-aware matching to provide behavior consistent with `.gitignore` and `pathlib.Path.glob()`:

- **Single `*`** matches any characters within a single path segment (does NOT cross directory boundaries). Example: `src/config/*.py` matches `src/config/loader.py` but NOT `src/config/sub/loader.py`.
- **`**`** matches zero or more directory segments. Example: `generated/**/*.py` matches `generated/foo.py`, `generated/a/b.py`, and `generated/a/b/c/foo.py`.
- **`?`** matches any single character within a path segment.

**Implementation:** Split both the pattern and the relative path on `/` into segments. Match segments using `fnmatch.fnmatch()` (which operates within a single segment without path separator concerns). Handle `**` by recursively attempting to match zero or more path segments. This is a small helper function (`_glob_match`) in `shared/suppressions.py` -- no external dependency is needed.

```python
def _glob_match(path_segments: list[str], pattern_segments: list[str]) -> bool:
    """Segment-aware glob match supporting ** for recursive directory matching."""
    pi = 0  # pattern index
    si = 0  # path segment index

    # Use a stack-based approach for ** backtracking
    stack: list[tuple[int, int]] = []

    while si < len(path_segments) or pi < len(pattern_segments):
        if pi < len(pattern_segments) and pattern_segments[pi] == "**":
            # ** matches zero or more segments; push backtrack point
            stack.append((pi, si + 1))
            pi += 1
            continue

        if (
            pi < len(pattern_segments)
            and si < len(path_segments)
            and fnmatch.fnmatch(path_segments[si], pattern_segments[pi])
        ):
            pi += 1
            si += 1
            continue

        # No match at current position; try backtracking
        if stack:
            pi, si = stack.pop()
            if si <= len(path_segments):
                stack.append((pi, si + 1))
                # pi stays at the segment after **
                continue

        return False

    return pi >= len(pattern_segments) and si >= len(path_segments)
```

The `matches()` method uses this helper instead of `fnmatch.fnmatch()` on the full path string:

```python
# In SuppressionRule.matches():
if self.file is not None:
    try:
        sink_path = Path(finding.sink.file)
        rel_path = sink_path.relative_to(project_root)
        rel_str = str(PurePosixPath(rel_path))
        path_segments = rel_str.split("/")
        pattern_segments = self.file.split("/")
        if not _glob_match(path_segments, pattern_segments):
            return False
    except ValueError:
        return False
```

### Suppression Semantics

Suppressions are applied **after Hunter deduplication but before Auditor/Architect/Bridge**. This means:

- **Suppressed findings do NOT consume Auditor sandbox slots.** They are not passed to the Auditor for PoC verification.
- **Suppressed findings do NOT generate Architect remediation guidance.** They are excluded from the Architect's input set.
- **Suppressed findings are NOT passed to the Bridge for fuzz target resolution.** They will not be selected as fuzzing targets.

This is intentional. A suppression is a statement that a finding is a known false positive or an accepted risk. Spending sandbox execution time, API credits, or fuzz iterations on findings the user has explicitly marked as non-actionable is wasteful.

The `--ignore-suppressions` flag (CLI) or `ignore_suppressions` parameter (MCP) bypasses all suppression logic. When set, all findings flow through the full pipeline as if no `.dcs-suppress.yaml` file existed. This is useful for periodic verification runs to confirm that suppressed findings have not changed character (e.g., a previously-safe config reader is now tainted by user input).

### Suppression File Size Limits

To prevent denial-of-service via a maliciously large suppression file (e.g., in an attacker-controlled repository scanned by a CI pipeline), the loader enforces two limits:

- **`_MAX_SUPPRESSION_FILE_SIZE = 65536`** (64 KB): The file size is checked before reading. Files exceeding this limit raise `SuppressionLoadError` with the message: "Suppression file exceeds maximum size of 64KB ({actual_size} bytes). Reduce the number of rules or use broader patterns."
- **`_MAX_SUPPRESSION_RULES = 500`**: The number of parsed rules is checked after `yaml.safe_load()`. Configs exceeding this limit raise `SuppressionLoadError` with the message: "Suppression file contains {count} rules (maximum: 500). Reduce the number of rules or use broader patterns."

These limits follow the existing pattern of `DCS_MAX_FILES`, `DCS_MAX_RESULTS`, etc. `SuppressionLoadError` is a subclass of `ValueError` so existing error handling in CLI and MCP continues to work.

### Architecture

The suppression system is implemented as a standalone module under `shared/` since it is a cross-cutting concern used by the Hunter orchestrator, CLI, and MCP server.

```
src/deep_code_security/
    shared/
        suppressions.py      # SuppressionRule model, SuppressionConfig model,
                              # load_suppressions(), apply_suppressions(),
                              # _glob_match(), SuppressionLoadError
```

#### Pydantic Models

```python
# shared/suppressions.py
from __future__ import annotations

import datetime
import fnmatch
import logging
import re
from pathlib import Path, PurePosixPath

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from deep_code_security.hunter.models import RawFinding

__all__ = [
    "SuppressionLoadError",
    "SuppressionRule",
    "SuppressionConfig",
    "SuppressionResult",
    "load_suppressions",
    "apply_suppressions",
]

logger = logging.getLogger(__name__)

_CWE_PATTERN = re.compile(r"^CWE-\d+$")
_SUPPRESS_FILENAME = ".dcs-suppress.yaml"
_MAX_SUPPRESSION_FILE_SIZE = 65536  # 64 KB
_MAX_SUPPRESSION_RULES = 500


class SuppressionLoadError(ValueError):
    """Raised when a suppression file cannot be loaded due to size/rule limits."""

    pass


def _glob_match(path_segments: list[str], pattern_segments: list[str]) -> bool:
    """Segment-aware glob match supporting ** for recursive directory matching.

    Single * matches within one segment only (does not cross / boundaries).
    ** matches zero or more complete segments.
    """
    pi = 0  # pattern index
    si = 0  # path segment index

    stack: list[tuple[int, int]] = []

    while si < len(path_segments) or pi < len(pattern_segments):
        if pi < len(pattern_segments) and pattern_segments[pi] == "**":
            stack.append((pi, si + 1))
            pi += 1
            continue

        if (
            pi < len(pattern_segments)
            and si < len(path_segments)
            and fnmatch.fnmatch(path_segments[si], pattern_segments[pi])
        ):
            pi += 1
            si += 1
            continue

        if stack:
            pi, si = stack.pop()
            if si <= len(path_segments):
                stack.append((pi, si + 1))
                continue

        return False

    return pi >= len(pattern_segments) and si >= len(path_segments)


class SuppressionRule(BaseModel):
    """A single suppression rule from the suppressions file."""

    rule: str | None = Field(
        default=None,
        description="CWE identifier to match (e.g., 'CWE-78')",
    )
    file: str | None = Field(
        default=None,
        description="Glob pattern for file paths, relative to project root",
    )
    lines: list[int] | None = Field(
        default=None,
        description="Inclusive line range [start, end]",
    )
    reason: str = Field(
        ...,
        min_length=1,
        description="Explanation for this suppression (required for auditability)",
    )
    expires: str | None = Field(
        default=None,
        description="Expiration date in YYYY-MM-DD format",
    )

    model_config = {"frozen": True}

    @field_validator("rule")
    @classmethod
    def validate_rule(cls, v: str | None) -> str | None:
        if v is not None and not _CWE_PATTERN.match(v):
            raise ValueError(
                f"Invalid rule format: {v!r}. Must match 'CWE-<number>' (e.g., 'CWE-78')"
            )
        return v

    @field_validator("lines")
    @classmethod
    def validate_lines(cls, v: list[int] | None) -> list[int] | None:
        if v is not None:
            if len(v) != 2:
                raise ValueError("lines must be a two-element list [start, end]")
            if v[0] < 1 or v[1] < 1:
                raise ValueError("line numbers must be >= 1")
            if v[0] > v[1]:
                raise ValueError(
                    f"lines[0] ({v[0]}) must be <= lines[1] ({v[1]})"
                )
        return v

    @field_validator("expires")
    @classmethod
    def validate_expires(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                datetime.date.fromisoformat(v)
            except ValueError:
                raise ValueError(
                    f"Invalid expires date: {v!r}. Must be YYYY-MM-DD format."
                )
        return v

    @model_validator(mode="after")
    def validate_at_least_one_matcher(self) -> SuppressionRule:
        if self.rule is None and self.file is None:
            raise ValueError(
                "At least one of 'rule' or 'file' must be specified "
                "in a suppression entry"
            )
        return self

    def is_expired(self, today: datetime.date | None = None) -> bool:
        """Check if this suppression has expired."""
        if self.expires is None:
            return False
        check_date = today or datetime.datetime.now(
            datetime.timezone.utc
        ).date()
        return check_date > datetime.date.fromisoformat(self.expires)

    def matches(
        self,
        finding: RawFinding,
        project_root: Path,
        today: datetime.date | None = None,
    ) -> bool:
        """Check if this suppression matches a finding."""
        # Check expiration first
        if self.is_expired(today):
            return False

        # Check rule match
        if self.rule is not None and finding.sink.cwe != self.rule:
            return False

        # Check file match (segment-aware glob against relative path)
        if self.file is not None:
            try:
                sink_path = Path(finding.sink.file)
                rel_path = sink_path.relative_to(project_root)
                # Use PurePosixPath for consistent forward-slash matching
                rel_str = str(PurePosixPath(rel_path))
                path_segments = rel_str.split("/")
                pattern_segments = self.file.split("/")
                if not _glob_match(path_segments, pattern_segments):
                    return False
            except ValueError:
                # sink.file is not relative to project root
                return False

        # Check line range match
        if self.lines is not None:
            if not (self.lines[0] <= finding.sink.line <= self.lines[1]):
                return False

        return True


class SuppressionConfig(BaseModel):
    """Parsed suppressions file."""

    version: int = Field(..., description="Schema version (must be 1)")
    suppressions: list[SuppressionRule] = Field(
        default_factory=list,
        description="List of suppression rules",
    )

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: int) -> int:
        if v != 1:
            raise ValueError(
                f"Unsupported suppressions file version: {v}. "
                f"Only version 1 is supported."
            )
        return v


class SuppressionResult(BaseModel):
    """Result of applying suppressions to a findings list."""

    active_findings: list[RawFinding] = Field(
        default_factory=list,
        description="Findings that were NOT suppressed",
    )
    suppressed_findings: list[RawFinding] = Field(
        default_factory=list,
        description="Findings that WERE suppressed",
    )
    suppression_reasons: dict[str, str] = Field(
        default_factory=dict,
        description="Map of finding_id -> suppression reason",
    )
    expired_rules: int = Field(
        default=0,
        description="Number of expired suppression rules (skipped)",
    )
    total_rules: int = Field(
        default=0,
        description="Total suppression rules loaded",
    )
    suppression_file_path: str = Field(
        default="",
        description="Path to the loaded suppressions file",
    )


def load_suppressions(project_root: Path) -> SuppressionConfig | None:
    """Load the suppressions file from the project root.

    Args:
        project_root: Absolute path to the scanned project root.

    Returns:
        SuppressionConfig if the file exists and is valid, None if the file
        does not exist. Raises SuppressionLoadError if the file exceeds size
        or rule count limits. Raises ValueError if the file exists but is
        malformed.
    """
    suppress_path = project_root / _SUPPRESS_FILENAME
    if not suppress_path.is_file():
        return None

    # Check file size before reading (DoS prevention)
    try:
        file_size = suppress_path.stat().st_size
    except OSError as e:
        logger.warning(
            "Cannot stat suppressions file %s: %s", suppress_path, e
        )
        return None

    if file_size > _MAX_SUPPRESSION_FILE_SIZE:
        raise SuppressionLoadError(
            f"Suppression file exceeds maximum size of 64KB "
            f"({file_size} bytes). Reduce the number of rules or use "
            f"broader patterns."
        )

    try:
        content = suppress_path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning(
            "Cannot read suppressions file %s: %s", suppress_path, e
        )
        return None

    # SECURITY: Always use yaml.safe_load() -- never yaml.load()
    try:
        raw = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ValueError(
            f"Invalid YAML in suppressions file {suppress_path}: {e}"
        ) from e

    if raw is None:
        # Empty file
        return SuppressionConfig(version=1, suppressions=[])

    if not isinstance(raw, dict):
        raise ValueError(
            f"Suppressions file must contain a YAML mapping, "
            f"got {type(raw).__name__}"
        )

    # Check rule count after parsing (DoS prevention)
    raw_suppressions = raw.get("suppressions", [])
    if isinstance(raw_suppressions, list) and len(raw_suppressions) > _MAX_SUPPRESSION_RULES:
        raise SuppressionLoadError(
            f"Suppression file contains {len(raw_suppressions)} rules "
            f"(maximum: {_MAX_SUPPRESSION_RULES}). Reduce the number of "
            f"rules or use broader patterns."
        )

    try:
        return SuppressionConfig(**raw)
    except Exception as e:
        raise ValueError(
            f"Invalid suppressions file {suppress_path}: {e}"
        ) from e


def apply_suppressions(
    findings: list[RawFinding],
    config: SuppressionConfig,
    project_root: Path,
    today: datetime.date | None = None,
) -> SuppressionResult:
    """Apply suppressions to a list of findings.

    Args:
        findings: List of RawFinding objects from the Hunter phase.
        config: Parsed suppressions configuration.
        project_root: Absolute path to the scanned project root
                      (for relative path computation).
        today: Override for the current date (for testing expiration).

    Returns:
        SuppressionResult with active and suppressed findings separated.
    """
    active: list[RawFinding] = []
    suppressed: list[RawFinding] = []
    reasons: dict[str, str] = {}

    # Count expired rules
    expired_count = sum(
        1 for rule in config.suppressions if rule.is_expired(today)
    )
    if expired_count > 0:
        logger.warning(
            "%d suppression rule(s) have expired and will not be applied",
            expired_count,
        )

    for finding in findings:
        matched_rule: SuppressionRule | None = None
        for rule in config.suppressions:
            if rule.matches(finding, project_root, today):
                matched_rule = rule
                break

        if matched_rule is not None:
            suppressed.append(finding)
            reasons[finding.id] = matched_rule.reason
        else:
            active.append(finding)

    return SuppressionResult(
        active_findings=active,
        suppressed_findings=suppressed,
        suppression_reasons=reasons,
        expired_rules=expired_count,
        total_rules=len(config.suppressions),
        suppression_file_path=str(project_root / _SUPPRESS_FILENAME),
    )
```

### Integration Points

#### 1. Hunter Orchestrator (`hunter/orchestrator.py`)

The `HunterOrchestrator.scan()` method is modified to accept an `ignore_suppressions` parameter. When `False` (the default), it loads `.dcs-suppress.yaml` from the target path and applies suppressions after deduplication but before sorting and pagination.

**The return signature is NOT changed.** Instead of adding a 5th tuple element, suppression metadata is embedded into the already-returned `ScanStats` object. This keeps the 4-tuple return signature backward compatible -- no existing call site needs to change its unpacking pattern.

**Updated signature (parameter added, return type unchanged):**

```python
def scan(
    self,
    target_path: str | Path,
    languages: list[str] | None = None,
    severity_threshold: str = "medium",
    max_results: int = 100,
    offset: int = 0,
    ignore_suppressions: bool = False,
) -> tuple[list[RawFinding], ScanStats, int, bool]:
```

**Suppression application point** (after deduplication, before sorting):

```python
# After: all_findings = _deduplicate_findings(all_findings)
# Apply suppressions
suppression_result: SuppressionResult | None = None
if not ignore_suppressions:
    suppress_config = load_suppressions(target_path)
    if suppress_config is not None:
        suppression_result = apply_suppressions(
            all_findings, suppress_config, target_path
        )
        all_findings = suppression_result.active_findings
        logger.info(
            "Suppressions applied: %d suppressed, %d active (%d rules, %d expired)",
            len(suppression_result.suppressed_findings),
            len(suppression_result.active_findings),
            suppression_result.total_rules,
            suppression_result.expired_rules,
        )

# Populate ScanStats suppression fields from SuppressionResult
# (done after suppression application, before stats object is finalized)
stats.findings_suppressed = (
    len(suppression_result.suppressed_findings) if suppression_result else 0
)
stats.suppression_rules_loaded = (
    suppression_result.total_rules if suppression_result else 0
)
stats.suppression_rules_expired = (
    suppression_result.expired_rules if suppression_result else 0
)
stats.suppressed_finding_ids = (
    list(suppression_result.suppression_reasons.keys()) if suppression_result else []
)

# Then: sort, paginate, return (4-tuple unchanged)
```

The orchestrator also stores the `SuppressionResult` as an instance variable (`self._last_suppression_result`) so that the CLI and MCP server can retrieve suppression details (including suppressed finding objects for SARIF output and suppression reasons for summary output) without changing the return signature.

```python
# After applying suppressions:
self._last_suppression_result = suppression_result

# Public accessor:
@property
def last_suppression_result(self) -> SuppressionResult | None:
    """Return the SuppressionResult from the most recent scan, or None."""
    return self._last_suppression_result
```

#### 2. ScanStats Model Update (`hunter/models.py`)

Add suppression tracking fields to `ScanStats`:

```python
class ScanStats(BaseModel):
    # ... existing fields ...
    findings_suppressed: int = Field(default=0, ge=0)
    suppression_rules_loaded: int = Field(default=0, ge=0)
    suppression_rules_expired: int = Field(default=0, ge=0)
    suppressed_finding_ids: list[str] = Field(default_factory=list)
```

After applying suppressions, the orchestrator populates these fields from the `SuppressionResult`. The `suppressed_finding_ids` field carries the IDs of suppressed findings so that downstream consumers (formatters, MCP responses) can reference which findings were suppressed without requiring the full `RawFinding` objects in the return tuple.

Note: `ScanStats.taint_paths_found` intentionally reflects pre-suppression counts. It represents what the scanner found, not what was suppressed.

#### 3. CLI Changes (`cli.py`)

Add `--ignore-suppressions` flag to `hunt`, `full-scan`, and `hunt-fuzz` commands:

```python
@click.option(
    "--ignore-suppressions", is_flag=True, default=False,
    help="Ignore .dcs-suppress.yaml and report all findings.",
)
```

The CLI passes this flag through to `HunterOrchestrator.scan()`.

The CLI retrieves the `SuppressionResult` from `orchestrator.last_suppression_result` to build the `SuppressionSummary` for formatter DTOs and to populate `HuntResult.suppressed_finding_ids` for SARIF output.

#### 4. MCP Server Changes (`mcp/server.py`)

Add `ignore_suppressions` parameter to `deep_scan_hunt`, `deep_scan_full`, and `deep_scan_hunt_fuzz` tool schemas:

```python
"ignore_suppressions": {
    "type": "boolean",
    "default": False,
    "description": "Ignore .dcs-suppress.yaml suppression rules",
},
```

The MCP handlers pass this through to `HunterOrchestrator.scan()`.

The MCP response JSON includes suppression summary data read from `ScanStats`:

```python
# In the hunt response
"suppressions": {
    "suppressed_count": stats.findings_suppressed,
    "total_rules": stats.suppression_rules_loaded,
    "expired_rules": stats.suppression_rules_expired,
    "suppressed_finding_ids": stats.suppressed_finding_ids,
}
```

Note: Suppression is applied at the Hunt phase only. The MCP session store reflects the findings from the most recent Hunt invocation (with or without suppressions as configured). `deep_scan_verify` and `deep_scan_remediate` operate on session state and are not updated -- they will only see non-suppressed findings when suppressions are active, which is the correct behavior.

#### 5. Formatter DTO Changes (`shared/formatters/protocol.py`)

Add a suppression summary DTO and include it in `HuntResult`, `FullScanResult`, and ensure `HuntFuzzResult` inherits it:

```python
class SuppressionSummary(BaseModel):
    """Summary of applied suppressions for formatter output."""

    suppressed_count: int = 0
    total_rules: int = 0
    expired_rules: int = 0
    suppression_reasons: dict[str, str] = Field(default_factory=dict)
    suppression_file: str = ""

class HuntResult(BaseModel):
    findings: list[RawFinding] = Field(default_factory=list)
    stats: ScanStats
    total_count: int = 0
    has_more: bool = False
    suppression_summary: SuppressionSummary | None = None  # NEW
    suppressed_finding_ids: list[str] = Field(default_factory=list)  # NEW
```

Similarly for `FullScanResult`:

```python
class FullScanResult(BaseModel):
    # ... existing fields ...
    suppression_summary: SuppressionSummary | None = None  # NEW
    suppressed_finding_ids: list[str] = Field(default_factory=list)  # NEW
```

`HuntFuzzResult` wraps a `HuntResult` (via `hunt_result: HuntResult`), so the `suppression_summary` and `suppressed_finding_ids` fields propagate automatically through `data.hunt_result.suppression_summary`. No separate top-level field is needed on `HuntFuzzResult`. The `format_hunt_fuzz` methods in each formatter read suppression data from `data.hunt_result.suppression_summary`.

For SARIF output, the SARIF formatter needs the actual suppressed `RawFinding` objects to emit proper SARIF results with locations, code flows, and `suppressions[]` arrays. Rather than carrying full finding objects through the DTO (which would bloat the DTO for all formatters), the SARIF formatter receives suppressed findings through a separate channel: the CLI/MCP handler retrieves suppressed findings from `orchestrator.last_suppression_result.suppressed_findings` and passes them to the SARIF formatter via a `context` dict or by temporarily populating a `_suppressed_findings` field on the DTO before formatting. This keeps the core DTOs lean while supporting the SARIF spec.

#### 6. Formatter Updates

Each formatter is updated to include suppression information in its output when a `SuppressionSummary` is present:

**TextFormatter**: Appends a suppression summary line:
```
Scanned 50 files, found 12 findings (3 suppressed) (250ms)
```

**JsonFormatter**: Includes a `suppressions` key in the output object:
```json
{
  "findings": [...],
  "stats": {...},
  "suppressions": {
    "suppressed_count": 3,
    "total_rules": 5,
    "expired_rules": 1,
    "reasons": {"<finding_id>": "reason", ...}
  }
}
```

**SarifFormatter**: Adds suppressed findings as SARIF results with `"suppressions"` property per the SARIF 2.1.0 spec:
```json
{
  "ruleId": "CWE-22",
  "level": "error",
  "suppressions": [
    {
      "kind": "inSource",
      "justification": "Config file paths come from admin-controlled environment variables"
    }
  ]
}
```
This is the SARIF-standard mechanism for inline suppressions. Suppressed findings are included in the SARIF output with the `suppressions` array populated, which allows SARIF consumers (DefectDojo, GitHub) to filter them client-side.

**HtmlFormatter**: Shows a collapsible suppression section with the count and table of suppressed findings with their reasons.

### Security Considerations

1. **yaml.safe_load() only**: The suppressions file is loaded exclusively with `yaml.safe_load()`. This is enforced by the implementation and tested explicitly.
2. **No path validator bypass**: The suppression file path is always `<validated_target_path>/.dcs-suppress.yaml`. The target path has already passed through `PathValidator`. The suppression file path uses a hardcoded filename joined to the validated path -- no user-controlled path component is introduced.
3. **No eval/exec**: Suppression matching uses simple string comparison, segment-aware glob matching via `fnmatch` on individual segments, and integer comparison. No code execution is involved.
4. **Glob patterns are read-only matchers**: The `file` glob in suppressions uses `_glob_match()` for pattern matching against relative paths. This is a pure string operation with no filesystem access.
5. **Malformed file is an error**: An invalid `.dcs-suppress.yaml` raises `ValueError` (not silently ignored), forcing the user to fix it rather than running with unexpected suppression behavior.
6. **File size and rule count limits**: The loader enforces a 64 KB file size limit and a 500 rule count limit to prevent DoS from maliciously large suppression files in attacker-controlled repositories scanned by CI pipelines.

## Interfaces / Schema Changes

### New Public API

| Module | Symbol | Type | Description |
|--------|--------|------|-------------|
| `shared.suppressions` | `SuppressionLoadError` | Exception class | Raised when suppression file exceeds size/rule limits |
| `shared.suppressions` | `SuppressionRule` | Pydantic model | A single suppression entry |
| `shared.suppressions` | `SuppressionConfig` | Pydantic model | Parsed suppressions file |
| `shared.suppressions` | `SuppressionResult` | Pydantic model | Result of applying suppressions |
| `shared.suppressions` | `load_suppressions(project_root)` | function | Load `.dcs-suppress.yaml` |
| `shared.suppressions` | `apply_suppressions(findings, config, root)` | function | Filter findings against suppressions |
| `shared.formatters.protocol` | `SuppressionSummary` | Pydantic model | Suppression data for formatters |

### Modified Public API

| Module | Symbol | Change |
|--------|--------|--------|
| `hunter.orchestrator.HunterOrchestrator.scan()` | Parameters | Adds `ignore_suppressions: bool = False` |
| `hunter.orchestrator.HunterOrchestrator` | Property | Adds `last_suppression_result: SuppressionResult \| None` |
| `hunter.models.ScanStats` | Fields | Adds `findings_suppressed`, `suppression_rules_loaded`, `suppression_rules_expired`, `suppressed_finding_ids` |
| `shared.formatters.protocol.HuntResult` | Fields | Adds `suppression_summary: SuppressionSummary \| None`, `suppressed_finding_ids: list[str]` |
| `shared.formatters.protocol.FullScanResult` | Fields | Adds `suppression_summary: SuppressionSummary \| None`, `suppressed_finding_ids: list[str]` |

Note: `HuntFuzzResult` inherits suppression data transitively via its `hunt_result: HuntResult` field. No separate suppression field is needed on `HuntFuzzResult` itself.

### CLI Option Changes

| Command | New Option | Description |
|---------|-----------|-------------|
| `hunt` | `--ignore-suppressions` | Skip loading `.dcs-suppress.yaml` |
| `full-scan` | `--ignore-suppressions` | Skip loading `.dcs-suppress.yaml` |
| `hunt-fuzz` | `--ignore-suppressions` | Skip loading `.dcs-suppress.yaml` |

### MCP Schema Changes

| Tool | New Parameter | Type | Default |
|------|--------------|------|---------|
| `deep_scan_hunt` | `ignore_suppressions` | `boolean` | `false` |
| `deep_scan_full` | `ignore_suppressions` | `boolean` | `false` |
| `deep_scan_hunt_fuzz` | `ignore_suppressions` | `boolean` | `false` |

## Data Migration

None. No persistent state is affected. The `.dcs-suppress.yaml` file is optional and user-created.

## Rollout Plan

This is a single-release feature addition with no phased rollout needed.

1. **Implement** the suppression module, model changes, orchestrator integration, CLI flags, MCP parameters, and formatter updates in a single branch.
2. **Test** with `make test` (unit + coverage) and manual testing with sample suppression files.
3. **Release** as part of the next version bump.

### Backward Compatibility

- **No breaking changes**: All new parameters have defaults. The `scan()` return type remains a 4-tuple -- suppression metadata is embedded in `ScanStats` (which is already the 2nd tuple element). No existing unpacking pattern needs to change.
- **Default behavior unchanged**: Without a `.dcs-suppress.yaml` file, behavior is identical to today. `ScanStats` suppression fields default to 0/empty.
- **ScanStats fields added with defaults**: New `ScanStats` fields default to 0 and `[]`, so existing serialized stats remain valid.
- **Formatter DTOs extended**: `HuntResult.suppression_summary` defaults to `None` and `suppressed_finding_ids` defaults to `[]`, so existing formatter code that does not reference these fields continues to work.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Overly broad suppressions hide real vulnerabilities | Medium | High | Require `reason` field for auditability. Support `expires` for time-limited suppressions. Show suppression count in all output formats. Use `--ignore-suppressions` for periodic full-pipeline verification runs. |
| Malformed `.dcs-suppress.yaml` blocks scanning | Low | Medium | Raise `ValueError` with a clear message pointing to the file and the validation error. Users can add `--ignore-suppressions` to unblock. |
| Glob pattern matching differs from user expectations | Low | Medium | Use segment-aware matching where `*` does not cross directory boundaries and `**` matches zero-or-more directories. Document semantics in suppression file format description. Comprehensive test cases cover edge cases. |
| SARIF consumers do not understand `suppressions[]` array | Low | Low | `suppressions` is a first-class SARIF 2.1.0 concept. DefectDojo and GitHub Code Scanning both handle it correctly. |
| File path in suppression does not match due to absolute vs relative path confusion | Medium | Medium | Document clearly that `file` patterns are relative to the project root. Compute relative paths using `Path.relative_to()` with clear error handling. |
| Performance impact from loading/parsing suppression file | Low | Low | The file is loaded once per scan, parsed with `yaml.safe_load()`, and validated with Pydantic. Matching is O(findings * rules) with simple string/glob operations. Both are small numbers. File size (64 KB) and rule count (500) limits prevent pathological cases. |
| Malicious suppression file causes DoS in CI pipeline | Low | Medium | File size limit (64 KB) and rule count limit (500) prevent memory exhaustion and O(n*m) slowdown. `SuppressionLoadError` provides actionable messages. |

## Test Plan

### Test Command

```bash
make test
```

This runs `pytest tests/ -v --cov=src/deep_code_security --cov-report=term-missing --cov-fail-under=90 --ignore=tests/test_integration`.

### Test Structure

New tests go in `tests/test_shared/test_suppressions.py`. Updates to existing test files are listed below.

```
tests/
    test_shared/
        test_suppressions.py           # Core suppression logic tests
    test_hunter/
        test_orchestrator.py           # Updated: suppression integration tests
    test_shared/
        test_formatters/
            test_text.py               # Updated: suppression summary in text output
            test_json.py               # Updated: suppression summary in JSON output
            test_sarif.py              # Updated: SARIF suppressions array
            test_html.py               # Updated: suppression section in HTML
```

### Test Cases

**Suppression Models and Loading (`test_suppressions.py`):**

- `test_suppression_rule_valid_rule_only` -- valid rule with CWE pattern
- `test_suppression_rule_valid_file_only` -- valid file glob without rule
- `test_suppression_rule_valid_rule_and_file` -- both rule and file specified
- `test_suppression_rule_valid_with_lines` -- valid line range
- `test_suppression_rule_valid_with_expires` -- valid expiration date
- `test_suppression_rule_invalid_no_rule_no_file` -- raises ValidationError when both omitted
- `test_suppression_rule_invalid_rule_format` -- raises for "SQL Injection" (not CWE-xx)
- `test_suppression_rule_invalid_lines_single` -- raises for `[42]` (not two elements)
- `test_suppression_rule_invalid_lines_reversed` -- raises for `[55, 42]`
- `test_suppression_rule_invalid_lines_zero` -- raises for `[0, 10]`
- `test_suppression_rule_invalid_expires_format` -- raises for "March 2026"
- `test_suppression_rule_missing_reason` -- raises when reason is omitted
- `test_suppression_rule_empty_reason` -- raises when reason is ""
- `test_suppression_config_valid` -- parses complete config
- `test_suppression_config_invalid_version` -- raises for version 2
- `test_suppression_config_empty_suppressions` -- valid with empty list

**Suppression Loading (`test_suppressions.py`):**

- `test_load_suppressions_file_exists` -- loads valid file, returns SuppressionConfig
- `test_load_suppressions_file_missing` -- returns None
- `test_load_suppressions_file_empty` -- returns config with empty suppressions
- `test_load_suppressions_file_malformed_yaml` -- raises ValueError
- `test_load_suppressions_file_wrong_type` -- raises ValueError for "just a string"
- `test_load_suppressions_uses_safe_load` -- verify yaml.safe_load is used (mock yaml.load to fail if called)
- `test_load_suppressions_invalid_schema` -- raises ValueError for missing version
- `test_load_suppressions_file_too_large` -- raises SuppressionLoadError for file > 64 KB
- `test_load_suppressions_too_many_rules` -- raises SuppressionLoadError for > 500 rules

**Suppression Matching (`test_suppressions.py`):**

- `test_matches_rule_only` -- CWE match
- `test_matches_rule_mismatch` -- different CWE does not match
- `test_matches_file_glob_single_star` -- `src/config/*.py` matches `src/config/loader.py`
- `test_matches_file_glob_single_star_no_cross_directory` -- `src/config/*.py` does NOT match `src/config/sub/loader.py`
- `test_matches_file_glob_recursive_zero_dirs` -- `generated/**/*.py` matches `generated/foo.py`
- `test_matches_file_glob_recursive_one_dir` -- `generated/**/*.py` matches `generated/a/foo.py`
- `test_matches_file_glob_recursive_deep` -- `generated/**/*.py` matches `generated/a/b/c/foo.py`
- `test_matches_file_glob_mismatch` -- `src/config/*.py` does not match `src/handlers/api.py`
- `test_matches_lines_within_range` -- sink line 45 matches [42, 55]
- `test_matches_lines_outside_range` -- sink line 60 does not match [42, 55]
- `test_matches_lines_boundary_start` -- sink line 42 matches [42, 55]
- `test_matches_lines_boundary_end` -- sink line 55 matches [42, 55]
- `test_matches_combined_rule_and_file` -- both must match
- `test_matches_combined_partial_mismatch` -- rule matches but file does not = no match
- `test_matches_expired_suppression` -- expired rule does not match
- `test_matches_not_yet_expired` -- rule expiring tomorrow still matches
- `test_matches_expires_today` -- rule expiring today still matches (inclusive)

**Glob Matching (`test_suppressions.py`):**

- `test_glob_match_single_star_no_slash` -- `*.py` matches `foo.py`
- `test_glob_match_single_star_blocks_slash` -- `src/*.py` does NOT match `src/sub/foo.py`
- `test_glob_match_double_star_zero` -- `**/*.py` matches `foo.py`
- `test_glob_match_double_star_deep` -- `**/*.py` matches `a/b/c/foo.py`
- `test_glob_match_middle_double_star` -- `src/**/test.py` matches `src/a/b/test.py`
- `test_glob_match_exact` -- `src/config/loader.py` matches exactly

**Suppression Application (`test_suppressions.py`):**

- `test_apply_suppressions_no_matches` -- all findings remain active
- `test_apply_suppressions_one_match` -- one finding suppressed, rest active
- `test_apply_suppressions_all_match` -- all findings suppressed
- `test_apply_suppressions_records_reasons` -- reason dict populated correctly
- `test_apply_suppressions_first_rule_wins` -- first matching rule's reason is recorded
- `test_apply_suppressions_expired_rules_counted` -- expired_rules count correct
- `test_apply_suppressions_multiple_rules` -- different rules suppress different findings

**Orchestrator Integration (`test_orchestrator.py` updates):**

- `test_scan_with_suppression_file` -- findings suppressed when file exists
- `test_scan_without_suppression_file` -- ScanStats suppression fields are 0/empty when file absent
- `test_scan_ignore_suppressions_flag` -- all findings returned when flag is True
- `test_scan_stats_include_suppression_counts` -- ScanStats.findings_suppressed, suppression_rules_loaded, suppression_rules_expired, suppressed_finding_ids populated
- `test_scan_return_tuple_unchanged` -- return value is still a 4-tuple
- `test_scan_last_suppression_result` -- orchestrator.last_suppression_result populated after scan with suppression file

**CLI Error Handling:**

- `test_cli_hunt_malformed_suppression_file` -- CLI exits with code 1, prints user-friendly error to stderr
- `test_cli_full_scan_malformed_suppression_file` -- CLI exits with code 1, prints user-friendly error to stderr

**Formatter Tests (updates to existing test files):**

- `test_text_format_hunt_with_suppressions` -- output includes suppression count
- `test_json_format_hunt_with_suppressions` -- JSON includes `suppressions` key
- `test_sarif_format_hunt_with_suppressions` -- suppressed findings have `suppressions[]` array
- `test_html_format_hunt_with_suppressions` -- HTML includes suppression section
- `test_text_format_hunt_no_suppressions` -- output unchanged when no suppressions
- `test_json_format_hunt_no_suppressions` -- no `suppressions` key when summary is None

## Acceptance Criteria

1. A `.dcs-suppress.yaml` file at the project root suppresses matching findings from `dcs hunt` output.
2. Suppressed findings are counted separately in scan stats (`findings_suppressed` field in `ScanStats`).
3. `dcs hunt <path> --ignore-suppressions` reports all findings regardless of the suppression file.
4. `dcs full-scan <path>` respects suppressions (suppressed findings are not passed to Auditor or Architect). This is intentional -- see "Suppression Semantics" section.
5. `dcs hunt-fuzz <path>` respects suppressions (suppressed findings are not passed to Bridge for fuzz target resolution). This is intentional -- see "Suppression Semantics" section.
6. MCP tools (`deep_scan_hunt`, `deep_scan_full`, `deep_scan_hunt_fuzz`) respect suppressions and accept `ignore_suppressions` parameter.
7. Invalid `.dcs-suppress.yaml` files produce a clear error message pointing to the file and the validation failure.
8. Expired suppressions are not applied and a warning is logged.
9. SARIF output includes SARIF-standard `suppressions[]` array on suppressed findings.
10. JSON output includes a `suppressions` object with counts and reasons.
11. Text output includes a suppression count in the summary line.
12. HTML output includes a suppression section.
13. `make test` passes with 90%+ coverage.
14. `make lint` passes.
15. No `yaml.load()` anywhere -- only `yaml.safe_load()`.
16. No new runtime dependencies added.
17. Glob patterns use segment-aware matching: `*` does not cross directory boundaries, `**` matches zero-or-more directories.
18. Suppression file size is limited to 64 KB and 500 rules.
19. `HunterOrchestrator.scan()` return type remains a 4-tuple (no breaking change).

## Task Breakdown

### Phase 1: Core Suppression Module

**Task 1.1: Create suppression models, glob matcher, and loader**
- Create: `src/deep_code_security/shared/suppressions.py`
- Contents: `SuppressionLoadError`, `_glob_match()` helper, `SuppressionRule`, `SuppressionConfig`, `SuppressionResult` Pydantic models; `load_suppressions()` function; `apply_suppressions()` function
- Key constraints: `yaml.safe_load()` only, segment-aware `_glob_match()` for glob matching, `datetime.datetime.now(datetime.timezone.utc).date()` for expiration checking, 64 KB file size limit, 500 rule count limit

**Task 1.2: Create suppression tests**
- Create: `tests/test_shared/test_suppressions.py`
- Contents: All test cases listed in "Suppression Models and Loading", "Suppression Loading", "Suppression Matching", "Glob Matching", and "Suppression Application" sections above

### Phase 2: Hunter Integration

**Task 2.1: Update ScanStats model**
- Modify: `src/deep_code_security/hunter/models.py`
- Add fields: `findings_suppressed: int`, `suppression_rules_loaded: int`, `suppression_rules_expired: int` (all defaulting to 0), `suppressed_finding_ids: list[str]` (defaulting to `[]`)

**Task 2.2: Integrate suppressions into HunterOrchestrator**
- Modify: `src/deep_code_security/hunter/orchestrator.py`
- Changes:
  - Add `ignore_suppressions: bool = False` parameter to `scan()`
  - Return type remains `tuple[list[RawFinding], ScanStats, int, bool]` (unchanged)
  - Call `load_suppressions()` and `apply_suppressions()` after deduplication
  - Populate `ScanStats` suppression fields from `SuppressionResult`
  - Store `SuppressionResult` as `self._last_suppression_result` instance variable
  - Add `last_suppression_result` property
  - Handle `ValueError`/`SuppressionLoadError` from malformed/oversized suppression files (log error, re-raise)

**Task 2.3: Update orchestrator tests**
- Modify: `tests/test_hunter/test_orchestrator.py`
- Add test cases listed in "Orchestrator Integration" section above
- Existing tests do NOT need unpacking changes (return type is still a 4-tuple)

### Phase 3: Formatter DTO and Output Updates

**Task 3.1: Add SuppressionSummary DTO and update result DTOs**
- Modify: `src/deep_code_security/shared/formatters/protocol.py`
- Add: `SuppressionSummary` model
- Modify: `HuntResult` -- add `suppression_summary: SuppressionSummary | None = None` and `suppressed_finding_ids: list[str] = Field(default_factory=list)`
- Modify: `FullScanResult` -- add `suppression_summary: SuppressionSummary | None = None` and `suppressed_finding_ids: list[str] = Field(default_factory=list)`
- Note: `HuntFuzzResult` inherits suppression data via `hunt_result: HuntResult` -- no changes needed
- Update: `__all__` to include `SuppressionSummary`

**Task 3.2: Update TextFormatter**
- Modify: `src/deep_code_security/shared/formatters/text.py`
- Changes: Include suppression count in summary line when `suppression_summary` is not None
- Update: `tests/test_shared/test_formatters/test_text.py` with suppression test cases

**Task 3.3: Update JsonFormatter**
- Modify: `src/deep_code_security/shared/formatters/json.py`
- Changes: Include `suppressions` key in JSON output when `suppression_summary` is not None
- Update: `tests/test_shared/test_formatters/test_json.py` with suppression test cases

**Task 3.4: Update SarifFormatter**
- Modify: `src/deep_code_security/shared/formatters/sarif.py`
- Changes: Emit suppressed findings as results with SARIF-standard `suppressions[]` array. The SARIF formatter retrieves suppressed findings from `orchestrator.last_suppression_result.suppressed_findings` (passed via CLI/MCP handler). It uses `suppression_summary.suppression_reasons` to look up justification text per finding ID.
- Update: `tests/test_shared/test_formatters/test_sarif.py` with suppression test cases

**Task 3.5: Update HtmlFormatter**
- Modify: `src/deep_code_security/shared/formatters/html.py`
- Changes: Add collapsible suppression section showing count and table of suppressed findings with reasons
- Update: `tests/test_shared/test_formatters/test_html.py` with suppression test cases

### Phase 4: CLI Integration

**Task 4.1: Update CLI commands**
- Modify: `src/deep_code_security/cli.py`
- Changes:
  - Add `--ignore-suppressions` flag to `hunt`, `full-scan`, `hunt-fuzz`
  - Pass `ignore_suppressions` to `HunterOrchestrator.scan()`
  - Retrieve `SuppressionResult` from `orchestrator.last_suppression_result`
  - Build `SuppressionSummary` from `SuppressionResult` and pass to formatter DTOs
  - Populate `HuntResult.suppressed_finding_ids` from `SuppressionResult.suppression_reasons.keys()`
  - Catch `ValueError` (including `SuppressionLoadError`) from malformed/oversized suppression files, report to stderr, exit(1)
  - Print suppression summary to stderr (e.g., "3 findings suppressed (5 rules, 1 expired)")

### Phase 5: MCP Integration

**Task 5.1: Update MCP server handlers**
- Modify: `src/deep_code_security/mcp/server.py`
- Changes:
  - Add `ignore_suppressions` to `deep_scan_hunt`, `deep_scan_full`, `deep_scan_hunt_fuzz` tool schemas
  - Pass parameter to `HunterOrchestrator.scan()`
  - Read suppression metadata from `ScanStats` fields for response JSON
  - Include suppression summary in response JSON using `stats.findings_suppressed`, `stats.suppression_rules_loaded`, etc.

### Phase 6: Exports and Cleanup

**Task 6.1: Update `__init__.py` exports**
- Modify: `src/deep_code_security/shared/__init__.py` -- add suppression imports to `__all__`

**Task 6.2: Update `CLAUDE.md`**
- Modify: `CLAUDE.md` -- add `--ignore-suppressions` to CLI commands table

**Task 6.3: Run full test suite**
- Run: `make test` and `make lint`
- Fix any coverage gaps or lint issues
- Verify 90%+ coverage threshold is maintained

### Files Summary

| Action | File |
|--------|------|
| Create | `src/deep_code_security/shared/suppressions.py` |
| Create | `tests/test_shared/test_suppressions.py` |
| Modify | `src/deep_code_security/hunter/models.py` |
| Modify | `src/deep_code_security/hunter/orchestrator.py` |
| Modify | `src/deep_code_security/shared/formatters/protocol.py` |
| Modify | `src/deep_code_security/shared/formatters/text.py` |
| Modify | `src/deep_code_security/shared/formatters/json.py` |
| Modify | `src/deep_code_security/shared/formatters/sarif.py` |
| Modify | `src/deep_code_security/shared/formatters/html.py` |
| Modify | `src/deep_code_security/cli.py` |
| Modify | `src/deep_code_security/mcp/server.py` |
| Modify | `src/deep_code_security/shared/__init__.py` |
| Modify | `CLAUDE.md` |
| Modify | `tests/test_hunter/test_orchestrator.py` |
| Modify | `tests/test_shared/test_formatters/test_text.py` |
| Modify | `tests/test_shared/test_formatters/test_json.py` |
| Modify | `tests/test_shared/test_formatters/test_sarif.py` |
| Modify | `tests/test_shared/test_formatters/test_html.py` |

No files are deleted. No new runtime dependencies are added.

## Context Alignment

### CLAUDE.md Patterns Followed

- **Never `yaml.load()` -- always `yaml.safe_load()`**: The suppression loader uses exclusively `yaml.safe_load()`. This is tested explicitly.
- **Never `eval()`, `exec()`, `os.system()`, `subprocess.run(shell=True)`**: No code execution in the suppression module. Matching uses segment-aware `_glob_match()` and simple comparisons.
- **All file paths validated through `mcp/path_validator.py`**: The suppression file path is derived from the already-validated target path by appending a hardcoded filename. No new user-controlled path component is introduced.
- **Pydantic v2 for all data-crossing models**: `SuppressionRule`, `SuppressionConfig`, `SuppressionResult`, `SuppressionSummary` are all Pydantic BaseModel subclasses.
- **Type hints on all public functions**: All functions in `suppressions.py` are fully typed.
- **`__all__` in `__init__.py`**: `suppressions.py` includes `__all__`. `shared/__init__.py` is updated with new exports.
- **pathlib.Path over os.path**: Suppression file loading and path matching use `pathlib.Path` throughout.
- **No mutable default arguments**: All list/dict fields use `Field(default_factory=...)`.
- **`models.py` per phase**: Suppression models live in their own module (`shared/suppressions.py`) since they are cross-cutting, following the pattern established by `shared/formatters/protocol.py`.
- **90%+ test coverage**: Comprehensive test plan with dedicated test module and updates to existing tests.
- **Registries in YAML files**: The suppression file follows the project's convention of using YAML for declarative configuration.

### Prior Plans Referenced

- **`plans/output-formats.md` (APPROVED, implemented)**: This plan builds on the formatter architecture established by output-formats. The `SuppressionSummary` DTO follows the same pattern as `HuntResult` and `FuzzReportResult`. Each formatter is updated to render suppression data in its format-specific way.
- **`plans/sast-to-fuzz-pipeline.md` (APPROVED, implemented)**: The `hunt-fuzz` command is updated to respect suppressions, ensuring suppressed findings are not passed to the Bridge for fuzz target resolution.
- **`plans/deep-code-security.md` (APPROVED, implemented)**: The original architecture plan does not mention suppressions, but the three-phase pipeline (Hunter -> Auditor -> Architect) is preserved. Suppressions are applied after the Hunter phase, before findings flow to downstream phases.

### Deviations from Established Patterns

- **ScanStats embedding instead of tuple expansion**: The original draft proposed expanding `HunterOrchestrator.scan()` from a 4-tuple to a 5-tuple return. This was revised based on red-team and feasibility review findings (F-1/M-2) that identified the tuple expansion as a fragile breaking change with no compile-time safety net. The revised approach embeds suppression metadata (`findings_suppressed`, `suppression_rules_loaded`, `suppression_rules_expired`, `suppressed_finding_ids`) directly into the already-returned `ScanStats` object, keeping the 4-tuple return signature fully backward compatible. Detailed suppression data (suppressed finding objects, per-finding reasons) is available via the `orchestrator.last_suppression_result` property for callers that need it (SARIF formatter, CLI suppression summary).
- **SARIF suppressed findings require access to the suppressed findings list**: To emit suppressed findings in SARIF with the standard `suppressions[]` array, the SARIF formatter needs the actual suppressed finding objects (not just a count). These are accessed via `orchestrator.last_suppression_result.suppressed_findings` rather than carried through the DTO. This keeps the core DTOs lean while supporting the SARIF spec.

### Review Findings Addressed

This revision addresses the following Critical and Major findings from `plans/suppressions-file.redteam.md`, `plans/suppressions-file.review.md`, and `plans/suppressions-file.feasibility.md`:

| Finding | Resolution |
|---------|------------|
| **F-1 [Critical]** Fragile 5-tuple return breaks all callers | Suppression metadata embedded in `ScanStats`; return type stays 4-tuple. `last_suppression_result` property provides detail. |
| **F-2/M-1 [Major]** `fnmatch` does not support `**` recursive glob | Replaced with segment-aware `_glob_match()` that splits on `/`, handles `**` as zero-or-more segments, uses `fnmatch` per-segment only. Test cases added for `*` not crossing directories and `**` matching zero/one/many. |
| **F-3/M-3 [Major]** `suppressed_findings` missing from DTO schema | Added `suppressed_finding_ids: list[str]` to `HuntResult` and `FullScanResult`. SARIF formatter gets full objects via `orchestrator.last_suppression_result`. Updated "Modified Public API" table. |
| **F-4 [Major]** Silent removal from Auditor/Bridge coverage | Added "Suppression Semantics" section explicitly documenting that suppressions exclude findings from Auditor/Architect/Bridge, and that `--ignore-suppressions` bypasses this for verification runs. |
| **F-5/M-4 [Major]** MCP pseudocode uses list where `len()` needed | MCP response now reads from `ScanStats` fields (`stats.findings_suppressed` is already an `int`), eliminating the type mismatch. |
| **F-6 [Major]** No size limit on suppression file | Added 64 KB file size limit and 500 rule count limit with `SuppressionLoadError`. Documented in "Suppression File Size Limits" section. |

<!-- Context Metadata
discovered_at: 2026-03-17T12:00:00Z
claude_md_exists: true
recent_plans_consulted: sast-to-fuzz-pipeline.md, fuzzer-container-backend.md, output-formats.md
archived_plans_consulted: merge-fuzzy-wuzzy.md, deep-code-security.md
-->

## Status: APPROVED
