"""Suppression file support for deep-code-security.

Loads and applies `.dcs-suppress.yaml` suppression files from the scanned
project root. Suppressions allow projects to mark known false positives or
accepted risks so they are excluded from reported findings.

Security notes:
- Uses yaml.safe_load() exclusively (never yaml.load()).
- No eval/exec/shell is used. Matching is pure string/fnmatch operations.
- File size (64 KB) and rule count (500) limits prevent DoS from malicious files.
- The suppression file path is always derived from the already-validated target
  path by appending a hardcoded filename -- no user-controlled path component.
"""

from __future__ import annotations

import datetime
import fnmatch
import logging
import re
from pathlib import Path, PurePosixPath
from typing import Any

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
    """Raised when a suppression file exceeds size or rule count limits."""

    pass


def _glob_match(path_segments: list[str], pattern_segments: list[str]) -> bool:
    """Segment-aware glob match supporting ** for recursive directory matching.

    Single * matches within one path segment only (does not cross / boundaries).
    ** matches zero or more complete path segments.
    ? matches any single character within a segment.

    Args:
        path_segments: Path split on '/' (e.g. ['src', 'config', 'loader.py']).
        pattern_segments: Pattern split on '/' (e.g. ['src', 'config', '*.py']).

    Returns:
        True if path_segments matches pattern_segments.
    """
    pi = 0  # pattern index
    si = 0  # path segment index

    # Stack for ** backtracking: stores (pattern_index_after_doublestar, next_si)
    stack: list[tuple[int, int]] = []

    while si < len(path_segments) or pi < len(pattern_segments):
        if pi < len(pattern_segments) and pattern_segments[pi] == "**":
            # ** matches zero or more segments; push backtrack point
            # pi+1 is the pattern index after the **, si+1 allows consuming
            # one more path segment on backtrack.
            stack.append((pi + 1, si))
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

        # No match at current position; try backtracking to a ** position
        if stack:
            bt_pi, bt_si = stack.pop()
            if bt_si < len(path_segments):
                # Consume one more path segment for the ** match and retry
                stack.append((bt_pi, bt_si + 1))
                pi = bt_pi
                si = bt_si + 1
                continue

        return False

    return pi >= len(pattern_segments) and si >= len(path_segments)


class SuppressionRule(BaseModel):
    """A single suppression rule from the suppressions file."""

    rule: str | None = Field(
        default=None,
        description="CWE identifier to match (e.g., 'CWE-78'). If omitted, matches all rules.",
    )
    file: str | None = Field(
        default=None,
        description="Glob pattern for file paths, relative to project root.",
    )
    lines: list[int] | None = Field(
        default=None,
        description="Inclusive line range [start, end]. Matches if sink.line is in this range.",
    )
    reason: str = Field(
        ...,
        min_length=1,
        description="Human-readable explanation for this suppression (required for auditability).",
    )
    expires: str | None = Field(
        default=None,
        description=(
            "Expiration date in YYYY-MM-DD format. Suppression is inactive after this date."
        ),
    )

    model_config = {"frozen": True}

    @field_validator("rule")
    @classmethod
    def validate_rule(cls, v: str | None) -> str | None:
        """Validate CWE rule format."""
        if v is not None and not _CWE_PATTERN.match(v):
            raise ValueError(
                f"Invalid rule format: {v!r}. Must match 'CWE-<number>' (e.g., 'CWE-78')"
            )
        return v

    @field_validator("lines")
    @classmethod
    def validate_lines(cls, v: list[int] | None) -> list[int] | None:
        """Validate line range is a two-element list with valid values."""
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
        """Validate expiration date is YYYY-MM-DD format."""
        if v is not None:
            try:
                datetime.date.fromisoformat(v)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid expires date: {v!r}. Must be YYYY-MM-DD format."
                ) from exc
        return v

    @model_validator(mode="after")
    def validate_at_least_one_matcher(self) -> SuppressionRule:
        """Require at least one of rule or file to be specified."""
        if self.rule is None and self.file is None:
            raise ValueError(
                "At least one of 'rule' or 'file' must be specified "
                "in a suppression entry"
            )
        return self

    def is_expired(self, today: datetime.date | None = None) -> bool:
        """Check if this suppression has expired.

        Args:
            today: Override for the current date (for testing). Defaults to
                   today's date in UTC.

        Returns:
            True if the suppression has an expiration date and it has passed.
        """
        if self.expires is None:
            return False
        check_date = today or datetime.datetime.now(datetime.UTC).date()
        return check_date > datetime.date.fromisoformat(self.expires)

    def matches(
        self,
        finding: RawFinding,
        project_root: Path,
        today: datetime.date | None = None,
    ) -> bool:
        """Check if this suppression matches a finding.

        A rule matches if ALL applicable conditions are satisfied:
        1. Not expired.
        2. rule matches finding.sink.cwe (if rule is set).
        3. file glob matches finding.sink.file relative to project_root (if file is set).
        4. finding.sink.line is within [lines[0], lines[1]] (if lines is set).

        Args:
            finding: The RawFinding to test.
            project_root: Absolute path to the project root (for relative path computation).
            today: Override for the current date (for testing).

        Returns:
            True if this suppression matches the finding.
        """
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
                # Use PurePosixPath for consistent forward-slash segment splitting
                rel_str = str(PurePosixPath(rel_path))
                path_segments = rel_str.split("/")
                pattern_segments = self.file.split("/")
                if not _glob_match(path_segments, pattern_segments):
                    return False
            except ValueError:
                # sink.file is not under project_root
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
        """Only version 1 is supported."""
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

    The suppressions file is always at `<project_root>/.dcs-suppress.yaml`.
    The file path is not user-controlled -- it is derived from the already-
    validated target path by appending a hardcoded filename.

    Args:
        project_root: Absolute path to the scanned project root.

    Returns:
        SuppressionConfig if the file exists and is valid. None if the file
        does not exist.

    Raises:
        SuppressionLoadError: If the file exceeds the 64 KB size limit or
            500 rule count limit.
        ValueError: If the file exists but contains invalid YAML or an
            invalid schema.
    """
    suppress_path = project_root / _SUPPRESS_FILENAME
    if not suppress_path.is_file():
        return None

    # Check file size before reading (DoS prevention)
    try:
        file_size = suppress_path.stat().st_size
    except OSError as e:
        logger.warning("Cannot stat suppressions file %s: %s", suppress_path, e)
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
        logger.warning("Cannot read suppressions file %s: %s", suppress_path, e)
        return None

    # SECURITY: Always use yaml.safe_load() -- never yaml.load()
    try:
        raw: Any = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ValueError(
            f"Invalid YAML in suppressions file {suppress_path}: {e}"
        ) from e

    if raw is None:
        # Empty file -- treat as empty suppression config
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

    Each finding is tested against all suppression rules. A finding is
    suppressed if ANY rule matches it (logical OR). The first matching rule's
    reason is recorded.

    Suppressions with an expiration date that has passed are counted but not
    applied; a warning is logged for each expired suppression.

    Args:
        findings: List of RawFinding objects from the Hunter phase.
        config: Parsed suppressions configuration.
        project_root: Absolute path to the scanned project root
                      (for relative path computation in file glob matching).
        today: Override for the current date (for testing expiration logic).

    Returns:
        SuppressionResult with active and suppressed findings separated.
    """
    active: list[RawFinding] = []
    suppressed: list[RawFinding] = []
    reasons: dict[str, str] = {}

    # Count expired rules upfront and log a warning
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
