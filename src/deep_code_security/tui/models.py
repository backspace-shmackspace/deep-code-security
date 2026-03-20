"""Pydantic models for the TUI frontend.

These models are pure data structures with no dependency on ``textual``.
They are safe to import and use from non-TUI code (tests, storage, runner).
"""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, Field, field_validator

__all__ = [
    "RunMeta",
    "ScanConfig",
]

ScanType = Literal["hunt", "full-scan", "hunt-fuzz", "fuzz"]
SeverityThreshold = Literal["critical", "high", "medium", "low"]


class RunMeta(BaseModel):
    """Metadata for a single scan run, stored as meta.json."""

    run_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique run identifier (UUID)",
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 UTC timestamp (e.g., '2026-03-20T14:30:00Z')",
    )
    target_path: str = Field(
        ...,
        description="Absolute path to the scanned target",
    )
    project_name: str = Field(
        ...,
        description="Derived project name (basename of target path)",
    )
    scan_type: ScanType = Field(
        ...,
        description="Scan type: 'hunt', 'full-scan', 'fuzz', 'hunt-fuzz'",
    )
    duration_seconds: float = Field(
        ...,
        ge=0.0,
        description="Wall-clock duration of the scan in seconds",
    )
    findings_count: int = Field(
        default=0,
        ge=0,
        description="Number of findings reported (0 if scan failed)",
    )
    backend_used: str = Field(
        default="unknown",
        description="Scanner backend: 'semgrep', 'treesitter', 'auto', or 'unknown'",
    )
    exit_code: int = Field(
        ...,
        description="Exit code of the dcs subprocess (0 = success)",
    )
    languages: list[str] = Field(
        default_factory=list,
        description="Languages scanned (empty = all detected)",
    )
    severity_threshold: str = Field(
        default="medium",
        description="Minimum severity threshold used",
    )
    report_files: list[str] = Field(
        default_factory=list,
        description="List of generated report filenames (relative to run dir)",
    )
    error_message: str = Field(
        default="",
        description="Error message if exit_code != 0",
    )
    dcs_version: str = Field(
        default="",
        description="deep-code-security version used for this scan",
    )

    @field_validator("scan_type", mode="before")
    @classmethod
    def normalize_scan_type(cls, v: str) -> str:
        """Normalize scan_type to lowercase for consistent comparison."""
        return v.lower() if isinstance(v, str) else v

    @field_validator("severity_threshold", mode="before")
    @classmethod
    def normalize_severity_threshold(cls, v: str) -> str:
        """Normalize severity_threshold to lowercase."""
        return v.lower() if isinstance(v, str) else v


class ScanConfig(BaseModel):
    """Scan configuration produced by the TUI scan config screen.

    All scan options are explicitly typed fields.  There is no ``extra_args``
    field -- users who need custom CLI flags use ``dcs`` directly.  This
    eliminates the risk of conflicting flags (``--output-file``, ``--format``)
    that would break TUI operation.
    """

    target_path: str = Field(
        ...,
        description="Absolute path to the scan target (file or directory)",
    )
    scan_type: ScanType = Field(
        ...,
        description="Scan type: 'hunt', 'full-scan', 'hunt-fuzz', 'fuzz'",
    )
    languages: list[str] = Field(
        default_factory=list,
        description="Language filter (empty = all detected). Values: 'python', 'go', 'c'.",
    )
    severity_threshold: SeverityThreshold = Field(
        default="medium",
        description="Minimum severity threshold",
    )
    skip_verify: bool = Field(
        default=False,
        description="Skip the Auditor verification phase (only for 'full-scan')",
    )
    ignore_suppressions: bool = Field(
        default=False,
        description="Ignore .dcs-suppress.yaml suppression rules",
    )

    @field_validator("scan_type", mode="before")
    @classmethod
    def normalize_scan_type(cls, v: str) -> str:
        """Normalize scan_type to lowercase."""
        return v.lower() if isinstance(v, str) else v

    @field_validator("severity_threshold", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        """Normalize severity_threshold to lowercase."""
        return v.lower() if isinstance(v, str) else v
