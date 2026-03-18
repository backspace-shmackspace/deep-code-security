"""Pydantic models for the Hunter (Discovery) phase."""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, Field, field_validator

__all__ = [
    "Source",
    "Sink",
    "TaintStep",
    "TaintPath",
    "RawFinding",
    "ScanStats",
    "Severity",
]

Severity = Literal["critical", "high", "medium", "low"]


class Source(BaseModel):
    """A user input entry point (taint source)."""

    file: str = Field(..., description="Absolute path to the source file")
    line: int = Field(..., ge=1, description="Line number (1-based)")
    column: int = Field(..., ge=0, description="Column offset (0-based)")
    function: str = Field(..., description="Source function/attribute (e.g., 'request.form')")
    category: str = Field(
        ..., description="Source category (e.g., 'web_input', 'cli_input', 'file_read')"
    )
    language: str = Field(..., description="Programming language")

    model_config = {"frozen": True}


class Sink(BaseModel):
    """A dangerous function call (taint sink)."""

    file: str = Field(..., description="Absolute path to the sink file")
    line: int = Field(..., ge=1, description="Line number (1-based)")
    column: int = Field(..., ge=0, description="Column offset (0-based)")
    function: str = Field(
        ..., description="Sink function (e.g., 'os.system', 'cursor.execute')"
    )
    category: str = Field(
        ..., description="Sink category (e.g., 'command_injection', 'sql_injection')"
    )
    cwe: str = Field(..., description="CWE identifier (e.g., 'CWE-78')")
    language: str = Field(..., description="Programming language")

    model_config = {"frozen": True}


class TaintStep(BaseModel):
    """A single step in a taint propagation path."""

    file: str = Field(..., description="Source file for this step")
    line: int = Field(..., ge=1, description="Line number (1-based)")
    column: int = Field(..., ge=0, description="Column offset (0-based)")
    variable: str = Field(..., description="Variable name carrying the taint")
    transform: str = Field(
        default="assignment",
        description="How the taint propagated (e.g., 'assignment', 'concatenation', 'f-string')",
    )

    model_config = {"frozen": True}


class TaintPath(BaseModel):
    """A complete dataflow path from source to sink."""

    steps: list[TaintStep] = Field(default_factory=list, description="Taint propagation steps")
    sanitized: bool = Field(
        default=False, description="True if the path passes through a known sanitizer"
    )
    sanitizer: str | None = Field(
        default=None, description="Sanitizer function if sanitized is True"
    )

    model_config = {"frozen": True}


class RawFinding(BaseModel):
    """A potential vulnerability discovered by the Hunter phase."""

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique finding identifier (UUID)",
    )
    source: Source = Field(..., description="Taint source")
    sink: Sink = Field(..., description="Taint sink")
    taint_path: TaintPath = Field(..., description="Dataflow path from source to sink")
    vulnerability_class: str = Field(
        ..., description="CWE category (e.g., 'CWE-78: OS Command Injection')"
    )
    severity: Severity = Field(..., description="Finding severity")
    language: str = Field(..., description="Programming language")
    raw_confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Pre-verification heuristic confidence (0.0-1.0)",
    )

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        """Normalize severity to lowercase."""
        return v.lower() if isinstance(v, str) else v


class ScanStats(BaseModel):
    """Statistics from a Hunter scan."""

    files_scanned: int = Field(default=0, ge=0)
    files_skipped: int = Field(default=0, ge=0)
    languages_detected: list[str] = Field(default_factory=list)
    sources_found: int = Field(default=0, ge=0)
    sinks_found: int = Field(default=0, ge=0)
    taint_paths_found: int = Field(default=0, ge=0)
    scan_duration_ms: int = Field(default=0, ge=0)
    registry_version_hash: str = Field(
        default="", description="Hash of registry files used for reproducibility"
    )
    findings_suppressed: int = Field(
        default=0, ge=0, description="Number of findings suppressed by .dcs-suppress.yaml"
    )
    suppression_rules_loaded: int = Field(
        default=0, ge=0, description="Number of suppression rules loaded from .dcs-suppress.yaml"
    )
    suppression_rules_expired: int = Field(
        default=0, ge=0, description="Number of expired suppression rules (skipped)"
    )
    suppressed_finding_ids: list[str] = Field(
        default_factory=list,
        description="IDs of findings suppressed by .dcs-suppress.yaml",
    )
