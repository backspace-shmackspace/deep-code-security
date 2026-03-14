"""Formatter protocol and data transfer objects."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, Field

from deep_code_security.architect.models import RemediateStats, RemediationGuidance
from deep_code_security.auditor.models import VerifiedFinding, VerifyStats
from deep_code_security.hunter.models import RawFinding, ScanStats

__all__ = [
    "Formatter",
    "FullScanResult",
    "HuntResult",
]


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

    def format_hunt(self, data: HuntResult, target_path: str = "") -> str:
        """Format hunt phase results."""
        ...

    def format_full_scan(self, data: FullScanResult, target_path: str = "") -> str:
        """Format full-scan (all three phases) results."""
        ...
