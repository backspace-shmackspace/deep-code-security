"""Pydantic models for the Auditor (Verification) phase."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from deep_code_security.hunter.models import RawFinding

__all__ = [
    "ExploitResult",
    "VerifiedFinding",
    "VerifyStats",
    "VerificationStatus",
]

VerificationStatus = Literal["confirmed", "likely", "unconfirmed", "false_positive"]


class ExploitResult(BaseModel):
    """Result of a sandbox exploit attempt."""

    exploit_script_hash: str = Field(
        ...,
        description="SHA-256 hash of the PoC script (not full script — avoid storing exploit code)",
    )
    exit_code: int = Field(..., description="Container exit code")
    stdout_truncated: str = Field(
        ..., description="First 2KB of stdout from sandbox execution"
    )
    stderr_truncated: str = Field(
        ..., description="First 2KB of stderr from sandbox execution"
    )
    exploitable: bool = Field(
        ..., description="True if the exploit succeeded in the sandbox"
    )
    execution_time_ms: int = Field(..., ge=0, description="Execution time in milliseconds")
    timed_out: bool = Field(default=False, description="True if execution timed out")

    model_config = {"frozen": True}


class VerifiedFinding(BaseModel):
    """A finding that has been through the Auditor phase."""

    finding: RawFinding = Field(..., description="The original raw finding")
    exploit_results: list[ExploitResult] = Field(
        default_factory=list, description="Results of sandbox exploit attempts"
    )
    confidence_score: int = Field(
        ..., ge=0, le=100, description="Final confidence score (0-100)"
    )
    verification_status: VerificationStatus = Field(
        ..., description="Verification verdict"
    )

    model_config = {"frozen": True}


class VerifyStats(BaseModel):
    """Statistics from an Auditor verification run."""

    total_findings: int = Field(default=0, ge=0)
    verified_count: int = Field(default=0, ge=0, description="Findings that went through verification")
    skipped_count: int = Field(default=0, ge=0, description="Findings skipped (over limit, etc.)")
    confirmed: int = Field(default=0, ge=0)
    likely: int = Field(default=0, ge=0)
    unconfirmed: int = Field(default=0, ge=0)
    false_positives: int = Field(default=0, ge=0)
    sandbox_available: bool = Field(default=False)
    verification_duration_ms: int = Field(default=0, ge=0)
