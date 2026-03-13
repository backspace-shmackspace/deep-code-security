"""Pydantic models for the Architect (Remediation) phase.

NOTE: No Patch model — guidance only, not apply-ready diffs.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

__all__ = [
    "DependencyImpact",
    "RemediationGuidance",
    "RemediateStats",
]


class DependencyImpact(BaseModel):
    """Impact of a fix on project dependencies."""

    manifest_file: str = Field(
        ..., description="Path to manifest file (e.g., requirements.txt, go.mod)"
    )
    current_deps: list[str] = Field(
        default_factory=list, description="Relevant current dependencies"
    )
    required_changes: list[str] = Field(
        default_factory=list,
        description="Suggested changes (new deps or version bumps)",
    )
    breaking_risk: str = Field(
        default="none",
        description="Risk level: 'none', 'minor', or 'major'",
    )


class RemediationGuidance(BaseModel):
    """Remediation guidance for a vulnerability.

    NOTE: This provides guidance with illustrative code examples,
    NOT apply-ready diffs or patches. See README for rationale.
    """

    finding_id: str = Field(..., description="UUID of the original RawFinding")
    vulnerability_explanation: str = Field(
        ...,
        description="Explanation of what the vulnerability is and why it is dangerous",
    )
    fix_pattern: str = Field(
        ...,
        description="General fix approach (e.g., 'Use parameterized queries')",
    )
    code_example: str = Field(
        ...,
        description="Illustrative code snippet showing the fix concept (not a patch)",
    )
    dependency_impact: DependencyImpact | None = Field(
        default=None,
        description="Dependency changes required by the fix, if any",
    )
    effort_estimate: str = Field(
        ...,
        description="Implementation effort: 'trivial', 'small', 'medium', or 'large'",
    )
    test_suggestions: list[str] = Field(
        default_factory=list,
        description="Suggested test cases to verify the fix",
    )
    references: list[str] = Field(
        default_factory=list,
        description="CWE and OWASP references",
    )


class RemediateStats(BaseModel):
    """Statistics from an Architect remediation run."""

    total_verified: int = Field(default=0, ge=0)
    guidance_generated: int = Field(default=0, ge=0)
    dependencies_affected: int = Field(default=0, ge=0)
    remediation_duration_ms: int = Field(default=0, ge=0)
