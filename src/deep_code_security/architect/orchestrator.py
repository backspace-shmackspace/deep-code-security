"""Architect phase orchestration — coordinates guidance and dependency analysis."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from deep_code_security.architect.dependency_analyzer import DependencyAnalyzer
from deep_code_security.architect.guidance_generator import GuidanceGenerator
from deep_code_security.architect.models import RemediateStats, RemediationGuidance
from deep_code_security.auditor.models import VerifiedFinding
from deep_code_security.shared.config import Config, get_config

__all__ = ["ArchitectOrchestrator"]

logger = logging.getLogger(__name__)


class ArchitectOrchestrator:
    """Orchestrates the Architect (Remediation) phase."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or get_config()
        self.guidance_generator = GuidanceGenerator()
        self.dependency_analyzer = DependencyAnalyzer()

    def remediate(
        self,
        verified_findings: list[VerifiedFinding],
        target_path: str | Path,
    ) -> tuple[list[RemediationGuidance], RemediateStats]:
        """Generate remediation guidance for verified findings.

        Args:
            verified_findings: Verified findings from the Auditor.
            target_path: Path to the target codebase.

        Returns:
            Tuple of (guidance_list, stats).
        """
        start_ms = time.monotonic() * 1000
        target_path = Path(target_path)

        stats = RemediateStats(total_verified=len(verified_findings))
        guidance_list: list[RemediationGuidance] = []
        deps_affected = set()

        for vf in verified_findings:
            try:
                # Generate guidance
                guidance = self.guidance_generator.generate(vf)

                # Analyze dependency impact
                dep_impact = self.dependency_analyzer.analyze(target_path, vf)
                if dep_impact is not None:
                    deps_affected.add(dep_impact.manifest_file)
                    # Rebuild guidance with dependency impact
                    guidance = RemediationGuidance(
                        finding_id=guidance.finding_id,
                        vulnerability_explanation=guidance.vulnerability_explanation,
                        fix_pattern=guidance.fix_pattern,
                        code_example=guidance.code_example,
                        dependency_impact=dep_impact,
                        effort_estimate=guidance.effort_estimate,
                        test_suggestions=guidance.test_suggestions,
                        references=guidance.references,
                    )

                guidance_list.append(guidance)
                stats.guidance_generated += 1

            except Exception as e:
                logger.error(
                    "Failed to generate guidance for finding %s: %s",
                    vf.finding.id, e,
                )

        stats.dependencies_affected = len(deps_affected)
        stats.remediation_duration_ms = int(time.monotonic() * 1000 - start_ms)

        logger.info(
            "Architect complete: %d guidance items, %d deps affected, %dms",
            stats.guidance_generated, stats.dependencies_affected,
            stats.remediation_duration_ms,
        )

        return guidance_list, stats
