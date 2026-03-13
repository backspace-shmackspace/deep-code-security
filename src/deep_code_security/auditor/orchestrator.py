"""Auditor phase orchestration."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from deep_code_security.auditor.models import VerifiedFinding, VerifyStats
from deep_code_security.auditor.noop import NoOpExploitGenerator, NoOpSandbox
from deep_code_security.auditor.protocols import ExploitGeneratorProtocol, SandboxProvider
from deep_code_security.auditor.verifier import Verifier
from deep_code_security.hunter.models import RawFinding
from deep_code_security.shared.config import Config, get_config

if TYPE_CHECKING:
    pass

__all__ = ["AuditorOrchestrator"]

logger = logging.getLogger(__name__)

# Severity order for prioritization
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


class AuditorOrchestrator:
    """Orchestrates the Auditor (Verification) phase."""

    def __init__(
        self,
        config: Config | None = None,
        sandbox: SandboxProvider | None = None,
        generator: ExploitGeneratorProtocol | None = None,
    ) -> None:
        self.config = config or get_config()
        sandbox, generator = _load_plugins(sandbox, generator, self.config)
        self.sandbox = sandbox
        self.verifier = Verifier(sandbox=self.sandbox, generator=generator)
        # Session store: verified_finding_id -> VerifiedFinding
        self._session_verified: dict[str, VerifiedFinding] = {}

    def verify(
        self,
        findings: list[RawFinding],
        target_path: str,
        sandbox_timeout: int | None = None,
        max_verifications: int | None = None,
    ) -> tuple[list[VerifiedFinding], VerifyStats]:
        """Verify a list of raw findings.

        Args:
            findings: Raw findings to verify.
            target_path: Path to the target codebase.
            sandbox_timeout: Per-exploit timeout override.
            max_verifications: Maximum number of findings to verify.

        Returns:
            Tuple of (verified_findings, stats).
        """
        start_ms = time.monotonic() * 1000
        max_ver = max_verifications or self.config.max_verifications
        timeout = sandbox_timeout or self.config.sandbox_timeout
        sandbox_available = self.sandbox.is_available()

        stats = VerifyStats(
            total_findings=len(findings),
            sandbox_available=sandbox_available,
        )

        # Sort by severity (critical first) for prioritization
        sorted_findings = sorted(
            findings,
            key=lambda f: -_SEVERITY_ORDER.get(f.severity, 0),
        )

        # Split into verify set and skipped set
        to_verify = sorted_findings[:max_ver]
        skipped = sorted_findings[max_ver:]

        stats.skipped_count = len(skipped)

        verified: list[VerifiedFinding] = []

        for finding in to_verify:
            try:
                vf = self.verifier.verify_finding(
                    finding=finding,
                    target_path=target_path,
                    timeout=timeout,
                )
                verified.append(vf)
                stats.verified_count += 1

                # Count by status
                if vf.verification_status == "confirmed":
                    stats.confirmed += 1
                elif vf.verification_status == "likely":
                    stats.likely += 1
                elif vf.verification_status == "unconfirmed":
                    stats.unconfirmed += 1
                else:
                    stats.false_positives += 1

                # Store in session
                self._session_verified[vf.finding.id] = vf

            except Exception as e:
                logger.error(
                    "Verification failed for finding %s: %s", finding.id, e
                )
                stats.skipped_count += 1

        # Handle skipped findings with base confidence only
        for finding in skipped:
            from deep_code_security.auditor.confidence import compute_confidence
            confidence, status = compute_confidence(finding, [])
            vf = VerifiedFinding(
                finding=finding,
                exploit_results=[],
                confidence_score=confidence,
                verification_status=status,
            )
            verified.append(vf)
            self._session_verified[vf.finding.id] = vf

            if vf.verification_status == "confirmed":
                stats.confirmed += 1
            elif vf.verification_status == "likely":
                stats.likely += 1
            elif vf.verification_status == "unconfirmed":
                stats.unconfirmed += 1
            else:
                stats.false_positives += 1

        stats.verification_duration_ms = int(time.monotonic() * 1000 - start_ms)

        logger.info(
            "Auditor complete: %d verified, %d skipped, %dms",
            stats.verified_count, stats.skipped_count, stats.verification_duration_ms,
        )

        return verified, stats

    def get_verified_for_ids(self, finding_ids: list[str]) -> list[VerifiedFinding]:
        """Retrieve verified findings from session store by finding ID.

        Args:
            finding_ids: Finding UUIDs from a previous verify run.

        Returns:
            List of matching VerifiedFinding instances.
        """
        return [
            vf for fid, vf in self._session_verified.items()
            if fid in finding_ids
        ]


def _load_plugins(
    sandbox: SandboxProvider | None,
    generator: ExploitGeneratorProtocol | None,
    config: Config,
) -> tuple[SandboxProvider, ExploitGeneratorProtocol]:
    """Load exploit generator and sandbox from dcs-exploits if installed.

    Falls back to NoOp implementations if the private package is not available.
    Explicit arguments take precedence over plugin discovery.

    Args:
        sandbox: Explicit sandbox override (used if not None).
        generator: Explicit generator override (used if not None).
        config: Server configuration for sandbox settings.

    Returns:
        Tuple of (sandbox, generator).
    """
    if sandbox is not None and generator is not None:
        return sandbox, generator

    # Try to import the private dcs-exploits package
    try:
        import dcs_exploits  # type: ignore[import-not-found]
        if sandbox is None:
            sandbox = dcs_exploits.create_sandbox(config)
            logger.info("Loaded sandbox provider from dcs-exploits")
        if generator is None:
            generator = dcs_exploits.create_exploit_generator()
            logger.info("Loaded exploit generator from dcs-exploits")
    except ImportError:
        logger.info(
            "dcs-exploits not installed — using NoOp auditor "
            "(Hunter and Architect phases are fully functional)"
        )
        if sandbox is None:
            sandbox = NoOpSandbox()
        if generator is None:
            generator = NoOpExploitGenerator()

    return sandbox, generator
