"""Exploit verification — orchestrates generation, sandbox execution, and scoring."""

from __future__ import annotations

import logging

from deep_code_security.auditor.confidence import compute_confidence
from deep_code_security.auditor.exploit_generator import ExploitGenerator
from deep_code_security.auditor.models import ExploitResult, VerifiedFinding
from deep_code_security.auditor.sandbox import SandboxManager, SandboxUnavailableError
from deep_code_security.hunter.models import RawFinding

__all__ = ["Verifier"]

logger = logging.getLogger(__name__)


class Verifier:
    """Orchestrates exploit verification for a single finding.

    Flow: validate finding -> generate PoC -> run in sandbox -> score -> wrap result.
    """

    def __init__(
        self,
        sandbox: SandboxManager,
        generator: ExploitGenerator | None = None,
    ) -> None:
        self.sandbox = sandbox
        self.generator = generator or ExploitGenerator()

    def verify_finding(
        self,
        finding: RawFinding,
        target_path: str,
        timeout: int | None = None,
    ) -> VerifiedFinding:
        """Verify a single finding by generating and running a PoC exploit.

        Args:
            finding: Raw finding to verify.
            target_path: Path to the target codebase.
            timeout: Optional override for sandbox timeout.

        Returns:
            VerifiedFinding with confidence score and verification status.
        """
        exploit_results: list[ExploitResult] = []

        # Generate exploit script
        try:
            script, script_hash = self.generator.generate_exploit(finding)
        except Exception as e:
            logger.warning(
                "Failed to generate exploit for finding %s: %s", finding.id, e
            )
            # Score without exploit results
            confidence, status = compute_confidence(finding, [])
            return VerifiedFinding(
                finding=finding,
                exploit_results=[],
                confidence_score=confidence,
                verification_status=status,
            )

        # Run in sandbox
        if self.sandbox.is_available():
            try:
                result = self.sandbox.run_exploit(
                    language=finding.language,
                    target_path=target_path,
                    poc_script=script,
                    timeout=timeout,
                )
                exploit_results.append(result)
                logger.debug(
                    "Exploit result for finding %s: exit=%d, exploitable=%s",
                    finding.id, result.exit_code, result.exploitable,
                )
            except SandboxUnavailableError as e:
                logger.info(
                    "Sandbox unavailable for finding %s: %s", finding.id, e
                )
            except Exception as e:
                logger.warning(
                    "Sandbox execution failed for finding %s: %s", finding.id, e
                )
        else:
            logger.debug(
                "Sandbox not available, skipping exploit execution for finding %s",
                finding.id,
            )

        # Compute confidence (exploit verification is bonus-only)
        confidence, status = compute_confidence(finding, exploit_results)

        return VerifiedFinding(
            finding=finding,
            exploit_results=exploit_results,
            confidence_score=confidence,
            verification_status=status,
        )
