"""NoOp implementations of exploit generation and sandbox execution.

Used when no concrete implementation package (e.g., dcs-exploits) is installed.
The Hunter and Architect phases remain fully functional; the Auditor phase
returns base confidence scores without exploit verification.
"""

from __future__ import annotations

import hashlib
import logging

from deep_code_security.auditor.models import ExploitResult
from deep_code_security.hunter.models import RawFinding

__all__ = [
    "NoOpExploitGenerator",
    "NoOpSandbox",
]

logger = logging.getLogger(__name__)

_NOOP_SCRIPT = """\
# NoOp PoC placeholder — no exploit generator installed.
# Install a concrete implementation (e.g., dcs-exploits) for real PoC generation.
print("NO_EXPLOIT_GENERATOR")
"""


class NoOpExploitGenerator:
    """Stub exploit generator that produces inert placeholder scripts.

    Used when no concrete exploit generation package is installed.
    The Auditor will compute base confidence without exploit verification.
    """

    def generate_exploit(self, finding: RawFinding) -> tuple[str, str]:
        """Return a placeholder script that does nothing exploitative.

        Args:
            finding: A validated RawFinding (unused).

        Returns:
            Tuple of (placeholder_script, sha256_hash).
        """
        script_hash = hashlib.sha256(_NOOP_SCRIPT.encode("utf-8")).hexdigest()
        logger.debug(
            "NoOp exploit generator: returning placeholder for finding %s",
            finding.id,
        )
        return _NOOP_SCRIPT, script_hash


class NoOpSandbox:
    """Stub sandbox that reports as unavailable.

    Used when no concrete sandbox implementation is installed.
    The Verifier will skip exploit execution and use base confidence only.
    """

    def is_available(self) -> bool:
        """Always returns False — no sandbox is available."""
        return False

    def run_exploit(
        self,
        language: str,
        target_path: str,
        poc_script: str,
        timeout: int | None = None,
    ) -> ExploitResult:
        """Never called (is_available returns False), but satisfies the protocol."""
        raise RuntimeError(
            "NoOpSandbox.run_exploit called — this should not happen. "
            "Install a concrete sandbox implementation (e.g., dcs-exploits)."
        )

    def build_images(self) -> bool:
        """No images to build."""
        logger.info("NoOp sandbox: no images to build. Install dcs-exploits for sandbox support.")
        return False
