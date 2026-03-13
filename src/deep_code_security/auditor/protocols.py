"""Protocol definitions for pluggable exploit generation and sandbox execution.

The public deep-code-security package defines these protocols. Concrete
implementations live in a separate private package (e.g., dcs-exploits)
and are discovered at import time. If no implementation is installed,
NoOp stubs from auditor.noop are used automatically.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from deep_code_security.auditor.models import ExploitResult
from deep_code_security.hunter.models import RawFinding

__all__ = [
    "ExploitGeneratorProtocol",
    "SandboxProvider",
]


@runtime_checkable
class ExploitGeneratorProtocol(Protocol):
    """Protocol for PoC exploit script generators.

    Implementations must validate all RawFinding fields (via input_validator)
    before interpolating them into any template or string.
    """

    def generate_exploit(self, finding: RawFinding) -> tuple[str, str]:
        """Generate a PoC exploit script for the given finding.

        Args:
            finding: A validated RawFinding.

        Returns:
            Tuple of (script_content, sha256_hash).

        Raises:
            GenerationError: If generation fails.
        """
        ...


@runtime_checkable
class SandboxProvider(Protocol):
    """Protocol for sandbox container managers.

    Implementations must enforce the full security policy:
    --network=none, --read-only, --cap-drop=ALL, --security-opt=no-new-privileges,
    seccomp profile, --pids-limit, --memory, --user=65534:65534, noexec tmpfs.
    """

    def is_available(self) -> bool:
        """Check if the sandbox runtime is available."""
        ...

    def run_exploit(
        self,
        language: str,
        target_path: str,
        poc_script: str,
        timeout: int | None = None,
    ) -> ExploitResult:
        """Run an exploit PoC in a sandboxed container.

        Args:
            language: Programming language ("python", "go", "c").
            target_path: Absolute path to target codebase (mounted read-only).
            poc_script: PoC script content to execute.
            timeout: Override timeout in seconds.

        Returns:
            ExploitResult with execution outcome.
        """
        ...

    def build_images(self) -> bool:
        """Build sandbox container images.

        Returns:
            True if all images built successfully.
        """
        ...
