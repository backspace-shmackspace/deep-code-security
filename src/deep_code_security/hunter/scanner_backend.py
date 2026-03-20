"""ScannerBackend protocol, BackendResult model, and backend factory.

This module defines the shared contract for scanner backends (Semgrep and
TreeSitter) and the ``select_backend()`` factory that reads
``DCS_SCANNER_BACKEND`` from the environment and returns the appropriate
backend instance.

Lazy imports inside ``select_backend()`` prevent circular-import issues:
``SemgrepBackend`` and ``TreeSitterBackend`` both import from this module, so
importing them at module level would create a cycle.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from deep_code_security.hunter.models import RawFinding
    from deep_code_security.shared.file_discovery import DiscoveredFile

__all__ = [
    "BackendResult",
    "ScannerBackend",
    "select_backend",
]

logger = logging.getLogger(__name__)

# Valid values for DCS_SCANNER_BACKEND
_VALID_BACKEND_VALUES = frozenset({"auto", "semgrep", "treesitter"})


class BackendResult(BaseModel):
    """Result returned by a scanner backend's ``scan_files()`` call.

    Attributes:
        findings: Raw findings produced by the backend.
        sources_found: Number of taint sources detected.
        sinks_found: Number of taint sinks detected.
        taint_paths_found: Number of source-to-sink taint paths found.
        backend_name: Identifier for the backend that produced this result
            (``"semgrep"`` or ``"treesitter"``).
        diagnostics: Human-readable diagnostic messages (warnings, errors,
            informational notes) produced during the scan.
    """

    findings: list[RawFinding] = Field(default_factory=list)
    sources_found: int = Field(default=0, ge=0)
    sinks_found: int = Field(default=0, ge=0)
    taint_paths_found: int = Field(default=0, ge=0)
    backend_name: str = Field(...)
    diagnostics: list[str] = Field(default_factory=list)

    model_config = {"frozen": True}


@runtime_checkable
class ScannerBackend(Protocol):
    """Protocol defining the contract for scanner backends.

    Both ``SemgrepBackend`` and ``TreeSitterBackend`` implement this protocol.
    Callers (the Hunter orchestrator) interact with backends only through this
    interface so that the two implementations are interchangeable.
    """

    #: Short identifier for the backend (``"semgrep"`` or ``"treesitter"``).
    name: str

    def scan_files(
        self,
        target_path: Path,
        discovered_files: list[DiscoveredFile],
        severity_threshold: str,
    ) -> BackendResult:
        """Scan files and return raw findings.

        Args:
            target_path: Root of the target codebase.
            discovered_files: Pre-filtered list of files to scan.  Backends
                MUST limit their output to findings whose ``path`` is in this
                list (post-filtering responsibility of each backend).
            severity_threshold: Minimum severity to include (``"critical"``,
                ``"high"``, ``"medium"``, ``"low"``).

        Returns:
            ``BackendResult`` containing findings, source/sink counts, and
            any diagnostic messages.
        """
        ...

    @classmethod
    def is_available(cls) -> bool:
        """Return True if this backend's runtime dependencies are available.

        For ``SemgrepBackend`` this checks that the ``semgrep`` binary is on
        ``$PATH`` and that the configured rules directory is non-empty.
        For ``TreeSitterBackend`` this always returns ``True``.
        """
        ...


def select_backend(backend_env: str | None = None) -> ScannerBackend:
    """Return the appropriate scanner backend based on configuration.

    Reads ``DCS_SCANNER_BACKEND`` from the environment (or uses the value
    supplied via ``backend_env`` for testing).  Valid values:

    * ``"auto"`` (default) — prefer ``SemgrepBackend`` when available,
      fall back to ``TreeSitterBackend``.
    * ``"semgrep"`` — require ``SemgrepBackend``; raise ``RuntimeError``
      if Semgrep is not installed or the rules directory is missing/empty.
    * ``"treesitter"`` — always use ``TreeSitterBackend``.

    Invalid values are treated as ``"auto"`` with a ``WARNING`` log.

    Args:
        backend_env: Override the environment variable (used in tests).

    Returns:
        An instance of the selected backend.

    Raises:
        RuntimeError: When ``DCS_SCANNER_BACKEND=semgrep`` and Semgrep is
            not available (binary missing from ``$PATH`` or rules directory
            empty/missing).
    """
    # Lazy imports to avoid circular dependencies.
    from deep_code_security.hunter.semgrep_backend import SemgrepBackend  # noqa: PLC0415
    from deep_code_security.hunter.treesitter_backend import TreeSitterBackend  # noqa: PLC0415

    raw = backend_env if backend_env is not None else os.environ.get("DCS_SCANNER_BACKEND", "auto")
    value = raw.strip().lower()

    if value not in _VALID_BACKEND_VALUES:
        logger.warning(
            "DCS_SCANNER_BACKEND=%r is not a valid value (expected one of %s); "
            "falling back to 'auto'.",
            raw,
            ", ".join(sorted(_VALID_BACKEND_VALUES)),
        )
        value = "auto"

    if value == "treesitter":
        logger.info("Scanner backend: treesitter (forced via DCS_SCANNER_BACKEND)")
        return TreeSitterBackend()

    if value == "semgrep":
        if not SemgrepBackend.is_available():
            raise RuntimeError(
                "Semgrep backend requested (DCS_SCANNER_BACKEND=semgrep) but the "
                "'semgrep' binary was not found on $PATH or the configured rules "
                "directory is missing or empty.  Install Semgrep with "
                "'pip install semgrep>=1.50.0,<2.0.0' or set "
                "DCS_SCANNER_BACKEND=treesitter to use the built-in tree-sitter engine."
            )
        logger.info("Scanner backend: semgrep (forced via DCS_SCANNER_BACKEND)")
        return SemgrepBackend()

    # value == "auto": prefer Semgrep, fall back to tree-sitter
    if SemgrepBackend.is_available():
        logger.info("Scanner backend: semgrep (auto-selected; semgrep binary found on $PATH)")
        return SemgrepBackend()

    logger.info(
        "Scanner backend: treesitter (auto-selected; semgrep binary not found on $PATH)"
    )
    return TreeSitterBackend()
