"""TUI frontend for deep-code-security -- interactive terminal UI powered by Textual.

This module provides a keyboard-driven workflow for target selection, scan
configuration, progress monitoring, and result browsing.  It wraps the ``dcs``
CLI via subprocess for all scanning operations and uses
``shared.formatters`` for in-process format conversion (JSON to SARIF/HTML).

The ``textual`` package is an **optional** dependency.  Import this module
only through the ``dcs tui`` CLI command, which handles the ``ImportError``
gracefully.  Non-Textual modules (``models``, ``storage``, ``runner``) can be
imported directly without ``textual`` installed.
"""

from __future__ import annotations

# Re-export models for convenience (these never require textual).
from deep_code_security.tui.models import RunMeta, ScanConfig

__all__ = [
    "RunMeta",
    "ScanConfig",
]


def _check_textual_available() -> bool:
    """Return True if the ``textual`` package is importable.

    This is a lazy check -- it does not import textual at module load time,
    avoiding a hard dependency for consumers that only need the pure-Python
    models or storage layer.
    """
    try:
        import importlib.util

        return importlib.util.find_spec("textual") is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False
