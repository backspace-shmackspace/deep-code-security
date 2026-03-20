"""TUI screen modules for deep-code-security.

Each screen provides a distinct step in the scan workflow:
target selection, scan configuration, progress monitoring,
results viewing, and run history browsing.

All screens depend on the ``textual`` package and must only be
imported when textual is available (e.g., via the ``dcs tui`` CLI
command).
"""

from __future__ import annotations

from deep_code_security.tui.screens.history import HistoryScreen
from deep_code_security.tui.screens.results_view import ResultsViewScreen
from deep_code_security.tui.screens.scan_config import ScanConfigScreen
from deep_code_security.tui.screens.scan_progress import ScanProgressScreen
from deep_code_security.tui.screens.target_select import TargetSelectScreen

__all__ = [
    "HistoryScreen",
    "ResultsViewScreen",
    "ScanConfigScreen",
    "ScanProgressScreen",
    "TargetSelectScreen",
]
