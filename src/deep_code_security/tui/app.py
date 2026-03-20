"""Main Textual application for deep-code-security TUI.

``DCSApp`` subclasses ``textual.app.App`` and manages screen navigation
for the full scan workflow: target selection, scan configuration,
progress monitoring, results viewing, and run history browsing.

Key bindings:

- ``q``: Quit the application
- ``Escape``: Go back to the previous screen
- ``Ctrl+C``: Cancel a running scan (on ScanProgressScreen)
- ``Enter``: Confirm selection / start scan
- ``Tab`` / ``Shift+Tab``: Navigate between widgets
"""

from __future__ import annotations

from textual.app import App

from deep_code_security import __version__
from deep_code_security.tui.screens.history import HistoryScreen
from deep_code_security.tui.screens.results_view import ResultsViewScreen
from deep_code_security.tui.screens.scan_config import ScanConfigScreen
from deep_code_security.tui.screens.scan_progress import ScanProgressScreen
from deep_code_security.tui.screens.target_select import TargetSelectScreen

__all__ = ["DCSApp"]


class DCSApp(App):
    """Interactive TUI frontend for deep-code-security.

    Provides a keyboard-driven workflow for:
    1. Selecting a scan target (directory or file)
    2. Configuring scan options (type, languages, severity, toggles)
    3. Monitoring scan progress in real time
    4. Viewing results and opening report files
    5. Browsing scan history per project
    """

    TITLE = f"deep-code-security v{__version__}"
    SUB_TITLE = "Interactive Security Scanner"

    CSS = """
    Screen {
        background: $surface;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("escape", "pop_screen_safe", "Back"),
    ]

    SCREENS = {
        "target_select": TargetSelectScreen,
        "history": HistoryScreen,
    }

    def on_mount(self) -> None:
        """Push the initial target selection screen on app mount."""
        self.push_screen(TargetSelectScreen())

    def action_pop_screen_safe(self) -> None:
        """Pop the current screen, keeping the initial TargetSelectScreen.

        Textual always has a default screen at position 0.  We push
        TargetSelectScreen on top of it during ``on_mount``, so the
        minimum stack depth during normal operation is 2.  This guard
        prevents popping past TargetSelectScreen.
        """
        if len(self.screen_stack) > 2:
            self.pop_screen()

    def push_screen_with_kwargs(
        self,
        screen_name: str,
        kwargs: dict,
    ) -> None:
        """Push a screen by name, passing keyword arguments for construction.

        This method constructs a screen instance from the given name and
        kwargs, then pushes it.  This allows screens to pass data to the
        next screen (e.g., target path from TargetSelectScreen to
        ScanConfigScreen).

        Unlike overriding ``push_screen``, this keeps the base class
        signature intact so Textual's callback plumbing works correctly.
        """
        screen_instance = self._build_screen(screen_name, kwargs)
        if screen_instance is not None:
            self.push_screen(screen_instance)

    def switch_to_screen(self, screen_name: str) -> None:
        """Switch to a screen by name, popping all intermediate screens.

        Constructs a fresh screen instance and replaces the current stack
        (keeping only Textual's default screen).  This avoids overriding
        the base class ``switch_screen`` with an incompatible signature.
        """
        instance = self._build_screen(screen_name, {})
        if instance is not None:
            # Pop all screens down to the default screen
            while len(self.screen_stack) > 1:
                self.pop_screen()
            self.push_screen(instance)

    def _build_screen(self, name: str, kwargs: dict) -> object | None:
        """Construct a screen instance by name with kwargs."""
        if name == "target_select":
            return TargetSelectScreen(**kwargs)
        if name == "scan_config":
            return ScanConfigScreen(**kwargs)
        if name == "scan_progress":
            return ScanProgressScreen(**kwargs)
        if name == "results_view":
            return ResultsViewScreen(**kwargs)
        if name == "history":
            return HistoryScreen(**kwargs)
        return None
