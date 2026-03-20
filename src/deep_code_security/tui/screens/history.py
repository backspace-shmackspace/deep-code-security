"""History screen -- browse past scan runs per project.

Displays a ``Select`` dropdown for project selection and a ``DataTable``
of past runs sorted by date descending.  Each row shows the date, scan
type, findings count, duration, backend, and exit code.  A [View] button
opens the selected run's report directory in the platform file manager.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Select, Static

__all__ = ["HistoryScreen"]


class HistoryScreen(Screen):
    """Per-project run history browser."""

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
    ]

    CSS = """
    HistoryScreen {
        layout: vertical;
    }

    #history-container {
        padding: 1 2;
        height: 1fr;
    }

    #history-header {
        text-style: bold;
        margin-bottom: 1;
    }

    #project-select {
        margin-bottom: 1;
    }

    #runs-table {
        height: 1fr;
        margin-bottom: 1;
    }

    #history-buttons {
        height: auto;
        align: center middle;
        padding: 1;
    }
    """

    def __init__(
        self,
        name: str | None = None,
        id: str | None = None,  # noqa: A002
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._storage: object | None = None
        self._current_project: str | None = None
        # Maps integer row index to run directory paths for the [View] action
        self._row_dirs: dict[int, Path] = {}

    def compose(self) -> ComposeResult:
        """Compose the history screen layout."""
        yield Header()
        with Vertical(id="history-container"):
            yield Static("Scan History", id="history-header")
            yield Select[str](
                options=[],
                prompt="Select project",
                allow_blank=True,
                id="project-select",
            )
            yield DataTable(id="runs-table")
            with Horizontal(id="history-buttons"):
                yield Button("View", id="view-button", variant="default")
                yield Button("Back", id="back-button", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        """Initialize the data table columns and load projects."""
        table = self.query_one("#runs-table", DataTable)
        table.add_columns(
            "Date", "Scan Type", "Findings", "Duration", "Backend", "Exit Code"
        )
        table.cursor_type = "row"

        self._load_projects()

    def _load_projects(self) -> None:
        """Load the project list from ReportStorage."""
        try:
            from deep_code_security.tui.storage import ReportStorage

            self._storage = ReportStorage()
            projects = self._storage.list_projects()
        except ImportError:
            projects = []

        select = self.query_one("#project-select", Select)
        if projects:
            select.set_options(
                [(name, name) for name in sorted(projects)]
            )
        else:
            select.set_options([("No projects found", "")])

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle project selection changes."""
        if event.select.id == "project-select":
            value = event.value
            if value is Select.BLANK or value is None or value == "":
                return
            self._current_project = str(value)
            self._load_runs(self._current_project)

    def _load_runs(self, project_name: str) -> None:
        """Load run history for the selected project into the DataTable.

        Builds a run_id -> directory mapping in a single pass over the
        project directory, then populates the table using the sorted run
        list from storage.  Uses integer row indices for the [View] button
        lookup (M-2, M-3 fixes).
        """
        table = self.query_one("#runs-table", DataTable)
        table.clear()
        self._row_dirs.clear()

        if self._storage is None:
            return

        try:
            runs = self._storage.list_runs(project_name)
        except Exception:
            return

        # Build a run_id -> directory mapping in a single pass (M-2 fix)
        run_id_to_dir: dict[str, Path] = {}
        output_dir = self._storage.get_output_dir()
        project_dir = output_dir / project_name
        if project_dir.is_dir():
            for child in project_dir.iterdir():
                if child.is_dir() and (child / "meta.json").exists():
                    child_meta = self._storage.read_meta(child)
                    if child_meta is not None:
                        run_id_to_dir[child_meta.run_id] = child

        for row_index, meta in enumerate(runs):
            duration = meta.duration_seconds
            hours = int(duration // 3600)
            minutes = int((duration % 3600) // 60)
            seconds = int(duration % 60)
            time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

            exit_display = (
                str(meta.exit_code)
                if meta.exit_code == 0
                else f"[red]{meta.exit_code}[/red]"
            )

            table.add_row(
                meta.timestamp,
                meta.scan_type,
                str(meta.findings_count),
                time_str,
                meta.backend_used,
                exit_display,
            )

            # M-3 fix: use integer row index as the key
            if meta.run_id in run_id_to_dir:
                self._row_dirs[row_index] = run_id_to_dir[meta.run_id]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle [View] and [Back] button presses."""
        if event.button.id == "back-button":
            self.app.pop_screen()
            return

        if event.button.id == "view-button":
            table = self.query_one("#runs-table", DataTable)
            cursor_row = table.cursor_row
            if cursor_row is not None and cursor_row in self._row_dirs:
                self._open_directory(self._row_dirs[cursor_row])

    def _open_directory(self, dir_path: Path) -> None:
        """Open a directory in the platform file manager.

        Uses the same platform-native approach as ``ResultsViewScreen``:
        - macOS: ``open``
        - Linux: ``xdg-open``
        - Windows: ``os.startfile()``

        No ``shell=True`` on any platform.
        """
        path_str = str(dir_path)

        if sys.platform == "win32":
            os.startfile(path_str)  # type: ignore[attr-defined]  # noqa: S606
        elif sys.platform == "darwin":
            asyncio.create_task(
                asyncio.create_subprocess_exec("open", path_str)
            )
        else:
            asyncio.create_task(
                asyncio.create_subprocess_exec("xdg-open", path_str)
            )
