"""Results view screen -- scan summary and report file openers.

Displays the summary from a completed ``RunMeta`` and provides [Open]
buttons that launch report files using the platform-native opener:

- **macOS**: ``asyncio.create_subprocess_exec("open", path)``
- **Linux**: ``asyncio.create_subprocess_exec("xdg-open", path)``
- **Windows**: ``os.startfile(path)`` (stdlib, no subprocess needed)

No ``shell=True`` is used on any platform.  File paths are constructed
from ``DCS_OUTPUT_DIR`` + sanitized project name + timestamp directory +
known filename -- fully deterministic and not user-controlled.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

if TYPE_CHECKING:
    from deep_code_security.tui.models import RunMeta

__all__ = ["ResultsViewScreen"]


class ResultsViewScreen(Screen):
    """Scan results summary with report file openers."""

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
    ]

    CSS = """
    ResultsViewScreen {
        layout: vertical;
    }

    #results-container {
        padding: 1 2;
        height: 1fr;
        overflow-y: auto;
    }

    .summary-line {
        margin-bottom: 0;
    }

    #summary-header {
        text-style: bold;
        margin-bottom: 1;
    }

    #report-files-header {
        text-style: bold;
        margin-top: 2;
        margin-bottom: 1;
    }

    .report-button {
        margin: 0 1 0 0;
    }

    #report-buttons {
        height: auto;
        margin-bottom: 1;
    }

    #nav-buttons {
        height: auto;
        align: center middle;
        padding: 1;
    }

    #new-scan-button {
        margin-right: 2;
    }
    """

    def __init__(
        self,
        run_meta: RunMeta | None = None,
        run_dir: Path | None = None,
        name: str | None = None,
        id: str | None = None,  # noqa: A002
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._run_meta = run_meta
        self._run_dir = run_dir

    def compose(self) -> ComposeResult:
        """Compose the results view layout."""
        yield Header()
        with Vertical(id="results-container"):
            yield Static("Scan Results", id="summary-header")
            yield Static(self._build_summary(), id="summary-text")
            yield Static("Report Files:", id="report-files-header")
            with Horizontal(id="report-buttons"):
                if self._run_meta is not None:
                    for filename in self._run_meta.report_files:
                        yield Button(
                            f"Open {filename}",
                            id=f"open-{filename.replace('.', '-')}",
                            classes="report-button",
                            variant="default",
                        )
                if not self._run_meta or not self._run_meta.report_files:
                    yield Static("No report files available.", id="no-reports")
            with Horizontal(id="nav-buttons"):
                yield Button(
                    "New Scan", id="new-scan-button", variant="primary"
                )
                yield Button(
                    "History", id="history-button", variant="default"
                )
        yield Footer()

    def _build_summary(self) -> str:
        """Build the summary text from run metadata."""
        if self._run_meta is None:
            return "No scan results available."

        meta = self._run_meta
        duration = meta.duration_seconds
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        exit_status = (
            "[green]Success[/green]"
            if meta.exit_code == 0
            else f"[red]Failed (exit code {meta.exit_code})[/red]"
        )

        lines = [
            f"Target: {meta.target_path}",
            f"Scan Type: {meta.scan_type}",
            f"Duration: {time_str}",
            f"Findings: {meta.findings_count}",
            f"Backend: {meta.backend_used}",
            f"Status: {exit_status}",
        ]

        if meta.languages:
            lines.append(f"Languages: {', '.join(meta.languages)}")

        if meta.severity_threshold != "medium":
            lines.append(f"Severity Threshold: {meta.severity_threshold}")

        if meta.error_message:
            lines.append(f"Error: {meta.error_message}")

        return "\n".join(lines)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses -- report openers and navigation."""
        button_id = event.button.id or ""

        if button_id == "new-scan-button":
            # Navigate back to target selection
            self.app.switch_to_screen("target_select")
            return

        if button_id == "history-button":
            self.app.push_screen("history")
            return

        if button_id.startswith("open-") and self._run_dir is not None:
            # Extract filename from button ID: open-hunt-json -> hunt.json
            file_part = button_id[len("open-"):]
            # Reverse the .replace('.', '-') from compose
            # The last dash is the extension separator
            last_dash = file_part.rfind("-")
            if last_dash >= 0:
                filename = file_part[:last_dash] + "." + file_part[last_dash + 1:]
            else:
                filename = file_part
            file_path = self._run_dir / filename
            if file_path.exists():
                self._open_file(file_path)

    def _open_file(self, file_path: Path) -> None:
        """Open a file using the platform-native opener.

        - macOS: ``open``
        - Linux: ``xdg-open``
        - Windows: ``os.startfile()``

        No ``shell=True`` is used on any platform.
        """
        path_str = str(file_path)

        if sys.platform == "win32":
            # os.startfile is a stdlib function that calls ShellExecute
            os.startfile(path_str)  # type: ignore[attr-defined]  # noqa: S606
        elif sys.platform == "darwin":
            asyncio.create_task(
                asyncio.create_subprocess_exec("open", path_str)
            )
        else:
            # Linux and other Unix-like systems
            asyncio.create_task(
                asyncio.create_subprocess_exec("xdg-open", path_str)
            )
