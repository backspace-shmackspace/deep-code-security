"""Scan progress screen -- live log, phase indicator, elapsed time, cancel.

This is the most critical screen for long-running scans (e.g., 45-minute
OpenSSL scans).  It streams stderr output in real time via a ``RichLog``
widget, shows the current scan phase, elapsed time, and provides a
[Cancel] button that sends ``SIGTERM`` to the subprocess.

The screen uses Textual's ``work`` decorator to run the scan in a worker,
posting messages back to the UI thread for display updates.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, RichLog, Static

if TYPE_CHECKING:
    from deep_code_security.tui.models import RunMeta, ScanConfig

__all__ = ["ScanProgressScreen"]


class ScanProgressScreen(Screen):
    """Live scan progress display with log streaming and cancellation."""

    BINDINGS = [
        ("ctrl+c", "cancel_scan", "Cancel scan"),
    ]

    CSS = """
    ScanProgressScreen {
        layout: vertical;
    }

    #progress-container {
        padding: 1 2;
        height: 1fr;
    }

    #phase-indicator {
        text-style: bold;
        margin-bottom: 1;
    }

    #elapsed-time {
        margin-bottom: 1;
        color: $text-muted;
    }

    #scan-log {
        height: 1fr;
        border: solid green;
        margin-bottom: 1;
    }

    #cancel-button-container {
        height: auto;
        align: center middle;
        padding: 1;
    }

    #cancel-button {
        min-width: 20;
    }
    """

    def __init__(
        self,
        scan_config: ScanConfig | None = None,
        name: str | None = None,
        id: str | None = None,  # noqa: A002
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._scan_config = scan_config
        self._start_time: float = 0.0
        self._runner: object | None = None  # ScanRunner instance
        self._completed_meta: RunMeta | None = None
        self._completed_run_dir: Path | None = None
        self._cancelled = False
        self._cancel_event = threading.Event()
        self._worker_loop: object | None = None  # asyncio event loop in worker thread

    def compose(self) -> ComposeResult:
        """Compose the progress screen layout."""
        yield Header()
        with Vertical(id="progress-container"):
            yield Static("Initializing scan...", id="phase-indicator")
            yield Static("Elapsed: 00:00:00", id="elapsed-time")
            yield RichLog(highlight=True, markup=True, id="scan-log")
            with Horizontal(id="cancel-button-container"):
                yield Button(
                    "Cancel", id="cancel-button", variant="error"
                )
        yield Footer()

    def on_mount(self) -> None:
        """Start the scan and elapsed time timer when the screen mounts."""
        self._start_time = time.monotonic()
        self.set_interval(1.0, self._update_elapsed)
        if self._scan_config is not None:
            self._run_scan()

    def _update_elapsed(self) -> None:
        """Update the elapsed time display every second."""
        if self._start_time <= 0:
            return
        elapsed = time.monotonic() - self._start_time
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = int(elapsed % 60)
        elapsed_widget = self.query_one("#elapsed-time", Static)
        elapsed_widget.update(f"Elapsed: {hours:02d}:{minutes:02d}:{seconds:02d}")

    @work(thread=True)
    def _run_scan(self) -> None:
        """Execute the scan in a worker thread.

        This method imports and uses ``ScanRunner`` from the ``tui.runner``
        module to run the scan subprocess.

        The worker posts progress updates to the UI thread via
        ``call_from_thread``.
        """
        try:
            from deep_code_security.tui.runner import ScanRunner
            from deep_code_security.tui.storage import ReportStorage
        except ImportError:
            self.app.call_from_thread(
                self._log_line, "[red]Error: Runner module not available.[/red]"
            )
            self.app.call_from_thread(self._update_phase, "Error: runner not available")
            return

        if self._scan_config is None:
            self.app.call_from_thread(self._log_line, "[red]Error: No scan configuration.[/red]")
            return

        storage = ReportStorage()
        project_name = storage.derive_project_name(self._scan_config.target_path)
        run_dir = storage.create_run_dir(project_name)

        def on_stderr_line(line: str) -> None:
            self.app.call_from_thread(self._log_line, line)
            # Update phase indicator if line looks like a phase transition
            if line.strip().startswith("[") and "/" in line and "]" in line:
                self.app.call_from_thread(self._update_phase, line.strip())

        runner = ScanRunner(
            scan_config=self._scan_config,
            run_dir=run_dir,
            on_stderr_line=on_stderr_line,
        )
        self._runner = runner

        import asyncio

        loop = asyncio.new_event_loop()
        self._worker_loop = loop
        try:
            meta = loop.run_until_complete(runner.run())

            # C-1: Persist meta.json to the run directory
            storage.write_meta(run_dir, meta)

            self._completed_meta = meta
            self._completed_run_dir = run_dir
            self.app.call_from_thread(self._on_scan_complete, meta, run_dir)
        except Exception as exc:
            self.app.call_from_thread(
                self._log_line,
                f"[red]Scan error: {exc}[/red]",
            )
            self.app.call_from_thread(self._update_phase, "Scan failed")
        finally:
            loop.close()
            self._worker_loop = None

    def _log_line(self, line: str) -> None:
        """Append a line to the scan log widget."""
        log = self.query_one("#scan-log", RichLog)
        log.write(line)

    def _update_phase(self, phase_text: str) -> None:
        """Update the phase indicator text."""
        phase = self.query_one("#phase-indicator", Static)
        phase.update(phase_text)

    def _on_scan_complete(self, meta: RunMeta, run_dir: Path) -> None:
        """Handle scan completion -- update UI and navigate to results."""
        self._update_phase("Scan complete")
        cancel_button = self.query_one("#cancel-button", Button)
        cancel_button.disabled = True

        duration = meta.duration_seconds
        findings = meta.findings_count
        self._log_line(
            f"\n[green]Scan finished in {duration:.1f}s "
            f"with {findings} finding(s).[/green]"
        )

        # C-2: Navigate to ResultsViewScreen with the completed metadata
        from deep_code_security.tui.screens.results_view import ResultsViewScreen

        self.app.push_screen(
            ResultsViewScreen(run_meta=meta, run_dir=run_dir)
        )

    def action_cancel_scan(self) -> None:
        """Cancel the running scan via SIGTERM.

        Uses a threading Event to signal the worker thread, and schedules
        the async cancel on the worker's event loop (where the subprocess
        Process object lives).
        """
        if self._cancelled:
            return
        self._cancelled = True
        self._cancel_event.set()
        self._update_phase("Cancelling...")
        self._log_line("[yellow]Cancelling scan...[/yellow]")

        cancel_button = self.query_one("#cancel-button", Button)
        cancel_button.disabled = True

        if self._runner is not None and self._worker_loop is not None:
            import asyncio

            try:
                loop = self._worker_loop
                if isinstance(loop, asyncio.AbstractEventLoop) and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self._runner.cancel(), loop
                    )
            except Exception:  # noqa: S110, BLE001
                pass  # Best effort cancellation

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle the [Cancel] button press."""
        if event.button.id == "cancel-button":
            self.action_cancel_scan()

    @property
    def completed_meta(self) -> RunMeta | None:
        """Return the completed run metadata, if available."""
        return self._completed_meta
