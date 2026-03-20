"""Target selection screen -- filesystem browser and manual path entry.

Users navigate a ``DirectoryTree`` widget or type a path into an ``Input``
widget.  The [Select] button is enabled only when the path points to an
existing file or directory.

A display-only note is shown when the selected path falls outside
``DCS_ALLOWED_PATHS`` (actual enforcement happens in the ``dcs`` subprocess).
"""

from __future__ import annotations

import os
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DirectoryTree, Footer, Header, Input, Static

__all__ = ["TargetSelectScreen"]


class TargetSelectScreen(Screen):
    """Filesystem browser with manual path input for scan target selection."""

    BINDINGS: list[tuple[str, str, str]] = []

    CSS = """
    TargetSelectScreen {
        layout: vertical;
    }

    #target-container {
        height: 1fr;
        padding: 1 2;
    }

    #tree-container {
        height: 1fr;
        border: solid green;
        margin-bottom: 1;
    }

    #path-input {
        margin-bottom: 1;
    }

    #allowed-paths-note {
        color: yellow;
        margin-bottom: 1;
        height: auto;
    }

    #select-button-container {
        height: auto;
        align: center middle;
    }

    #select-button {
        min-width: 20;
    }
    """

    def __init__(
        self,
        name: str | None = None,
        id: str | None = None,  # noqa: A002
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._selected_path: Path | None = None

    def compose(self) -> ComposeResult:
        """Compose the target selection screen layout."""
        yield Header()
        with Vertical(id="target-container"):
            yield Static("Select a scan target:", id="target-label")
            with Vertical(id="tree-container"):
                yield DirectoryTree(str(Path.cwd()), id="dir-tree")
            yield Input(
                placeholder="Or type a path manually...",
                id="path-input",
            )
            yield Static("", id="allowed-paths-note")
            with Horizontal(id="select-button-container"):
                yield Button("Select", id="select-button", variant="primary", disabled=True)
        yield Footer()

    def on_directory_tree_directory_selected(
        self, event: DirectoryTree.DirectorySelected
    ) -> None:
        """Handle directory selection from the tree."""
        self._update_selected_path(event.path)

    def on_directory_tree_file_selected(
        self, event: DirectoryTree.FileSelected
    ) -> None:
        """Handle file selection from the tree."""
        self._update_selected_path(event.path)

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle manual path input changes."""
        if event.input.id == "path-input":
            text = event.value.strip()
            if text:
                path = Path(text)
                if path.exists():
                    self._update_selected_path(path)
                else:
                    self._selected_path = None
                    self._update_select_button()
            else:
                self._selected_path = None
                self._update_select_button()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key on path input -- trigger select if valid."""
        if event.input.id == "path-input" and self._selected_path is not None:
            self._do_select()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle the [Select] button press."""
        if event.button.id == "select-button" and self._selected_path is not None:
            self._do_select()

    def _update_selected_path(self, path: Path) -> None:
        """Update the selected path and refresh UI state."""
        self._selected_path = path.resolve()
        # Update the input widget to show the resolved path
        path_input = self.query_one("#path-input", Input)
        path_input.value = str(self._selected_path)
        self._update_select_button()
        self._check_allowed_paths()

    def _update_select_button(self) -> None:
        """Enable or disable the select button based on path validity."""
        button = self.query_one("#select-button", Button)
        button.disabled = self._selected_path is None

    def _check_allowed_paths(self) -> None:
        """Display a note if the path is outside DCS_ALLOWED_PATHS.

        This is informational only -- the subprocess performs the actual
        enforcement via ``path_validator.py``.
        """
        note_widget = self.query_one("#allowed-paths-note", Static)
        if self._selected_path is None:
            note_widget.update("")
            return

        allowed_env = os.environ.get("DCS_ALLOWED_PATHS", "")
        if not allowed_env:
            note_widget.update("")
            return

        allowed_paths = [
            Path(p.strip()).resolve()
            for p in allowed_env.split(",")
            if p.strip()
        ]

        path_resolved = self._selected_path.resolve()
        is_allowed = any(
            path_resolved == ap or _is_relative_to(path_resolved, ap)
            for ap in allowed_paths
        )

        if not is_allowed:
            note_widget.update(
                "[yellow]Note: Selected path is outside DCS_ALLOWED_PATHS. "
                "The scan may be rejected by path validation.[/yellow]"
            )
        else:
            note_widget.update("")

    def _do_select(self) -> None:
        """Proceed to the scan configuration screen with the selected path."""
        if self._selected_path is not None:
            self.app.push_screen_with_kwargs(
                "scan_config",
                {"target_path": str(self._selected_path)},
            )

    @property
    def selected_path(self) -> Path | None:
        """Return the currently selected path, or None."""
        return self._selected_path


def _is_relative_to(path: Path, parent: Path) -> bool:
    """Check if *path* is relative to *parent* (Python 3.11 compatible)."""
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False
