"""Scan configuration screen -- scan type, languages, severity, and options.

Presents explicitly-typed UI controls for all scan parameters:

- ``RadioSet`` for scan type (hunt, full-scan, hunt-fuzz, fuzz)
- ``SelectionList`` for language filter (Python, Go, C)
- ``Select`` dropdown for severity threshold
- ``Switch`` toggles for ``--skip-verify`` and ``--ignore-suppressions``

There is NO free-form text input for additional CLI arguments.  Users who
need custom flags use the ``dcs`` CLI directly.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Label,
    RadioButton,
    RadioSet,
    Select,
    SelectionList,
    Static,
    Switch,
)

__all__ = ["ScanConfigScreen"]

_SCAN_TYPES = [
    ("hunt", "Hunt (static analysis)"),
    ("full-scan", "Full Scan (hunt + verify + remediate)"),
    ("hunt-fuzz", "Hunt-Fuzz (static + fuzzing)"),
    ("fuzz", "Fuzz (AI-powered fuzzing)"),
]

_LANGUAGES = [
    ("Python", "python", True),
    ("Go", "go", True),
    ("C", "c", True),
]

_SEVERITY_OPTIONS: list[tuple[str, str]] = [
    ("Low", "low"),
    ("Medium", "medium"),
    ("High", "high"),
    ("Critical", "critical"),
]


class ScanConfigScreen(Screen):
    """Scan configuration form with explicitly-typed controls."""

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
    ]

    CSS = """
    ScanConfigScreen {
        layout: vertical;
    }

    #config-container {
        padding: 1 2;
        height: 1fr;
        overflow-y: auto;
    }

    .section-label {
        margin-top: 1;
        margin-bottom: 0;
        text-style: bold;
    }

    #scan-type-radio {
        margin-bottom: 1;
    }

    #language-list {
        height: 5;
        margin-bottom: 1;
    }

    #severity-select {
        margin-bottom: 1;
    }

    .switch-container {
        height: 3;
        margin-bottom: 0;
    }

    .switch-label {
        width: 30;
        padding-top: 1;
    }

    #target-display {
        margin-bottom: 1;
        color: $text-muted;
    }

    #run-button-container {
        height: auto;
        align: center middle;
        padding: 1;
    }

    #run-button {
        min-width: 20;
    }
    """

    def __init__(
        self,
        target_path: str = "",
        name: str | None = None,
        id: str | None = None,  # noqa: A002
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._target_path = target_path

    def compose(self) -> ComposeResult:
        """Compose the scan configuration layout."""
        yield Header()
        with Vertical(id="config-container"):
            yield Static(
                f"Target: {self._target_path}",
                id="target-display",
                markup=False,
            )

            yield Static("Scan Type:", classes="section-label")
            with RadioSet(id="scan-type-radio"):
                for i, (type_id, label) in enumerate(_SCAN_TYPES):
                    yield RadioButton(label, id=f"scan-type-{type_id}", value=(i == 0))

            yield Static("Languages:", classes="section-label")
            yield SelectionList[str](
                *[(label, value, selected) for label, value, selected in _LANGUAGES],
                id="language-list",
            )

            yield Static("Severity Threshold:", classes="section-label")
            yield Select[str](
                options=[(label, value) for label, value in _SEVERITY_OPTIONS],
                value="medium",
                prompt="Select severity",
                allow_blank=False,
                id="severity-select",
            )

            yield Static("Options:", classes="section-label")
            with Horizontal(classes="switch-container", id="skip-verify-container"):
                yield Label("Skip verification:", classes="switch-label")
                yield Switch(value=False, id="skip-verify-switch")
            with Horizontal(classes="switch-container", id="ignore-supp-container"):
                yield Label("Ignore suppressions:", classes="switch-label")
                yield Switch(value=False, id="ignore-supp-switch")

            with Horizontal(id="run-button-container"):
                yield Button("Run Scan", id="run-button", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        """Update option visibility based on the initial scan type."""
        self._update_option_visibility()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Handle scan type radio changes to update option visibility."""
        if event.radio_set.id == "scan-type-radio":
            self._update_option_visibility()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle the [Run Scan] button press."""
        if event.button.id == "run-button":
            self._start_scan()

    def _update_option_visibility(self) -> None:
        """Show or hide options based on the selected scan type.

        - ``--skip-verify`` is only relevant for ``full-scan``.
        - ``--ignore-suppressions`` is relevant for ``hunt``, ``full-scan``,
          and ``hunt-fuzz`` (not ``fuzz``).
        """
        scan_type = self._get_selected_scan_type()

        skip_verify_container = self.query_one("#skip-verify-container")
        skip_verify_container.display = scan_type == "full-scan"

        ignore_supp_container = self.query_one("#ignore-supp-container")
        ignore_supp_container.display = scan_type != "fuzz"

    def _get_selected_scan_type(self) -> str:
        """Return the currently selected scan type string."""
        radio_set = self.query_one("#scan-type-radio", RadioSet)
        pressed_index = radio_set.pressed_index
        if pressed_index < 0 or pressed_index >= len(_SCAN_TYPES):
            return "hunt"
        return _SCAN_TYPES[pressed_index][0]

    def _get_selected_languages(self) -> list[str]:
        """Return the list of selected language values."""
        selection_list = self.query_one("#language-list", SelectionList)
        return list(selection_list.selected)

    def _get_severity_threshold(self) -> str:
        """Return the selected severity threshold."""
        select = self.query_one("#severity-select", Select)
        value = select.value
        if value is Select.BLANK or value is None:
            return "medium"
        return str(value)

    def _start_scan(self) -> None:
        """Build a ScanConfig and push the progress screen."""
        from deep_code_security.tui.models import ScanConfig

        scan_type = self._get_selected_scan_type()
        languages = self._get_selected_languages()
        severity = self._get_severity_threshold()

        skip_verify = False
        if scan_type == "full-scan":
            skip_verify_switch = self.query_one("#skip-verify-switch", Switch)
            skip_verify = skip_verify_switch.value

        ignore_suppressions = False
        if scan_type != "fuzz":
            ignore_supp_switch = self.query_one("#ignore-supp-switch", Switch)
            ignore_suppressions = ignore_supp_switch.value

        config = ScanConfig(
            target_path=self._target_path,
            scan_type=scan_type,
            languages=languages,
            severity_threshold=severity,
            skip_verify=skip_verify,
            ignore_suppressions=ignore_suppressions,
        )

        self.app.push_screen_with_kwargs(
            "scan_progress",
            {"scan_config": config},
        )
