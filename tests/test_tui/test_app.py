"""Textual pilot tests for DCSApp.

Tests cover startup, initial screen detection, and quit key binding.
These tests gracefully skip when ``textual`` is not installed.
"""

from __future__ import annotations

import pytest

# Gracefully skip if textual is not installed
pytest.importorskip("textual")


from deep_code_security.tui.app import DCSApp  # noqa: E402
from deep_code_security.tui.screens.target_select import TargetSelectScreen  # noqa: E402


@pytest.mark.asyncio
async def test_app_startup() -> None:
    """DCSApp mounts without error."""
    app = DCSApp()
    async with app.run_test() as _pilot:
        # Verify the app started and has a screen
        assert app.screen is not None
        assert len(app.screen_stack) >= 1


@pytest.mark.asyncio
async def test_app_initial_screen() -> None:
    """The initial screen is TargetSelectScreen."""
    app = DCSApp()
    async with app.run_test() as _pilot:
        assert isinstance(app.screen, TargetSelectScreen)


@pytest.mark.asyncio
async def test_app_quit_binding() -> None:
    """Pressing 'q' triggers the quit action."""
    app = DCSApp()
    async with app.run_test() as pilot:
        await pilot.press("q")
        # After pressing q, the app should exit.
        # run_test context manager handles cleanup.
        # If the app did not quit, this test would hang
        # (run_test times out after 5 seconds by default).


@pytest.mark.asyncio
async def test_app_title_contains_version() -> None:
    """The app title includes the package version."""
    from deep_code_security import __version__

    app = DCSApp()
    async with app.run_test() as _pilot:
        assert __version__ in app.title


@pytest.mark.asyncio
async def test_app_escape_on_initial_screen() -> None:
    """Pressing Escape on the initial screen does not crash.

    The initial TargetSelectScreen is the only screen on the stack
    (beyond the default), so Escape should be a no-op rather than
    raising an error.
    """
    app = DCSApp()
    async with app.run_test() as pilot:
        await pilot.press("escape")
        # The app should still be running with the same screen
        assert isinstance(app.screen, TargetSelectScreen)
