"""Tests for scanner backend selection and orchestrator integration.

Tests in this module cover:
- select_backend() with DCS_SCANNER_BACKEND=auto and semgrep available/unavailable
- select_backend() with DCS_SCANNER_BACKEND=treesitter (forced)
- select_backend() with DCS_SCANNER_BACKEND=semgrep and binary unavailable
- select_backend() with invalid DCS_SCANNER_BACKEND value (falls back to auto)
- HunterOrchestrator.scan() sets stats.scanner_backend correctly
- MCP server raises ToolError(retryable=False) when semgrep is forced but absent
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.hunter.models import (
    RawFinding,
    Sink,
    Source,
    TaintPath,
    TaintStep,
)
from deep_code_security.hunter.scanner_backend import BackendResult, select_backend
from deep_code_security.mcp.shared.server_base import ToolError
from deep_code_security.shared.config import Config, reset_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fake_semgrep_module(is_available: bool, name: str = "semgrep") -> types.ModuleType:
    """Create a fake ``deep_code_security.hunter.semgrep_backend`` module.

    Returns a module-like object with a ``SemgrepBackend`` class whose
    ``is_available()`` classmethod returns ``is_available``.
    """
    instance = MagicMock()
    instance.name = name

    cls = MagicMock()
    cls.is_available = MagicMock(return_value=is_available)
    cls.return_value = instance

    mod = types.ModuleType("deep_code_security.hunter.semgrep_backend")
    mod.SemgrepBackend = cls  # type: ignore[attr-defined]
    return mod


def _make_fake_treesitter_module(name: str = "treesitter") -> types.ModuleType:
    """Create a fake ``deep_code_security.hunter.treesitter_backend`` module."""
    instance = MagicMock()
    instance.name = name

    cls = MagicMock()
    cls.is_available = MagicMock(return_value=True)
    cls.return_value = instance

    mod = types.ModuleType("deep_code_security.hunter.treesitter_backend")
    mod.TreeSitterBackend = cls  # type: ignore[attr-defined]
    return mod


def _inject_fake_backends(
    semgrep_available: bool = True,
) -> tuple[types.ModuleType, types.ModuleType]:
    """Inject fake backend modules into sys.modules and return (semgrep_mod, ts_mod)."""
    semgrep_mod = _make_fake_semgrep_module(is_available=semgrep_available)
    ts_mod = _make_fake_treesitter_module()
    sys.modules["deep_code_security.hunter.semgrep_backend"] = semgrep_mod
    sys.modules["deep_code_security.hunter.treesitter_backend"] = ts_mod
    return semgrep_mod, ts_mod


def _remove_fake_backends() -> None:
    """Remove injected fake backend modules from sys.modules."""
    sys.modules.pop("deep_code_security.hunter.semgrep_backend", None)
    sys.modules.pop("deep_code_security.hunter.treesitter_backend", None)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clear_env_and_config():
    """Ensure DCS_SCANNER_BACKEND is not set, config is reset, and fake modules cleaned up.

    Saves real backend module references before each test and restores them
    after, so that _inject_fake_backends() does not leave sys.modules without
    the real modules.  Without this restoration, ``patch()`` calls in
    *other* test files re-import the backend modules, creating new module
    objects while the already-imported class objects still reference the old
    module's globals — causing mocks to silently have no effect.
    """
    os.environ.pop("DCS_SCANNER_BACKEND", None)
    reset_config()
    # Save original module objects so we can restore them after the test.
    _saved: dict[str, object] = {
        k: sys.modules.get(k)
        for k in (
            "deep_code_security.hunter.semgrep_backend",
            "deep_code_security.hunter.treesitter_backend",
        )
    }
    yield
    # Restore originals (or remove key if module was absent before the test).
    for key, original in _saved.items():
        if original is not None:
            sys.modules[key] = original  # type: ignore[assignment]
        else:
            sys.modules.pop(key, None)
    os.environ.pop("DCS_SCANNER_BACKEND", None)
    reset_config()


def _make_raw_finding(file: str = "/tmp/test.py") -> RawFinding:
    """Build a minimal RawFinding for use in test BackendResults."""
    source = Source(
        file=file,
        line=10,
        column=0,
        function="request.form",
        category="web_input",
        language="python",
    )
    sink = Sink(
        file=file,
        line=15,
        column=4,
        function="cursor.execute",
        category="sql_injection",
        cwe="CWE-89",
        language="python",
    )
    step_source = TaintStep(file=file, line=10, column=0, variable="user_input")
    step_sink = TaintStep(file=file, line=15, column=4, variable="user_input")
    taint_path = TaintPath(steps=[step_source, step_sink], sanitized=False)
    return RawFinding(
        source=source,
        sink=sink,
        taint_path=taint_path,
        vulnerability_class="CWE-89: SQL Injection",
        severity="critical",
        language="python",
        raw_confidence=0.6,
    )


# ---------------------------------------------------------------------------
# Test select_backend() -- auto mode
# ---------------------------------------------------------------------------


class TestSelectBackendAuto:
    """select_backend() with DCS_SCANNER_BACKEND=auto (the default)."""

    def test_auto_returns_semgrep_when_available(self) -> None:
        """When auto mode and semgrep is available, a semgrep-named backend is returned."""
        semgrep_mod, ts_mod = _inject_fake_backends(semgrep_available=True)

        backend = select_backend("auto")

        assert backend.name == "semgrep"
        # Verify availability was checked
        semgrep_mod.SemgrepBackend.is_available.assert_called_once()

    def test_auto_falls_back_to_treesitter_when_semgrep_unavailable(self) -> None:
        """When auto mode and semgrep is NOT available, treesitter backend is returned."""
        semgrep_mod, ts_mod = _inject_fake_backends(semgrep_available=False)

        backend = select_backend("auto")

        assert backend.name == "treesitter"
        # Semgrep was checked and found unavailable
        semgrep_mod.SemgrepBackend.is_available.assert_called_once()


# ---------------------------------------------------------------------------
# Test select_backend() -- explicit treesitter
# ---------------------------------------------------------------------------


class TestSelectBackendTreesitter:
    """select_backend() with DCS_SCANNER_BACKEND=treesitter."""

    def test_treesitter_forced_returns_treesitter(self) -> None:
        """When treesitter is forced, TreeSitterBackend is returned."""
        semgrep_mod, ts_mod = _inject_fake_backends(semgrep_available=True)

        backend = select_backend("treesitter")

        assert backend.name == "treesitter"

    def test_treesitter_forced_does_not_check_semgrep_availability(self) -> None:
        """When treesitter is forced, SemgrepBackend.is_available() is never called."""
        semgrep_mod, ts_mod = _inject_fake_backends(semgrep_available=True)

        select_backend("treesitter")

        semgrep_mod.SemgrepBackend.is_available.assert_not_called()


# ---------------------------------------------------------------------------
# Test select_backend() -- explicit semgrep, binary unavailable
# ---------------------------------------------------------------------------


class TestSelectBackendSemgrepUnavailable:
    """select_backend() with DCS_SCANNER_BACKEND=semgrep when binary is missing."""

    def test_semgrep_forced_but_unavailable_raises_runtime_error(self) -> None:
        """RuntimeError is raised when semgrep is forced but not available."""
        _inject_fake_backends(semgrep_available=False)

        with pytest.raises(RuntimeError) as exc_info:
            select_backend("semgrep")

        # The error message must mention 'semgrep'
        assert "semgrep" in str(exc_info.value).lower()

    def test_semgrep_forced_and_available_returns_backend(self) -> None:
        """When semgrep is forced and available, a semgrep backend is returned."""
        _inject_fake_backends(semgrep_available=True)

        backend = select_backend("semgrep")

        assert backend.name == "semgrep"


# ---------------------------------------------------------------------------
# Test select_backend() -- invalid backend value
# ---------------------------------------------------------------------------


class TestSelectBackendInvalid:
    """select_backend() with invalid DCS_SCANNER_BACKEND value."""

    def test_invalid_value_falls_back_to_treesitter_when_semgrep_absent(self) -> None:
        """Invalid backend value is treated as 'auto'; treesitter is selected when semgrep absent."""
        _inject_fake_backends(semgrep_available=False)

        # "foobar" is not a valid backend value; should fall back to auto -> treesitter
        backend = select_backend("foobar")

        assert backend.name == "treesitter"

    def test_invalid_value_falls_back_to_semgrep_when_semgrep_available(self) -> None:
        """Invalid backend value is treated as 'auto'; semgrep selected when available."""
        _inject_fake_backends(semgrep_available=True)

        backend = select_backend("invalid_value_xyz")

        assert backend.name == "semgrep"


# ---------------------------------------------------------------------------
# Test orchestrator sets stats.scanner_backend
# ---------------------------------------------------------------------------


class TestOrchestratorScanStats:
    """HunterOrchestrator.scan() propagates scanner_backend to ScanStats."""

    def test_scan_sets_scanner_backend_in_stats(self, tmp_path: Path) -> None:
        """stats.scanner_backend matches the selected backend's name after scan()."""
        # Create a minimal Python file so file discovery finds something
        (tmp_path / "app.py").write_text("x = 1\n")

        # Build a mock backend that returns an empty BackendResult
        mock_backend = MagicMock()
        mock_backend.name = "semgrep"
        mock_backend.scan_files.return_value = BackendResult(
            findings=[],
            sources_found=3,
            sinks_found=2,
            taint_paths_found=0,
            backend_name="semgrep",
            diagnostics=[],
        )

        # Inject the mock backend via sys.modules so select_backend returns it
        semgrep_mod = _make_fake_semgrep_module(is_available=True)
        semgrep_mod.SemgrepBackend.return_value = mock_backend  # type: ignore[attr-defined]
        ts_mod = _make_fake_treesitter_module()
        sys.modules["deep_code_security.hunter.semgrep_backend"] = semgrep_mod
        sys.modules["deep_code_security.hunter.treesitter_backend"] = ts_mod

        os.environ["DCS_ALLOWED_PATHS"] = str(tmp_path)
        os.environ["DCS_REGISTRY_PATH"] = str(
            Path(__file__).parent.parent.parent / "registries"
        )
        os.environ["DCS_SCANNER_BACKEND"] = "auto"
        reset_config()
        config = Config()

        # Also patch the backend's scan_files call specifically
        with patch(
            "deep_code_security.hunter.scanner_backend.select_backend",
            return_value=mock_backend,
        ):
            from deep_code_security.hunter.orchestrator import HunterOrchestrator

            hunter = HunterOrchestrator(config=config)
            _findings, stats, _total, _has_more = hunter.scan(
                target_path=str(tmp_path)
            )

        assert stats.scanner_backend == "semgrep"
        assert stats.sources_found == 3
        assert stats.sinks_found == 2

        # Cleanup
        os.environ.pop("DCS_ALLOWED_PATHS", None)
        os.environ.pop("DCS_REGISTRY_PATH", None)
        os.environ.pop("DCS_SCANNER_BACKEND", None)
        reset_config()

    def test_scan_treesitter_backend_in_stats(self, tmp_path: Path) -> None:
        """When treesitter backend is selected, stats.scanner_backend is 'treesitter'."""
        (tmp_path / "main.py").write_text("x = 1\n")

        mock_backend = MagicMock()
        mock_backend.name = "treesitter"
        mock_backend.scan_files.return_value = BackendResult(
            findings=[],
            sources_found=0,
            sinks_found=0,
            taint_paths_found=0,
            backend_name="treesitter",
            diagnostics=[],
        )

        os.environ["DCS_ALLOWED_PATHS"] = str(tmp_path)
        os.environ["DCS_REGISTRY_PATH"] = str(
            Path(__file__).parent.parent.parent / "registries"
        )
        os.environ["DCS_SCANNER_BACKEND"] = "treesitter"
        reset_config()
        config = Config()

        with patch(
            "deep_code_security.hunter.scanner_backend.select_backend",
            return_value=mock_backend,
        ):
            from deep_code_security.hunter.orchestrator import HunterOrchestrator

            hunter = HunterOrchestrator(config=config)
            _findings, stats, _total, _has_more = hunter.scan(
                target_path=str(tmp_path)
            )

        assert stats.scanner_backend == "treesitter"

        # Cleanup
        os.environ.pop("DCS_ALLOWED_PATHS", None)
        os.environ.pop("DCS_REGISTRY_PATH", None)
        os.environ.pop("DCS_SCANNER_BACKEND", None)
        reset_config()

    def test_scan_backend_diagnostics_are_logged(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Diagnostics from BackendResult are emitted as warnings by the orchestrator."""
        import logging

        (tmp_path / "app.py").write_text("x = 1\n")

        mock_backend = MagicMock()
        mock_backend.name = "semgrep"
        mock_backend.scan_files.return_value = BackendResult(
            findings=[],
            sources_found=0,
            sinks_found=0,
            taint_paths_found=0,
            backend_name="semgrep",
            diagnostics=["Semgrep rule file not found: missing.yaml"],
        )

        os.environ["DCS_ALLOWED_PATHS"] = str(tmp_path)
        os.environ["DCS_REGISTRY_PATH"] = str(
            Path(__file__).parent.parent.parent / "registries"
        )
        reset_config()
        config = Config()

        with (
            patch(
                "deep_code_security.hunter.scanner_backend.select_backend",
                return_value=mock_backend,
            ),
            caplog.at_level(logging.WARNING, logger="deep_code_security.hunter.orchestrator"),
        ):
            from deep_code_security.hunter.orchestrator import HunterOrchestrator

            hunter = HunterOrchestrator(config=config)
            hunter.scan(target_path=str(tmp_path))

        assert any(
            "Semgrep rule file not found" in record.message
            for record in caplog.records
        ), f"Expected diagnostic warning not found in: {[r.message for r in caplog.records]}"

        # Cleanup
        os.environ.pop("DCS_ALLOWED_PATHS", None)
        os.environ.pop("DCS_REGISTRY_PATH", None)
        reset_config()


# ---------------------------------------------------------------------------
# Test MCP ToolError when DCS_SCANNER_BACKEND=semgrep and binary absent
# ---------------------------------------------------------------------------


class TestMCPToolErrorWhenSemgrepAbsent:
    """MCP server must raise ToolError(retryable=False) when semgrep is forced but absent.

    Plan acceptance criterion AC-7: ``DCS_SCANNER_BACKEND=semgrep`` returns a
    clear ``ToolError(retryable=False)`` from MCP.
    """

    def test_handle_hunt_raises_tool_error_when_hunter_init_fails(
        self, tmp_path: Path
    ) -> None:
        """ToolError(retryable=False) is raised by _handle_hunt when HunterOrchestrator
        could not be initialized due to semgrep being unavailable.

        The MCP server catches RuntimeError from HunterOrchestrator.__init__ and
        stores it as self._hunter_init_error.  When deep_scan_hunt is called,
        _handle_hunt raises ToolError(retryable=False) immediately.
        """
        import asyncio

        from deep_code_security.mcp.server import DeepCodeSecurityMCPServer

        os.environ["DCS_ALLOWED_PATHS"] = str(tmp_path)
        reset_config()

        try:
            # Patch HunterOrchestrator.__init__ to raise RuntimeError, simulating
            # DCS_SCANNER_BACKEND=semgrep with the binary absent.
            with patch(
                "deep_code_security.mcp.server.HunterOrchestrator.__init__",
                side_effect=RuntimeError("Semgrep not found on $PATH"),
            ):
                server = DeepCodeSecurityMCPServer()

            # The server should be initialized but hunter must be None
            assert server.hunter is None
            assert server._hunter_init_error is not None
            assert "Semgrep not found" in server._hunter_init_error

            # Calling _handle_hunt must raise ToolError(retryable=False)
            with pytest.raises(ToolError) as exc_info:
                asyncio.run(server._handle_hunt({"path": str(tmp_path)}))

            tool_error = exc_info.value
            assert tool_error.retryable is False
            assert "unavailable" in str(tool_error).lower() or "semgrep" in str(tool_error).lower()

        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)
            reset_config()

    def test_handle_full_raises_tool_error_when_hunter_init_fails(
        self, tmp_path: Path
    ) -> None:
        """ToolError(retryable=False) is also raised by _handle_full when hunter is None."""
        import asyncio

        from deep_code_security.mcp.server import DeepCodeSecurityMCPServer

        os.environ["DCS_ALLOWED_PATHS"] = str(tmp_path)
        reset_config()

        try:
            with patch(
                "deep_code_security.mcp.server.HunterOrchestrator.__init__",
                side_effect=RuntimeError("Semgrep binary missing"),
            ):
                server = DeepCodeSecurityMCPServer()

            assert server.hunter is None

            with pytest.raises(ToolError) as exc_info:
                asyncio.run(server._handle_full({"path": str(tmp_path)}))

            assert exc_info.value.retryable is False

        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)
            reset_config()
