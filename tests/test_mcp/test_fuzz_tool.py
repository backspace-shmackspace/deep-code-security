"""Tests for the deep_scan_fuzz MCP tool and its conditional registration."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.fuzzer.execution.sandbox import ContainerBackend
from deep_code_security.mcp.server import DeepCodeSecurityMCPServer, FuzzRunState
from deep_code_security.mcp.shared.server_base import ToolError
from deep_code_security.shared.config import Config, reset_config

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture(autouse=True)
def _reset_config():
    """Reset singleton config between tests."""
    reset_config()
    yield
    reset_config()


@pytest.fixture()
def server_config(tmp_path: Path) -> Config:
    """Config with tmp_path as allowed directory."""
    os.environ["DCS_ALLOWED_PATHS"] = str(tmp_path) + "," + str(FIXTURES_DIR)
    os.environ["DCS_REGISTRY_PATH"] = str(
        Path(__file__).parent.parent.parent / "registries"
    )
    reset_config()
    config = Config()
    yield config
    os.environ.pop("DCS_ALLOWED_PATHS", None)
    os.environ.pop("DCS_REGISTRY_PATH", None)
    reset_config()


@pytest.fixture()
def server_with_container(server_config: Config) -> DeepCodeSecurityMCPServer:
    """Server initialized with ContainerBackend reporting as available."""
    with patch.object(ContainerBackend, "is_available", return_value=True):
        s = DeepCodeSecurityMCPServer(config=server_config)
        s._register_tools()
        return s


@pytest.fixture()
def server_without_container(server_config: Config) -> DeepCodeSecurityMCPServer:
    """Server initialized with ContainerBackend reporting as unavailable."""
    with patch.object(ContainerBackend, "is_available", return_value=False):
        s = DeepCodeSecurityMCPServer(config=server_config)
        s._register_tools()
        return s


class TestFuzzToolConditionalRegistration:
    """deep_scan_fuzz is only registered when ContainerBackend is available."""

    def test_fuzz_tool_registered_when_container_available(
        self, server_with_container: DeepCodeSecurityMCPServer
    ) -> None:
        """deep_scan_fuzz must appear in the tool list when Podman + image are available."""
        assert "deep_scan_fuzz" in server_with_container._tools

    def test_fuzz_tool_not_registered_when_container_unavailable(
        self, server_without_container: DeepCodeSecurityMCPServer
    ) -> None:
        """deep_scan_fuzz must NOT appear when ContainerBackend is unavailable."""
        assert "deep_scan_fuzz" not in server_without_container._tools

    def test_fuzz_status_always_registered(
        self, server_without_container: DeepCodeSecurityMCPServer
    ) -> None:
        """deep_scan_fuzz_status must always be available regardless of backend."""
        assert "deep_scan_fuzz_status" in server_without_container._tools


class TestFuzzToolConsentEnforcement:
    """The deep_scan_fuzz handler rejects calls without explicit consent."""

    @pytest.mark.asyncio
    async def test_fuzz_tool_rejects_no_consent(
        self, server_with_container: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """Calling deep_scan_fuzz with consent=False must raise ToolError."""
        target = tmp_path / "target.py"
        target.write_text("def f(x): return x")

        with pytest.raises(ToolError, match="consent"):
            await server_with_container._handle_fuzz(
                {
                    "target_path": str(target),
                    "consent": False,
                }
            )

    @pytest.mark.asyncio
    async def test_fuzz_tool_rejects_missing_consent(
        self, server_with_container: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """Calling deep_scan_fuzz with no consent key must raise ToolError."""
        target = tmp_path / "target.py"
        target.write_text("def f(x): return x")

        with pytest.raises(ToolError, match="consent"):
            await server_with_container._handle_fuzz(
                {
                    "target_path": str(target),
                    # consent not provided
                }
            )


class TestFuzzToolValidation:
    """Input validation for the deep_scan_fuzz handler."""

    @pytest.mark.asyncio
    async def test_fuzz_tool_validates_function_names(
        self, server_with_container: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """Invalid function names (shell metacharacters etc.) must raise ToolError."""
        target = tmp_path / "target.py"
        target.write_text("def f(x): return x")

        with pytest.raises(ToolError):
            await server_with_container._handle_fuzz(
                {
                    "target_path": str(target),
                    "consent": True,
                    "functions": ["valid_func", "invalid; rm -rf /"],
                }
            )

    @pytest.mark.asyncio
    async def test_fuzz_tool_rejects_path_outside_allowlist(
        self, server_with_container: DeepCodeSecurityMCPServer
    ) -> None:
        """target_path outside the DCS_ALLOWED_PATHS allowlist must raise ToolError."""
        with pytest.raises(ToolError, match="Path validation"):
            await server_with_container._handle_fuzz(
                {
                    "target_path": "/etc/passwd",
                    "consent": True,
                }
            )


class TestFuzzStatusDynamicAvailability:
    """deep_scan_fuzz_status reports container availability dynamically."""

    @pytest.mark.asyncio
    async def test_fuzz_status_reports_container_available_dynamically(
        self, server_config: Config
    ) -> None:
        """When ContainerBackend.is_available() returns True, status reports it."""
        with patch.object(ContainerBackend, "is_available", return_value=False):
            s = DeepCodeSecurityMCPServer(config=server_config)
            s._register_tools()

        # Now make it available for the status check
        with patch.object(ContainerBackend, "is_available", return_value=True):
            result = await s._handle_fuzz_status({})

        text = result["content"][0]["text"]
        data = json.loads(text)
        assert data["container_backend_available"] is True

    @pytest.mark.asyncio
    async def test_fuzz_status_reports_container_unavailable(
        self, server_config: Config
    ) -> None:
        """When ContainerBackend.is_available() returns False, status reports it."""
        with patch.object(ContainerBackend, "is_available", return_value=False):
            s = DeepCodeSecurityMCPServer(config=server_config)
            s._register_tools()
            result = await s._handle_fuzz_status({})

        text = result["content"][0]["text"]
        data = json.loads(text)
        assert data["container_backend_available"] is False

    @pytest.mark.asyncio
    async def test_fuzz_status_returns_run_state(
        self, server_config: Config
    ) -> None:
        """Polling with a known fuzz_run_id returns the stored state."""
        with patch.object(ContainerBackend, "is_available", return_value=False):
            s = DeepCodeSecurityMCPServer(config=server_config)
            s._register_tools()

        # Inject a fake run
        fake_id = "test-run-id-12345"
        s._fuzz_runs[fake_id] = FuzzRunState(
            run_id=fake_id,
            status="completed",
            result={"crashes_found": 1},
        )

        result = await s._handle_fuzz_status({"fuzz_run_id": fake_id})
        text = result["content"][0]["text"]
        data = json.loads(text)

        assert "fuzz_run" in data
        assert data["fuzz_run"]["status"] == "completed"
        assert data["fuzz_run"]["result"]["crashes_found"] == 1


class TestFuzzConcurrentRunLimit:
    """The MCP handler rejects new fuzz requests when concurrent run limit is reached."""

    @pytest.mark.asyncio
    async def test_fuzz_concurrent_run_limit(
        self, server_with_container: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """Third fuzz request must raise ToolError when 2 runs are already active."""
        target = tmp_path / "target.py"
        target.write_text("def f(x): return x")

        # Inject 2 active "running" entries into the run store
        for i in range(2):
            fake_id = f"running-run-{i}"
            server_with_container._fuzz_runs[fake_id] = FuzzRunState(
                run_id=fake_id,
                status="running",
            )

        with pytest.raises(ToolError, match="Maximum concurrent fuzz runs"):
            await server_with_container._handle_fuzz(
                {
                    "target_path": str(target),
                    "consent": True,
                }
            )

    @pytest.mark.asyncio
    async def test_fuzz_concurrent_limit_allows_when_below_limit(
        self, server_with_container: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """Request is accepted when only one run is active (limit is 2)."""
        target = tmp_path / "target.py"
        target.write_text("def f(x): return x")

        # Inject 1 active run and 1 completed run (only running ones count)
        server_with_container._fuzz_runs["running-1"] = FuzzRunState(
            run_id="running-1", status="running"
        )
        server_with_container._fuzz_runs["done-1"] = FuzzRunState(
            run_id="done-1", status="completed"
        )

        # Mock out the background thread so it doesn't actually run
        with patch("threading.Thread") as mock_thread_cls:
            mock_thread = MagicMock()
            mock_thread_cls.return_value = mock_thread
            result = await server_with_container._handle_fuzz(
                {
                    "target_path": str(target),
                    "consent": True,
                }
            )

        text = result["content"][0]["text"]
        data = json.loads(text)
        assert data["status"] == "running"
        assert "fuzz_run_id" in data


class TestFuzzThreadExceptionSetsFailedStatus:
    """If the orchestrator raises inside the background thread, run_state becomes 'failed'."""

    @pytest.mark.asyncio
    async def test_fuzz_thread_exception_sets_failed(
        self, server_with_container: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """When orchestrator.run() raises an exception, run_state.status must be 'failed'."""
        target = tmp_path / "target.py"
        target.write_text("def f(x): return x")

        # Patch both select_backend and FuzzOrchestrator in the server module.
        # We must keep patches active while waiting for the background thread —
        # _handle_fuzz() returns immediately after starting the thread, so the
        # wait loop must live inside the `with patch(...)` block.
        mock_backend = MagicMock(spec=ContainerBackend)
        mock_orc_instance = MagicMock()
        mock_orc_instance._shutdown_requested = False
        mock_orc_instance.run.side_effect = RuntimeError("simulated orchestrator failure")

        with patch(
            "deep_code_security.mcp.server.select_backend", return_value=mock_backend
        ), patch(
            "deep_code_security.fuzzer.orchestrator.FuzzOrchestrator",
            return_value=mock_orc_instance,
        ):
            result = await server_with_container._handle_fuzz(
                {
                    "target_path": str(target),
                    "consent": True,
                }
            )

            text = result["content"][0]["text"]
            data = json.loads(text)
            run_id = data["fuzz_run_id"]

            # Wait for background thread to fail (patches still active)
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                run_state = server_with_container._fuzz_runs.get(run_id)
                if run_state and run_state.status != "running":
                    break
                time.sleep(0.05)

        run_state = server_with_container._fuzz_runs.get(run_id)
        assert run_state is not None, f"Run {run_id} not found in _fuzz_runs"
        assert run_state.status == "failed", (
            f"Expected status='failed', got {run_state.status!r}"
        )
        assert run_state.error is not None
        assert "simulated orchestrator failure" in run_state.error
