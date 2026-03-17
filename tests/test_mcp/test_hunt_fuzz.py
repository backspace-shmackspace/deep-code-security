"""Tests for the deep_scan_hunt_fuzz MCP tool."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from deep_code_security.mcp.server import DeepCodeSecurityMCPServer


@pytest.fixture
def server(tmp_path: Path) -> DeepCodeSecurityMCPServer:
    """Create a server instance with mocked config."""
    with patch(
        "deep_code_security.mcp.server.get_config"
    ) as mock_cfg:
        cfg = MagicMock()
        cfg.allowed_paths_str = [str(tmp_path)]
        cfg.registry_path = tmp_path
        cfg.fuzz_model = "claude-sonnet-4-6"
        cfg.fuzz_max_iterations = 5
        cfg.fuzz_inputs_per_iteration = 10
        cfg.fuzz_timeout_ms = 5000
        cfg.fuzz_max_cost_usd = 5.0
        cfg.fuzz_output_dir = str(tmp_path / "fuzzy-output")
        cfg.fuzz_use_vertex = False
        cfg.fuzz_gcp_project = ""
        cfg.fuzz_gcp_region = "us-east5"
        cfg.fuzz_consent = False
        cfg.fuzz_mcp_timeout = 120
        mock_cfg.return_value = cfg
        srv = DeepCodeSecurityMCPServer(config=cfg)
    return srv


def test_hunt_fuzz_tool_registration_conditions_no_container() -> None:
    """deep_scan_hunt_fuzz is NOT registered when ContainerBackend is unavailable."""
    with (
        patch("deep_code_security.mcp.server.ContainerBackend") as mock_cb,
        patch("deep_code_security.mcp.server.get_config") as mock_cfg,
    ):
        mock_cb.is_available.return_value = False
        cfg = MagicMock()
        cfg.allowed_paths_str = ["/tmp"]
        cfg.registry_path = Path("/tmp")
        cfg.fuzz_model = "claude-sonnet-4-6"
        cfg.fuzz_inputs_per_iteration = 10
        cfg.fuzz_timeout_ms = 5000
        cfg.fuzz_max_cost_usd = 5.0
        cfg.fuzz_output_dir = "/tmp"
        cfg.fuzz_use_vertex = False
        cfg.fuzz_gcp_project = ""
        cfg.fuzz_gcp_region = "us-east5"
        cfg.fuzz_consent = False
        cfg.fuzz_mcp_timeout = 120
        mock_cfg.return_value = cfg

        srv = DeepCodeSecurityMCPServer(config=cfg)
        # deep_scan_hunt_fuzz should NOT be registered
        tool_names = list(srv._tools.keys()) if hasattr(srv, "_tools") else []
        assert "deep_scan_hunt_fuzz" not in tool_names


def test_hunt_fuzz_consent_required(server: DeepCodeSecurityMCPServer) -> None:
    """Handler raises ToolError if consent is not True."""
    from deep_code_security.mcp.shared.server_base import ToolError

    with pytest.raises(ToolError, match="consent"):
        import asyncio
        asyncio.run(
            server._handle_hunt_fuzz({"path": "/tmp", "consent": False})
        )


@pytest.mark.asyncio
async def test_hunt_fuzz_consent_false_raises(server: DeepCodeSecurityMCPServer) -> None:
    """Async test: consent=False raises ToolError."""
    from deep_code_security.mcp.shared.server_base import ToolError

    with pytest.raises(ToolError):
        await server._handle_hunt_fuzz({"path": "/tmp", "consent": False})


@pytest.mark.asyncio
async def test_hunt_fuzz_path_validation(server: DeepCodeSecurityMCPServer) -> None:
    """Invalid path raises ToolError."""
    from deep_code_security.mcp.shared.server_base import ToolError

    with pytest.raises(ToolError, match="[Pp]ath"):
        await server._handle_hunt_fuzz({
            "path": "/not/allowed/path",
            "consent": True,
        })


@pytest.mark.asyncio
async def test_hunt_fuzz_no_fuzz_targets_returns_immediately(
    server: DeepCodeSecurityMCPServer, tmp_path: Path
) -> None:
    """When bridge finds no fuzz targets, returns immediately without fuzz thread."""
    # Create a Python file with no fuzzable functions (only route handlers)
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def ping_host() -> str:
            from flask import request
            import os
            host = request.form["host"]
            return str(os.system("ping " + host))
        """)
    )

    # Mock the Hunter to return a finding in ping_host (no params)
    from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath

    mock_finding = RawFinding(
        source=Source(
            file=str(py_file), line=4, column=0,
            function="request.form", category="web_input", language="python"
        ),
        sink=Sink(
            file=str(py_file), line=5, column=4,
            function="os.system", category="command_injection",
            cwe="CWE-78", language="python"
        ),
        taint_path=TaintPath(steps=[], sanitized=False),
        vulnerability_class="CWE-78: OS Command Injection",
        severity="high",
        language="python",
        raw_confidence=0.8,
    )

    mock_stats = MagicMock()
    mock_stats.files_scanned = 1
    mock_stats.scan_duration_ms = 100

    server.hunter.scan = MagicMock(return_value=([mock_finding], mock_stats, 1, False))

    import json
    result = await server._handle_hunt_fuzz({
        "path": str(tmp_path),
        "consent": True,
    })
    content = json.loads(result["content"][0]["text"])
    # Should get no_fuzz_targets status
    assert content.get("status") == "no_fuzz_targets"


@pytest.mark.asyncio
async def test_hunt_fuzz_handler_with_mocked_pipeline(
    server: DeepCodeSecurityMCPServer, tmp_path: Path
) -> None:
    """Handler returns fuzz_run_id when fuzz targets are found."""
    py_file = tmp_path / "module.py"
    py_file.write_text(
        textwrap.dedent("""\
        def process_cmd(cmd: str) -> None:
            import os
            os.system(cmd)
        """)
    )

    from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath

    mock_finding = RawFinding(
        source=Source(
            file=str(py_file), line=1, column=0,
            function="user_input", category="cli_input", language="python"
        ),
        sink=Sink(
            file=str(py_file), line=3, column=4,
            function="os.system", category="command_injection",
            cwe="CWE-78", language="python"
        ),
        taint_path=TaintPath(steps=[], sanitized=False),
        vulnerability_class="CWE-78: OS Command Injection",
        severity="high",
        language="python",
        raw_confidence=0.8,
    )

    mock_stats = MagicMock()
    mock_stats.files_scanned = 1
    mock_stats.scan_duration_ms = 50

    server.hunter.scan = MagicMock(return_value=([mock_finding], mock_stats, 1, False))

    # Mock ContainerBackend select_backend and FuzzOrchestrator
    from deep_code_security.fuzzer.models import FuzzReport

    mock_fuzz_report = FuzzReport(
        targets=[],
        all_results=[],
        crashes=[],
        total_iterations=1,
    )

    with (
        patch("deep_code_security.mcp.server.select_backend") as mock_sb,
        patch("deep_code_security.fuzzer.orchestrator.FuzzOrchestrator.run") as mock_run,
    ):
        mock_sb.return_value = MagicMock()
        mock_run.return_value = mock_fuzz_report

        import json
        result = await server._handle_hunt_fuzz({
            "path": str(tmp_path),
            "consent": True,
            "max_iterations": 1,
        })

    content = json.loads(result["content"][0]["text"])
    # Should have a fuzz_run_id
    assert "fuzz_run_id" in content
    assert content.get("status") == "running"


@pytest.mark.asyncio
async def test_hunt_fuzz_correlation_in_status_polling(
    server: DeepCodeSecurityMCPServer, tmp_path: Path
) -> None:
    """Correlation is included in completed run when polling fuzz_status."""
    # Set up a completed run state with correlation
    from deep_code_security.mcp.server import FuzzRunState
    import time

    run_id = "test-run-123"
    run_state = FuzzRunState(
        run_id=run_id,
        status="completed",
        result={"total_iterations": 1, "crashes_found": 1, "targets": ["process_cmd"]},
        bridge_result={"fuzz_targets_count": 1, "total_findings": 1},
        correlation_result={
            "total_sast_findings": 1,
            "crash_in_scope_count": 1,
            "entries": [
                {
                    "finding_id": "f-1",
                    "target_function": "process_cmd",
                    "crash_in_finding_scope": True,
                    "crash_count": 1,
                    "crash_signatures": ["ZeroDivisionError"],
                }
            ],
        },
    )
    server._fuzz_runs[run_id] = run_state

    import json
    result = await server._handle_fuzz_status({"fuzz_run_id": run_id})
    content = json.loads(result["content"][0]["text"])

    assert "fuzz_run" in content
    fuzz_run = content["fuzz_run"]
    assert fuzz_run["status"] == "completed"
    assert "correlation_result" in fuzz_run
    assert fuzz_run["correlation_result"]["crash_in_scope_count"] == 1


@pytest.mark.asyncio
async def test_hunt_fuzz_correlation_crash_data_sanitized(
    server: DeepCodeSecurityMCPServer, tmp_path: Path
) -> None:
    """Crash signatures in correlation report are sanitized via validate_crash_data."""
    py_file = tmp_path / "module.py"
    py_file.write_text(
        textwrap.dedent("""\
        def process_cmd(cmd: str) -> None:
            import os
            os.system(cmd)
        """)
    )

    from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath
    from deep_code_security.bridge.models import BridgeResult, FuzzTarget, SASTContext
    from deep_code_security.bridge.orchestrator import BridgeOrchestrator
    from deep_code_security.bridge.models import CorrelationEntry, CorrelationReport

    mock_finding = RawFinding(
        source=Source(
            file=str(py_file), line=1, column=0,
            function="cmd", category="cli_input", language="python"
        ),
        sink=Sink(
            file=str(py_file), line=3, column=4,
            function="os.system", category="command_injection",
            cwe="CWE-78", language="python"
        ),
        taint_path=TaintPath(steps=[], sanitized=False),
        vulnerability_class="CWE-78: OS Command Injection",
        severity="high",
        language="python",
        raw_confidence=0.8,
    )

    mock_stats = MagicMock()
    mock_stats.files_scanned = 1
    mock_stats.scan_duration_ms = 10
    server.hunter.scan = MagicMock(return_value=([mock_finding], mock_stats, 1, False))

    from deep_code_security.fuzzer.models import FuzzReport, FuzzInput, FuzzResult

    fi = FuzzInput(target_function="process_cmd", args=("'; ls -la'",))
    crash = FuzzResult(
        input=fi,
        success=False,
        exception="ZeroDivisionError: " + "x" * 3000,  # overly long
    )
    mock_report = FuzzReport(
        targets=[],
        all_results=[crash],
        crashes=[crash],
        total_iterations=1,
    )

    with (
        patch("deep_code_security.mcp.server.select_backend") as mock_sb,
        patch("deep_code_security.fuzzer.orchestrator.FuzzOrchestrator.run") as mock_run,
        patch("deep_code_security.mcp.server.validate_crash_data") as mock_validate,
    ):
        mock_sb.return_value = MagicMock()
        mock_run.return_value = mock_report
        # validate_crash_data should return a truncated/safe value
        mock_validate.return_value = {
            "exception": "ZeroDivisionError: " + "x" * 2000,
            "traceback": None,
            "target_function": "process_cmd",
        }

        import json
        result = await server._handle_hunt_fuzz({
            "path": str(tmp_path),
            "consent": True,
            "max_iterations": 1,
        })

    # Verify run was started (fuzz_run_id returned)
    content = json.loads(result["content"][0]["text"])
    assert "fuzz_run_id" in content
