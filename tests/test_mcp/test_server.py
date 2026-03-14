"""Tests for the MCP server."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from deep_code_security.mcp.input_validator import InputValidationError, validate_raw_finding
from deep_code_security.mcp.path_validator import PathValidationError, validate_path
from deep_code_security.mcp.server import DeepCodeSecurityMCPServer
from deep_code_security.shared.config import Config, reset_config

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def server_config(tmp_path: Path) -> Config:
    """Config with tmp_path as allowed directory."""
    os.environ["DCS_ALLOWED_PATHS"] = str(tmp_path) + "," + str(FIXTURES_DIR)
    os.environ["DCS_REGISTRY_PATH"] = str(Path(__file__).parent.parent.parent / "registries")
    reset_config()
    config = Config()
    yield config
    os.environ.pop("DCS_ALLOWED_PATHS", None)
    os.environ.pop("DCS_REGISTRY_PATH", None)
    reset_config()


@pytest.fixture
def server(server_config: Config) -> DeepCodeSecurityMCPServer:
    """A configured MCP server for testing."""
    s = DeepCodeSecurityMCPServer(config=server_config)
    s._register_tools()
    return s


class TestToolRegistration:
    """Tests for tool registration."""

    def test_all_tools_registered(self, server: DeepCodeSecurityMCPServer) -> None:
        """All 6 required tools are registered (deep_scan_fuzz deferred)."""
        expected = {
            "deep_scan_hunt",
            "deep_scan_verify",
            "deep_scan_remediate",
            "deep_scan_full",
            "deep_scan_status",
            "deep_scan_fuzz_status",
        }
        assert set(server._tools.keys()) == expected

    def test_each_tool_has_description(self, server: DeepCodeSecurityMCPServer) -> None:
        """Each tool has a non-empty description."""
        for name, tool in server._tools.items():
            assert tool["description"], f"Tool {name!r} has empty description"

    def test_each_tool_has_input_schema(self, server: DeepCodeSecurityMCPServer) -> None:
        """Each tool has an input schema with 'type': 'object'."""
        for name, tool in server._tools.items():
            assert tool["inputSchema"]["type"] == "object", f"Tool {name!r} schema type is not 'object'"

    def test_each_tool_has_handler(self, server: DeepCodeSecurityMCPServer) -> None:
        """Each tool has a registered handler."""
        for name in server._tools:
            assert name in server._handlers, f"Tool {name!r} has no handler"


class TestPathValidation:
    """Tests for path validation in tool handlers."""

    @pytest.mark.asyncio
    async def test_hunt_rejects_path_outside_allowlist(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """deep_scan_hunt rejects paths outside the allowlist."""
        from deep_code_security.mcp.shared.server_base import ToolError
        with pytest.raises(ToolError, match="Path validation"):
            await server._handle_hunt({"path": "/etc/passwd"})

    @pytest.mark.asyncio
    async def test_hunt_rejects_path_with_traversal(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """deep_scan_hunt rejects paths with .. traversal."""
        from deep_code_security.mcp.shared.server_base import ToolError
        traversal_path = str(tmp_path / ".." / "etc")
        with pytest.raises(ToolError, match="Path validation"):
            await server._handle_hunt({"path": traversal_path})

    def test_validate_path_proc_rejected(self, tmp_path: Path) -> None:
        """Validate path rejects /proc paths."""
        with pytest.raises(PathValidationError, match="special filesystem"):
            validate_path("/proc/self/environ", [str(tmp_path)])

    def test_validate_path_within_allowed(self, tmp_path: Path) -> None:
        """Validate path accepts paths within the allowlist."""
        result = validate_path(str(tmp_path), [str(tmp_path)])
        assert result == str(tmp_path.resolve())

    def test_validate_path_empty_allowlist(self, tmp_path: Path) -> None:
        """Empty allowlist rejects all paths."""
        with pytest.raises(PathValidationError, match="No allowed paths"):
            validate_path(str(tmp_path), [])


class TestInputValidation:
    """Tests for input validation."""

    def test_validate_function_name_valid(self) -> None:
        """Valid function names pass validation."""
        from deep_code_security.mcp.input_validator import validate_function_name
        assert validate_function_name("os.system") == "os.system"
        assert validate_function_name("request.form") == "request.form"
        assert validate_function_name("cursor_execute") == "cursor_execute"

    def test_validate_function_name_rejects_semicolon(self) -> None:
        """Function names with semicolons are rejected."""
        from deep_code_security.mcp.input_validator import validate_function_name
        with pytest.raises(InputValidationError):
            validate_function_name("os.system; rm -rf /")

    def test_validate_function_name_rejects_backtick(self) -> None:
        """Function names with backticks are rejected."""
        from deep_code_security.mcp.input_validator import validate_function_name
        with pytest.raises(InputValidationError):
            validate_function_name("`id`")

    def test_validate_function_name_rejects_quotes(self) -> None:
        """Function names with quotes are rejected."""
        from deep_code_security.mcp.input_validator import validate_function_name
        with pytest.raises(InputValidationError):
            validate_function_name("os.system('id')")

    def test_validate_file_path_valid(self) -> None:
        """Valid file paths pass validation."""
        from deep_code_security.mcp.input_validator import validate_file_path
        assert validate_file_path("/tmp/test.py") == "/tmp/test.py"
        assert validate_file_path("/home/user/project/main.go") == "/home/user/project/main.go"

    def test_validate_file_path_rejects_null_byte(self) -> None:
        """File paths with null bytes are rejected."""
        from deep_code_security.mcp.input_validator import validate_file_path
        with pytest.raises(InputValidationError):
            validate_file_path("/tmp/test\x00.py")

    def test_validate_file_path_rejects_spaces(self) -> None:
        """File paths with spaces are rejected."""
        from deep_code_security.mcp.input_validator import validate_file_path
        with pytest.raises(InputValidationError):
            validate_file_path("/tmp/test file.py")

    def test_validate_raw_finding_valid(self, sample_raw_finding) -> None:
        """A valid finding passes validation."""
        result = validate_raw_finding(sample_raw_finding)
        assert result is sample_raw_finding

    def test_validate_raw_finding_rejects_malicious_function(self) -> None:
        """Finding with malicious function name is rejected."""
        from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath
        malicious = RawFinding(
            source=Source(
                file="/test.py", line=1, column=0,
                function="'; DROP TABLE users; --",  # SQL injection in field
                category="web_input", language="python"
            ),
            sink=Sink(
                file="/test.py", line=2, column=0,
                function="cursor.execute", category="sql_injection",
                cwe="CWE-89", language="python"
            ),
            taint_path=TaintPath(steps=[]),
            vulnerability_class="CWE-89: SQL Injection",
            severity="critical",
            language="python",
            raw_confidence=0.5,
        )
        with pytest.raises(InputValidationError):
            validate_raw_finding(malicious)


class TestSessionStore:
    """Tests for finding session store."""

    @pytest.mark.asyncio
    async def test_verify_rejects_unknown_finding_ids(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        """deep_scan_verify rejects finding IDs not from a previous hunt."""
        from deep_code_security.mcp.shared.server_base import ToolError
        with pytest.raises(ToolError, match="No findings found"):
            await server._handle_verify({
                "finding_ids": ["00000000-0000-0000-0000-000000000000"],
                "target_path": str(FIXTURES_DIR),
            })

    @pytest.mark.asyncio
    async def test_remediate_rejects_unknown_finding_ids(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        """deep_scan_remediate rejects finding IDs not from a previous verify."""
        from deep_code_security.mcp.shared.server_base import ToolError
        with pytest.raises(ToolError, match="No verified findings"):
            await server._handle_remediate({
                "finding_ids": ["00000000-0000-0000-0000-000000000000"],
                "target_path": str(FIXTURES_DIR),
            })


class TestStatusHandler:
    """Tests for deep_scan_status."""

    @pytest.mark.asyncio
    async def test_status_returns_expected_fields(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        """deep_scan_status returns all expected fields."""
        result = await server._handle_status({})
        content = json.loads(result["content"][0]["text"])
        assert "sandbox_available" in content
        assert "container_runtime" in content
        assert "registries_loaded" in content
        assert "languages_supported" in content
        assert "server_version" in content
        assert "allowed_paths" in content

    @pytest.mark.asyncio
    async def test_status_version_matches(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        """Status reports correct server version."""
        result = await server._handle_status({})
        content = json.loads(result["content"][0]["text"])
        assert content["server_version"] == "1.0.0"


class TestAuditLogging:
    """Tests for audit logging."""

    @pytest.mark.asyncio
    async def test_hunt_produces_audit_log(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """Hunt tool invocation is logged in audit logger."""
        import logging
        audit_records = []

        class TestHandler(logging.Handler):
            def emit(self, record):
                audit_records.append(record)

        handler = TestHandler()
        audit_log = logging.getLogger("deep_code_security.audit")
        original_level = audit_log.level
        audit_log.setLevel(logging.INFO)
        audit_log.addHandler(handler)

        try:
            # Run hunt on tmp_path (empty dir, may find 0 findings)
            await server._handle_hunt({"path": str(tmp_path)})
            # Audit log should have at least one record
            assert len(audit_records) >= 1
            assert any("deep_scan_hunt" in str(r.getMessage()) for r in audit_records)
        finally:
            audit_log.removeHandler(handler)
            audit_log.setLevel(original_level)


class TestVerifyHandler:
    """Tests for deep_scan_verify error paths."""

    @pytest.mark.asyncio
    async def test_verify_empty_finding_ids_raises(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        from deep_code_security.mcp.shared.server_base import ToolError
        with pytest.raises(ToolError, match="finding_ids is required"):
            await server._handle_verify({
                "finding_ids": [],
                "target_path": str(tmp_path),
            })

    @pytest.mark.asyncio
    async def test_verify_invalid_path_raises(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        from deep_code_security.mcp.shared.server_base import ToolError
        with pytest.raises(ToolError, match="Path validation"):
            await server._handle_verify({
                "finding_ids": ["some-id"],
                "target_path": "/proc/self",
            })

    @pytest.mark.asyncio
    async def test_verify_unknown_ids_raises_tool_error(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        from deep_code_security.mcp.shared.server_base import ToolError
        with pytest.raises(ToolError, match="No findings found"):
            await server._handle_verify({
                "finding_ids": ["deadbeef-dead-dead-dead-deaddeadbeef"],
                "target_path": str(tmp_path),
            })


class TestRemediateHandler:
    """Tests for deep_scan_remediate error paths."""

    @pytest.mark.asyncio
    async def test_remediate_empty_finding_ids_raises(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        from deep_code_security.mcp.shared.server_base import ToolError
        with pytest.raises(ToolError, match="finding_ids is required"):
            await server._handle_remediate({
                "finding_ids": [],
                "target_path": str(tmp_path),
            })

    @pytest.mark.asyncio
    async def test_remediate_invalid_path_raises(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        from deep_code_security.mcp.shared.server_base import ToolError
        with pytest.raises(ToolError, match="Path validation"):
            await server._handle_remediate({
                "finding_ids": ["some-id"],
                "target_path": "/dev/null",
            })


class TestFullHandler:
    """Tests for deep_scan_full handler."""

    @pytest.mark.asyncio
    async def test_full_invalid_path_raises(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        from deep_code_security.mcp.shared.server_base import ToolError
        with pytest.raises(ToolError, match="Path validation"):
            await server._handle_full({"path": "/sys/kernel"})

    @pytest.mark.asyncio
    async def test_full_empty_dir_returns_structure(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        result = await server._handle_full({
            "path": str(tmp_path),
            "skip_verification": True,
        })
        content = json.loads(result["content"][0]["text"])
        assert "findings" in content
        assert "verified" in content
        assert "guidance" in content
        assert "hunt_stats" in content
