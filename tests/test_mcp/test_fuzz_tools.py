"""Tests for MCP fuzz tools."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from deep_code_security.fuzzer.execution.sandbox import ContainerBackend
from deep_code_security.mcp.server import DeepCodeSecurityMCPServer
from deep_code_security.shared.config import Config


class TestFuzzStatus:
    @pytest.fixture
    def server(self) -> DeepCodeSecurityMCPServer:
        config = Config()
        return DeepCodeSecurityMCPServer(config=config)

    @pytest.mark.asyncio
    async def test_deep_scan_fuzz_status(self, server: DeepCodeSecurityMCPServer) -> None:
        await server.initialize()
        # Patch is_available for deterministic test regardless of Podman state
        with patch.object(ContainerBackend, "is_available", return_value=False):
            result = await server._handle_fuzz_status({})
        text = result["content"][0]["text"]
        data = json.loads(text)

        assert "anthropic_available" in data
        assert isinstance(data["anthropic_available"], bool)
        assert "vertex_configured" in data
        assert "consent_stored" in data
        assert "available_plugins" in data
        assert data["container_backend_available"] is False

    @pytest.mark.asyncio
    async def test_fuzz_status_with_run_id(self, server: DeepCodeSecurityMCPServer) -> None:
        await server.initialize()
        result = await server._handle_fuzz_status({"fuzz_run_id": "nonexistent"})
        text = result["content"][0]["text"]
        data = json.loads(text)

        assert data["fuzz_run"] is not None
        assert data["fuzz_run"]["status"] == "not_found"


class TestFuzzDeferred:
    @pytest.fixture
    def server(self) -> DeepCodeSecurityMCPServer:
        """Server where ContainerBackend is unavailable (ensures fuzz tool not registered)."""
        with patch.object(ContainerBackend, "is_available", return_value=False):
            config = Config()
            s = DeepCodeSecurityMCPServer(config=config)
            s._register_tools()
            return s

    @pytest.mark.asyncio
    async def test_deep_scan_fuzz_not_registered(self, server: DeepCodeSecurityMCPServer) -> None:
        """deep_scan_fuzz tool should NOT be registered when container backend unavailable."""
        tool_names = list(server._tools.keys())
        assert "deep_scan_fuzz" not in tool_names

    @pytest.mark.asyncio
    async def test_deep_scan_fuzz_status_is_registered(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        """deep_scan_fuzz_status tool should always be registered."""
        tool_names = list(server._tools.keys())
        assert "deep_scan_fuzz_status" in tool_names

    @pytest.mark.asyncio
    async def test_handle_fuzz_raises_without_consent(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        """_handle_fuzz raises ToolError when consent is not provided."""
        from deep_code_security.mcp.shared.server_base import ToolError

        with pytest.raises(ToolError, match="consent"):
            await server._handle_fuzz({})
