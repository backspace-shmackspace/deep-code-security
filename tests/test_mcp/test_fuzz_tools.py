"""Tests for MCP fuzz tools."""

from __future__ import annotations

import json

import pytest

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
        config = Config()
        return DeepCodeSecurityMCPServer(config=config)

    @pytest.mark.asyncio
    async def test_deep_scan_fuzz_not_registered(self, server: DeepCodeSecurityMCPServer) -> None:
        """deep_scan_fuzz tool should NOT be registered."""
        await server.initialize()
        tool_names = list(server._tools.keys())
        assert "deep_scan_fuzz" not in tool_names

    @pytest.mark.asyncio
    async def test_deep_scan_fuzz_status_is_registered(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        """deep_scan_fuzz_status tool should be registered."""
        await server.initialize()
        tool_names = list(server._tools.keys())
        assert "deep_scan_fuzz_status" in tool_names

    @pytest.mark.asyncio
    async def test_handle_fuzz_raises(self, server: DeepCodeSecurityMCPServer) -> None:
        """_handle_fuzz stub should raise ToolError."""
        from deep_code_security.mcp.shared.server_base import ToolError

        await server.initialize()
        with pytest.raises(ToolError, match="container-based sandboxing"):
            await server._handle_fuzz({})
