"""Minimal BaseMCPServer stub vendored from helper-mcps.

This provides the base class for MCP server implementations.
The full version with credential provider, lifecycle state machine,
and structured logging lives at ~/projects/workspaces/helper-mcps/.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from collections.abc import Callable
from enum import Enum
from typing import Any

__all__ = ["BaseMCPServer", "LifecycleState", "ToolError"]

logger = logging.getLogger(__name__)


class LifecycleState(str, Enum):
    """MCP server lifecycle states."""

    INITIALIZING = "INITIALIZING"
    SERVICE_VALIDATED = "SERVICE_VALIDATED"
    STDIO_VALIDATED = "STDIO_VALIDATED"
    READY = "READY"
    SHUTTING_DOWN = "SHUTTING_DOWN"
    STOPPED = "STOPPED"


class ToolError(Exception):
    """Error returned from a tool handler."""

    def __init__(self, message: str, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.message = message


class BaseMCPServer:
    """Base class for MCP servers using the stdio transport.

    Subclasses register tools and implement handlers.
    The server reads JSON-RPC messages from stdin and writes responses to stdout.
    All logging goes to stderr.
    """

    SERVER_NAME: str = "base-mcp-server"
    SERVER_VERSION: str = "1.0.0"

    def __init__(self) -> None:
        self._state = LifecycleState.INITIALIZING
        self._tools: dict[str, dict[str, Any]] = {}
        self._handlers: dict[str, Callable] = {}
        self._request_id = 0

    @property
    def state(self) -> LifecycleState:
        """Current lifecycle state."""
        return self._state

    def _transition(self, new_state: LifecycleState) -> None:
        """Transition to a new lifecycle state."""
        logger.debug("State: %s -> %s", self._state.value, new_state.value)
        self._state = new_state

    def register_tool(
        self,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        handler: Callable,
    ) -> None:
        """Register a tool with the MCP server.

        Args:
            name: Tool name (used in JSON-RPC calls).
            description: Human-readable description.
            input_schema: JSON Schema for tool inputs.
            handler: Async callable that handles tool invocations.
        """
        self._tools[name] = {
            "name": name,
            "description": description,
            "inputSchema": input_schema,
        }
        self._handlers[name] = handler
        logger.debug("Registered tool: %s", name)

    async def initialize(self) -> None:
        """Initialize the server. Override in subclasses."""
        pass

    async def validate_services(self) -> None:
        """Validate external services. Override in subclasses."""
        pass

    async def _handle_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle a JSON-RPC request.

        Args:
            request: Parsed JSON-RPC request.

        Returns:
            JSON-RPC response dict.
        """
        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params", {})

        try:
            if method == "initialize":
                result = await self._handle_initialize(params)
            elif method == "tools/list":
                result = await self._handle_tools_list(params)
            elif method == "tools/call":
                result = await self._handle_tools_call(params)
            elif method == "ping":
                result = {}
            else:
                return self._error_response(req_id, -32601, f"Method not found: {method}")

            return {"jsonrpc": "2.0", "id": req_id, "result": result}

        except ToolError as e:
            return self._error_response(req_id, -32000, str(e), {"retryable": e.retryable})
        except Exception as e:
            logger.exception("Error handling method %s", method)
            return self._error_response(req_id, -32000, str(e))

    async def _handle_initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle MCP initialize request."""
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {
                "name": self.SERVER_NAME,
                "version": self.SERVER_VERSION,
            },
        }

    async def _handle_tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle tools/list request."""
        return {"tools": list(self._tools.values())}

    async def _handle_tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle tools/call request."""
        tool_name = params.get("name")
        tool_input = params.get("arguments", {})

        if tool_name not in self._handlers:
            raise ToolError(f"Unknown tool: {tool_name}")

        handler = self._handlers[tool_name]
        result = await handler(tool_input)
        return result

    def _error_response(
        self,
        req_id: Any,
        code: int,
        message: str,
        data: dict | None = None,
    ) -> dict[str, Any]:
        """Build a JSON-RPC error response."""
        error: dict[str, Any] = {"code": code, "message": message}
        if data:
            error["data"] = data
        return {"jsonrpc": "2.0", "id": req_id, "error": error}

    async def run_stdio(self) -> None:
        """Run the MCP server on stdio.

        Reads JSON-RPC messages from stdin (one per line) and
        writes responses to stdout.
        """
        self._transition(LifecycleState.STDIO_VALIDATED)

        try:
            await self.initialize()
            await self.validate_services()
        except Exception:
            logger.exception("Server initialization failed")
            sys.exit(1)

        self._transition(LifecycleState.READY)
        logger.info(
            "%s %s ready (stdio transport)", self.SERVER_NAME, self.SERVER_VERSION
        )

        # Use asyncio streams for stdin/stdout
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        stdout_transport, stdout_protocol = await loop.connect_write_pipe(
            asyncio.BaseProtocol, sys.stdout
        )

        async def write_response(response: dict) -> None:
            data = json.dumps(response, ensure_ascii=False) + "\n"
            stdout_transport.write(data.encode("utf-8"))

        try:
            while True:
                try:
                    line = await reader.readline()
                    if not line:
                        break
                    line_str = line.decode("utf-8", errors="replace").strip()
                    if not line_str:
                        continue
                    request = json.loads(line_str)
                except json.JSONDecodeError as e:
                    logger.warning("Invalid JSON input: %s", e)
                    continue
                except Exception as e:
                    logger.error("Read error: %s", e)
                    break

                response = await self._handle_request(request)
                await write_response(response)

        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Fatal error in stdio loop")
        finally:
            self._transition(LifecycleState.SHUTTING_DOWN)
            stdout_transport.close()
            self._transition(LifecycleState.STOPPED)
            logger.info("%s stopped", self.SERVER_NAME)
