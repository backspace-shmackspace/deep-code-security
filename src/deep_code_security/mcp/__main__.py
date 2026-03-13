"""MCP server entry point — python -m deep_code_security.mcp

Lifecycle: INITIALIZING -> SERVICE_VALIDATED -> STDIO_VALIDATED -> READY -> SHUTTING_DOWN -> STOPPED
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

from deep_code_security.mcp.server import DeepCodeSecurityMCPServer
from deep_code_security.shared.config import get_config

# Configure logging to stderr (stdout is reserved for MCP protocol)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    stream=sys.stderr,
)

logger = logging.getLogger(__name__)


async def main() -> None:
    """Run the MCP server."""
    config = get_config()

    logger.info(
        "deep-code-security MCP server starting (allowed_paths=%s)",
        config.allowed_paths_str,
    )

    server = DeepCodeSecurityMCPServer(config=config)

    # Set up signal handlers for graceful shutdown
    loop = asyncio.get_event_loop()

    def shutdown_handler(signum, frame):
        logger.info("Received signal %d, initiating shutdown...", signum)
        for task in asyncio.all_tasks(loop):
            task.cancel()

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    try:
        await server.run_stdio()
    except asyncio.CancelledError:
        logger.info("Server cancelled, shutting down...")
    except Exception as e:
        logger.exception("Fatal server error: %s", e)
        sys.exit(1)

    logger.info("deep-code-security MCP server stopped")


if __name__ == "__main__":
    asyncio.run(main())
