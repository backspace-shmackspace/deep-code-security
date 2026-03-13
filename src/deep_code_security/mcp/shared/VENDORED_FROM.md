# Vendored From: helper-mcps

This directory contains a minimal stub of the shared MCP server base library
from the helper-mcps monorepo.

## Source

- Repository: `~/projects/workspaces/helper-mcps/`
- Original path: `shared/server_base.py`, `shared/lifecycle.py`, `shared/types.py`
- Commit hash: (populate after vendoring from upstream)

## What Was Vendored

- `server_base.py` — `BaseMCPServer` base class with stdio transport and lifecycle states
  - This is a **minimal stub** that implements the core interface but omits:
    - `CredentialProvider` integration
    - Structured logging configuration (`configure_logging()`)
    - Full lifecycle state machine validation
    - Tool rate limiting
    - Audit log rotation
  - These features should be added when vendoring from the full helper-mcps

## How to Update

1. Check out the latest helper-mcps:
   ```
   cd ~/projects/workspaces/helper-mcps
   git log --oneline -5
   ```
2. Copy updated shared files to this directory
3. Update the commit hash above
4. Run: `make check-vendor`

## Deviation from Upstream

The upstream BaseMCPServer uses the `mcp` SDK's high-level server API.
This stub implements a minimal JSON-RPC loop for compatibility.
When the full helper-mcps shared library is vendored, update to use
the SDK's `Server` class and `stdio_server()` context manager.

## check-vendor Target

The `Makefile`'s `check-vendor` target verifies this file exists.
For full upstream comparison, implement a hash comparison against the
upstream HEAD commit of `~/projects/workspaces/helper-mcps/shared/`.
