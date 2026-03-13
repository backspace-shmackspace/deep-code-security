# deep-code-security — Claude Code Project Guide

## Project Overview

Multi-language SAST tool with agentic verification. Three-phase pipeline:
1. **Hunter** — AST parsing via tree-sitter, taint tracking, source/sink discovery
2. **Auditor** — Sandbox exploit verification, confidence scoring (bonus-only)
3. **Architect** — Remediation guidance generation (NOT apply-ready patches)

Exposed via MCP server (native stdio, not containerized).

## Architecture

```
src/deep_code_security/
├── shared/          # File discovery, language detection, config, JSON output
├── hunter/          # Phase 1: tree-sitter parse → taint track → RawFinding[]
├── auditor/         # Phase 2: exploit generation → sandbox exec → VerifiedFinding[]
├── architect/       # Phase 3: context gather → guidance → RemediationGuidance[]
├── mcp/             # MCP server (BaseMCPServer, 5 tools, stdio transport)
│   └── shared/      # Vendored from helper-mcps (BaseMCPServer base class)
registries/          # YAML source/sink definitions per language
sandbox/             # Docker images for exploit execution
tests/               # pytest suite (90%+ coverage required)
```

## Critical Rules

### Security (Non-Negotiable)
- **Never `yaml.load()`** — always `yaml.safe_load()`
- **Never `eval()`, `exec()`, `os.system()`, `subprocess.run(shell=True)`** in production code
- **All subprocess calls use list-form arguments** (never shell=True)
- **All file paths validated through `mcp/path_validator.py`** with DCS_ALLOWED_PATHS allowlist
- **All container operations enforce full security policy**: seccomp + no-new-privileges + cap-drop=ALL
- **Jinja2 SandboxedEnvironment** for PoC template rendering (never raw string formatting)
- **`mcp/input_validator.py`** validates all RawFinding fields before template interpolation

### Code Quality
- **Pydantic v2** for all data-crossing models
- **Type hints on all public functions**
- **`__all__` in `__init__.py` files**
- **pathlib.Path** over os.path
- **No mutable default arguments**

### Testing
- Run tests: `make test` (90%+ coverage required)
- Per-component: `make test-hunter`, `make test-auditor`, `make test-architect`, `make test-mcp`
- Integration: `make test-integration` (requires Docker/Podman)
- Lint: `make lint`
- Security scan: `make sast`

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Taint scope | Intraprocedural only (v1) | ~10-25% real-world detection; proves architecture |
| Exploit weight | 10% bonus-only | Failed PoCs ≠ false finding; most fail due to missing context |
| Sandbox transport | subprocess CLI | No Docker socket mount (avoids root-equivalent host access) |
| MCP deployment | Native stdio | Containerized MCP + Docker socket = root-equivalent |
| Architect output | Guidance only | Apply-ready patches are frequently wrong; guidance avoids trust erosion |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DCS_ALLOWED_PATHS` | cwd | Comma-separated allowlist for filesystem access |
| `DCS_REGISTRY_PATH` | `./registries` | Path to YAML registry files |
| `DCS_SANDBOX_TIMEOUT` | `30` | Per-exploit timeout in seconds |
| `DCS_CONTAINER_RUNTIME` | `auto` | `podman`, `docker`, or `auto` |
| `DCS_MAX_FILES` | `10000` | Max files per scan |
| `DCS_MAX_RESULTS` | `100` | Max findings returned per hunt operation |
| `DCS_MAX_VERIFICATIONS` | `50` | Max findings to verify in auditor phase |
| `DCS_MAX_CONCURRENT_SANDBOXES` | `2` | Concurrency limit for sandbox execution |
| `DCS_QUERY_TIMEOUT` | `5.0` | Tree-sitter query timeout in seconds |
| `DCS_QUERY_MAX_RESULTS` | `1000` | Max results per tree-sitter query |

## Known Limitations (v1)

1. **Intraprocedural taint only** — source and sink must be in the same function. Expected detection rate: 10-25% of real-world injection vulnerabilities.
2. **Query brittleness** — aliased imports (`req = request; req.form`), fully-qualified names (`flask.request.form`), and class attributes (`self.request.form`) are NOT matched.
3. **PoC verification is bonus-only** — most template PoCs fail due to missing execution context. This is expected.
4. **No cross-language taint** — Python calling C via FFI is not analyzed.

## File Conventions

- `models.py` per phase — all Pydantic models
- `orchestrator.py` per phase — entry point coordinating subcomponents
- Registries in `registries/` YAML files, never hardcoded in Python
- Test fixtures in `tests/fixtures/vulnerable_samples/` and `tests/fixtures/safe_samples/`
