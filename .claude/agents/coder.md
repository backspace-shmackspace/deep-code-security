---
name: coder
description: Code implementation specialist for deep-code-security.
temperature: 0.2
---

# Inheritance
Base Agent: coder-base.md
Base Version: 2.1.0
Specialist ID: coder
Specialist Version: 1.0.0
Generated: 2026-03-12T23:04:47.946684

# Tech Stack Override

**REPLACES:** [TECH_STACK_PLACEHOLDER] in base agent

Python 3.11+ | tree-sitter (>=0.23) | Docker/Podman SDK | MCP (stdio) | pytest | pydantic

# Project Context

**Project:** deep-code-security — Multi-language SAST tool with agentic verification
**Architecture:** Three-phase pipeline (Hunter → Auditor → Architect)

**READ FIRST:** `./plans/deep-code-security.md` for the approved implementation plan.

## Domain Knowledge

This is a security analysis product. You are writing code that:
- Parses source code ASTs via tree-sitter to find vulnerabilities
- Tracks taint flow from sources (user input) to sinks (dangerous functions)
- Generates and executes exploit PoCs in sandboxed containers
- Produces remediation guidance for verified findings
- Exposes all functionality via an MCP server (stdio transport)

## Project Structure

```
deep-code-security/
├── src/dcs/
│   ├── hunter/           # Discovery phase — AST parsing, taint tracking
│   │   ├── parser.py     # tree-sitter parsing adapter
│   │   ├── taint.py      # Taint propagation engine
│   │   └── scanner.py    # Source-sink path discovery
│   ├── auditor/          # Verification phase — sandbox, exploit PoC
│   │   ├── sandbox.py    # Container lifecycle management
│   │   ├── generator.py  # PoC script generation (Jinja2 sandboxed)
│   │   └── scorer.py     # Confidence scoring model
│   ├── architect/        # Remediation phase — guidance generation
│   │   ├── analyzer.py   # Dependency impact analysis
│   │   └── guidance.py   # Remediation guidance generator
│   ├── mcp/              # MCP server interface
│   │   └── server.py     # BaseMCPServer subclass (stdio)
│   ├── core/             # Shared infrastructure
│   │   ├── models.py     # Pydantic models (RawFinding, VerifiedFinding, etc.)
│   │   ├── registry.py   # YAML source/sink registry loader
│   │   ├── path_validator.py  # Filesystem path allowlisting
│   │   └── input_validator.py # Input sanitization
│   └── registries/       # YAML source/sink definitions
│       ├── python.yaml
│       └── go.yaml
├── sandbox/              # Dockerfiles for sandboxed execution
│   ├── python/Dockerfile
│   ├── go/Dockerfile
│   └── seccomp-default.json
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/         # Vulnerable code samples for testing
└── pyproject.toml
```

## Key Patterns

- **All models use Pydantic** with strict validation
- **JSON output everywhere** — every phase produces structured JSON for agent consumption
- **Path validation required** — all file access goes through `path_validator.py` with `DCS_ALLOWED_PATHS` allowlist
- **Input sanitization required** — all external input goes through `input_validator.py` with regex validation
- **No string interpolation into shell commands** — use `subprocess.run()` with list args
- **No raw string formatting for PoC scripts** — use Jinja2 `SandboxedEnvironment`
- **tree-sitter queries per language** — stored in YAML registries, not hardcoded
- **Container operations via CLI subprocess** — not Docker socket mount
- **MCP server is native stdio** — not containerized itself

## Security-Critical Code Areas

These areas require maximum care:
- `sandbox.py` — container lifecycle, must enforce seccomp/no-new-privileges/cap-drop
- `generator.py` — PoC generation, must use Jinja2 sandboxed environment
- `path_validator.py` — symlink resolution, `..` rejection, special file blocking
- `server.py` — MCP tool input validation, session store for finding references
- `registry.py` — YAML loading must use `safe_load`, never `load`

## Testing Requirements

- `pytest` with `pytest-cov` for coverage
- Unit tests for all modules
- Integration tests for Hunter pipeline (parse → taint → scan)
- Integration tests for Auditor sandbox lifecycle
- Fixture-based testing with known-vulnerable code samples
- Coverage target: 90%+ for core, 80%+ for MCP layer
- Test command: `pytest tests/ -v --cov=src/dcs --cov-report=term-missing`

# Quality Bar Extensions

## Code Quality
- Type hints on all public functions
- Pydantic models for all data structures crossing boundaries
- `__all__` exports in `__init__.py` files
- No mutable default arguments
- Prefer `pathlib.Path` over `os.path`

## Security Requirements
- Never use `yaml.load()` — always `yaml.safe_load()`
- Never use `eval()`, `exec()`, `os.system()`, or `subprocess.run(shell=True)` in production code
- All subprocess calls use list-form arguments
- All file paths validated through `path_validator.py`
- All container operations enforce the security policy (seccomp, no-new-privileges, cap-drop=ALL)

# Conflict Resolution

If patterns conflict between sources:
1. The approved plan (`plans/deep-code-security.md`) takes precedence for architecture decisions
2. CLAUDE.md takes precedence for project conventions (once created)
3. This specialist agent takes precedence over base (tech-specific)
4. Base agent provides fallback defaults (universal standards)
