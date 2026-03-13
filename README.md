# deep-code-security

Multi-language Static Application Security Testing (SAST) tool with agentic verification. Uses tree-sitter for deterministic AST parsing, sandbox-verified exploit PoCs, and structured remediation guidance. Exposes all functionality via an MCP server for Claude Code integration.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Run via CLI
dcs hunt /path/to/project
dcs verify --finding-ids <id1> <id2>
dcs remediate --finding-ids <id1> --target-path /path/to/project

# Run via MCP server
python -m deep_code_security.mcp
```

## Architecture

```
Target Codebase
    |
    v
HUNTER     tree-sitter parse → source/sink match → taint track
    |      Output: RawFinding[] (JSON, paginated)
    v
AUDITOR    PoC generation → sandbox execution → confidence scoring
    |      Output: VerifiedFinding[] (JSON)  [Exploit = 10% bonus only]
    v
ARCHITECT  context gather → guidance generation → dependency analysis
           Output: RemediationGuidance[] (JSON)
```

### Supported Languages (v1)

- Python (Flask, Django patterns)
- Go (net/http, database/sql patterns)
- C (stretch goal — basic argv/stdin patterns)

## Installation

```bash
# Clone
git clone https://github.com/your-org/deep-code-security.git
cd deep-code-security

# Install with dev dependencies
pip install -e ".[dev]"

# Build sandbox images (requires Docker or Podman)
make build-sandboxes
```

## MCP Configuration

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "deep-code-security": {
      "command": "python",
      "args": ["-m", "deep_code_security.mcp"],
      "cwd": "/path/to/deep-code-security",
      "env": {
        "DCS_REGISTRY_PATH": "/path/to/deep-code-security/registries",
        "DCS_ALLOWED_PATHS": "/path/to/projects",
        "DCS_CONTAINER_RUNTIME": "auto"
      }
    }
  }
}
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `deep_scan_hunt` | Run Hunter phase (AST parse + taint track) |
| `deep_scan_verify` | Run Auditor phase (sandbox exploit verification) |
| `deep_scan_remediate` | Run Architect phase (remediation guidance) |
| `deep_scan_full` | Run all three phases sequentially |
| `deep_scan_status` | Check sandbox health and registry info |

## Confidence Scoring

The confidence score (0-100) uses a weighted composite:

| Factor | Weight | Notes |
|--------|--------|-------|
| Taint path completeness | 45% | Full path = 100, partial = 50, heuristic = 20 |
| Sanitizer absence | 25% | No sanitizer = 100, full sanitizer = 0 |
| CWE severity baseline | 20% | Critical = 100, High = 75, Medium = 50, Low = 25 |
| Exploit verification | 10% | **Bonus only** — failed PoC does not penalize |

Thresholds: `>=75` confirmed, `>=45` likely, `>=20` unconfirmed, `<20` false positive

## Sandbox Security Policy

Sandbox containers enforce:
- `--network=none` — no network access
- `--read-only` — read-only root filesystem
- `--tmpfs /tmp:rw,noexec,nosuid,size=64m` — writable temp with noexec
- `--cap-drop=ALL` — no Linux capabilities
- `--security-opt=no-new-privileges` — no privilege escalation
- `--security-opt seccomp=seccomp-default.json` — custom seccomp profile
- `--pids-limit=64` — no fork bombs
- `--memory=512m` — memory ceiling
- `--user=65534:65534` — run as nobody

## Development

```bash
make lint           # Lint with ruff
make test           # All tests (90%+ coverage required)
make test-hunter    # Hunter tests only
make test-auditor   # Auditor tests only
make test-architect # Architect tests only
make test-mcp       # MCP server tests only
make sast           # Security scan with bandit
make security       # sast + pip-audit
```

## Registry Format

See `registries/README.md` for the YAML registry format documentation.

## Known Limitations (v1)

1. **Intraprocedural taint only** — source and sink must be in the same function body. Expected detection rate: **10-25%** of real-world injection vulnerabilities. Most web app vulnerabilities span multiple function call boundaries and will NOT be detected by v1.

2. **Query brittleness** — tree-sitter queries match specific AST shapes. The following patterns are NOT matched in v1:
   - Aliased imports: `req = request; req.form`
   - Fully-qualified names: `flask.request.form`
   - Class attributes: `self.request.form`
   - Chained calls: `request.form.get("key")` (partial match only)

3. **PoC verification is bonus-only** — most template-based PoCs fail due to missing execution context (framework setup, dependency injection, state initialization). A failed PoC does NOT mean the vulnerability is false. The exploit bonus is capped at 10 points.

4. **No cross-language taint** — Python calling C via FFI is not analyzed. Each language is analyzed independently.

5. **No interprocedural analysis** — call graphs across functions/files are not traced in v1. Deferred to v1.1.

## Security Model

The MCP server runs as a **native stdio process** on the host. It does NOT run inside a Docker container, avoiding the Docker socket mount attack vector. Docker/Podman is only used for sandbox containers that execute exploit PoCs.

All file access goes through `DCS_ALLOWED_PATHS` allowlist validation with symlink resolution. All RawFinding fields are validated before exploit template interpolation. Finding provenance is verified via server-side session store (external callers cannot inject arbitrary findings).

## v1.1 Roadmap

- Interprocedural taint tracking (call graph construction)
- Java and Rust language support
- Additional registry patterns (aliased imports, fully-qualified names)
- gVisor/Firecracker sandbox option for higher-risk deployments
