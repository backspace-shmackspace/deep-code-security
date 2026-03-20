# deep-code-security

Multi-language SAST tool with agentic verification and AI-powered fuzzing. Two analysis modes:
1. **Static Analysis (SAST)** - Uses Semgrep with tree-sitter fallback for deterministic AST parsing, sandbox-verified exploit PoCs, and structured remediation guidance
2. **Dynamic Analysis (Fuzzing)** - AI-powered fuzzer with coverage-guided feedback, crash deduplication, and corpus management

Exposes all functionality via an MCP server for Claude Code integration.

## Quick Start

```bash
# Install (basic)
pip install -e ".[dev]"

# Install with fuzzing support
pip install -e ".[dev,fuzz]"

# Static analysis via CLI
dcs hunt /path/to/project
dcs hunt /path/to/project --ignore-suppressions
dcs verify --finding-ids <id1> <id2>

# Dynamic analysis (fuzzing) via CLI
dcs fuzz /path/to/target.py
dcs replay /path/to/corpus
dcs corpus /path/to/corpus
dcs fuzz-plugins
dcs report /path/to/output

# Integrated SAST-to-Fuzz pipeline
dcs hunt-fuzz /path/to/project

# Run via MCP server
python -m deep_code_security.mcp
```

## Architecture

### Static Analysis (SAST)

```
Target Codebase
    |
    v
HUNTER     scanner backend (Semgrep/tree-sitter) → source/sink match → taint track
    |      Output: RawFinding[] (JSON, paginated)
    v
AUDITOR    PoC generation → sandbox execution → confidence scoring
    |      Output: VerifiedFinding[] (JSON)  [Exploit = 10% bonus only]
    v
ARCHITECT  context gather → guidance generation → dependency analysis
           Output: RemediationGuidance[] (JSON)
```

### Dynamic Analysis (Fuzzing)

```
Target Function
    |
    v
FUZZER     LLM-guided input generation → sandboxed execution →
           crash detection → corpus management → coverage tracking
           Output: CrashReport[] (JSON, with reproducer inputs)
```

## Supported Languages (v1)

- Python (Flask, Django patterns; SAST + fuzzing)
- Go (net/http, database/sql patterns; SAST only)
- C (command injection, buffer overflow, format string, memory corruption
  patterns; SAST + fuzzing). C fuzzing requires
  `DCS_FUZZ_ALLOWED_PLUGINS=python,c` and AI-powered harness generation with
  AddressSanitizer and gcov instrumentation.

### Suppression Files

You can suppress specific findings by creating a `.dcs-suppress.yaml` file
in your project root. This is useful for marking false positives, accepted
risks, or findings that will be addressed later.

**Basic usage:**

```yaml
# .dcs-suppress.yaml
version: 1
suppressions:
  - rule: CWE-22
    file: "src/config/*.py"
    reason: "Config paths are admin-controlled"

  - rule: CWE-89
    file: "src/legacy/db.py"
    line: 145
    reason: "Legacy code scheduled for refactor in Q2"
```

**CLI flags:**
- By default, suppressions are applied during `dcs hunt`, `dcs full-scan`,
  and `dcs hunt-fuzz` commands
- Use `--ignore-suppressions` to bypass the suppression file and show all
  findings

**Notes:**
- Suppression files only affect SAST findings, not fuzzer crashes
- The file must be named `.dcs-suppress.yaml` and located in the project
  root
- All formatters (text, JSON, SARIF, HTML) show suppression statistics in
  their output

## Installation

```bash
# Clone
git clone https://github.com/your-org/deep-code-security.git
cd deep-code-security

# Install with dev dependencies
pip install -e ".[dev]"

# Install with fuzzing support (requires anthropic SDK)
pip install -e ".[dev,fuzz]"

# Build sandbox images (requires Docker or Podman)
make build-sandboxes        # Build auditor/architect sandbox images
make build-fuzz-sandbox     # Build Python fuzzer sandbox image (Podman only)
make build-fuzz-c-sandbox   # Build C fuzzer sandbox image (Podman only)
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
        "DCS_CONTAINER_RUNTIME": "auto",
        "ANTHROPIC_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### Optional Environment Variables

For advanced tuning, additional variables are available:

**Static Analysis**:

| Variable | Default | Description |
|----------|---------|-------------|
| `DCS_SCANNER_BACKEND` | `auto` | Scanner backend: `semgrep`, `treesitter`, or `auto` (prefer semgrep if available) |
| `DCS_SEMGREP_TIMEOUT` | `120` | Maximum seconds for Semgrep subprocess |
| `DCS_SEMGREP_RULES_PATH` | `<registry>/semgrep` | Path to DCS Semgrep rule files |
| `DCS_MAX_RESULTS` | `100` | Max findings returned per hunt operation |
| `DCS_MAX_VERIFICATIONS` | `50` | Max findings to verify in auditor phase |
| `DCS_SANDBOX_TIMEOUT` | `30` | Per-exploit timeout in seconds |
| `DCS_MAX_FILES` | `10000` | Max files per scan |
| `DCS_MAX_CONCURRENT_SANDBOXES` | `2` | Concurrency limit for sandbox execution |
| `DCS_QUERY_TIMEOUT` | `5.0` | Tree-sitter query timeout in seconds |
| `DCS_QUERY_MAX_RESULTS` | `1000` | Max results per tree-sitter query |
| `DCS_BRIDGE_MAX_TARGETS` | `10` | Max fuzz targets produced by SAST-to-Fuzz bridge |

**Dynamic Analysis (Fuzzing)**:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | (none) | API key for Claude (required for fuzzing) |
| `GOOGLE_CLOUD_PROJECT` | (none) | GCP project ID for Vertex AI (optional) |
| `CLOUD_ML_PROJECT_NUMBER` | (none) | GCP project number for Vertex AI (optional) |
| `ANTHROPIC_VERTEX_PROJECT_ID` | (none) | Vertex AI project override (optional) |
| `DCS_FUZZ_MODEL` | `claude-sonnet-4-6` | Claude model for input generation |
| `DCS_FUZZ_MAX_ITERATIONS` | `10` | Max fuzzing iterations |
| `DCS_FUZZ_INPUTS_PER_ITER` | `10` | Inputs generated per iteration |
| `DCS_FUZZ_TIMEOUT_MS` | `5000` | Per-input execution timeout |
| `DCS_FUZZ_MAX_COST_USD` | `5.0` | API cost budget |
| `DCS_FUZZ_OUTPUT_DIR` | `./fuzzy-output` | Corpus and report output directory |
| `DCS_FUZZ_CONSENT` | `false` | Pre-configured consent for CI |
| `DCS_FUZZ_GCP_REGION` | `us-east5` | GCP region for Vertex AI |
| `DCS_FUZZ_ALLOWED_PLUGINS` | `python` | Comma-separated allowlist of fuzzer plugins (default: python; set to python,c to enable both) |
| `DCS_FUZZ_MCP_TIMEOUT` | `120` | Hard wall-clock timeout for MCP fuzz invocations |
| `DCS_FUZZ_CONTAINER_IMAGE` | `dcs-fuzz-python:latest` | Podman image used by ContainerBackend for MCP fuzz runs |
| `DCS_FUZZ_C_CONTAINER_IMAGE` | `dcs-fuzz-c:latest` | Podman image used by CContainerBackend |
| `DCS_FUZZ_C_COMPILE_FLAGS` | `""` | Comma-separated gcc flags (e.g., `-O2,-march=native`) |
| `DCS_FUZZ_C_INCLUDE_PATHS` | `""` | Comma-separated include paths for C harness compilation |

## MCP Tools

| Tool | Description |
|------|-------------|
| `deep_scan_hunt` | Run Hunter phase (AST parse + taint track) |
| `deep_scan_verify` | Run Auditor phase (sandbox exploit verification) |
| `deep_scan_remediate` | Run Architect phase (remediation guidance) |
| `deep_scan_full` | Run all three phases sequentially |
| `deep_scan_status` | Check sandbox health and registry info |
| `deep_scan_fuzz` | Run AI-powered fuzzing (requires Podman container backend) |
| `deep_scan_hunt_fuzz` | Run SAST analysis followed by AI-powered fuzzing of identified vulnerable functions (requires Podman + consent) |
| `deep_scan_fuzz_status` | Check fuzzer availability and configuration |

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
make test-fuzzer    # Fuzzer tests only
make test-c-fuzzer  # C fuzzer plugin tests only
make sast           # Security scan with bandit
make security       # sast + pip-audit
```

## Registry Format

See `registries/README.md` for the YAML registry format documentation.

## Known Limitations (v1)

1. **Intraprocedural taint only** — source and sink must be in the same function body. Expected detection rate: **10-25%** of real-world injection vulnerabilities. Most web app vulnerabilities span multiple function call boundaries and will NOT be detected by v1.

2. **Query brittleness (tree-sitter backend only)** — tree-sitter queries match specific AST shapes. When using Semgrep backend, aliased imports, fully-qualified names, and class attributes are handled correctly. The following patterns are NOT matched when using tree-sitter:
   - Aliased imports: `req = request; req.form`
   - Fully-qualified names: `flask.request.form`
   - Class attributes: `self.request.form`
   - Chained calls: `request.form.get("key")` (partial match only)

3. **PoC verification is bonus-only** — most template-based PoCs fail due to missing execution context (framework setup, dependency injection, state initialization). A failed PoC does NOT mean the vulnerability is false. The exploit bonus is capped at 10 points.

4. **No cross-language taint** — Python calling C via FFI is not analyzed. Each language is analyzed independently.

5. **No interprocedural analysis** — call graphs across functions/files are not traced in v1. Deferred to v1.1.

6. **Fuzzer requires optional dependencies** — dynamic analysis requires `pip install -e ".[fuzz]"` to install the `anthropic` SDK and related packages. The fuzzer will not be available without these dependencies.

7. **`deep_scan_fuzz` MCP tool requires Podman** — The MCP fuzzing tool uses
   ContainerBackend for full isolation and is only available when Podman is
   installed and the `dcs-fuzz-python:latest` image is built via
   `make build-fuzz-sandbox`. CLI fuzzing supports both SubprocessBackend
   (rlimits-only) and ContainerBackend.

8. **C language: no preprocessor resolution** — `#ifdef` guards and macro
   expansions are invisible to the scanner. Code hidden behind conditional
   compilation will not be analyzed.

9. **C language: no struct member taint tracking** — taint does not propagate
   through struct field assignments. Only scalar variables and direct pointer
   dereferences are tracked.

10. **C language: pointer aliasing tracked within same function only** —
    intraprocedural constraint applies (same as limitation #1). Pointer
    aliases passed to other functions are not tracked.

11. **C language: output-parameter sources deferred** — C source functions
    that deliver tainted data via output parameters (`recv`, `fread`, `read`,
    `scanf`, `getline`, `getdelim`) are not effective taint sources in v1.
    Only functions whose return value is the tainted data (`argv`, `getenv`,
    `gets`, `fgets`) work correctly with the LHS-seeding taint engine.

12. **C language: CWE-416 (use-after-free) detection deferred** — requires
    temporal ordering analysis (tracking that `free(ptr)` precedes a
    subsequent use of `ptr`), which is fundamentally different from the
    source-to-sink taint model.

13. **C language: `mktemp()`/`tmpnam()` detection gap** — registered as
    CWE-676 sinks, but the taint-flow pipeline requires a source-to-sink
    path. Most real-world uses call these with hardcoded template strings, so
    they will NOT be flagged.

14. **C fuzzer harness validation is allowlist-based, not
    sandbox-escape-proof** — The C fuzzer compiles and executes LLM-generated
    C code inside a Podman container with seccomp enforcement. Dual-layer AST
    validation prohibits dangerous syscalls and non-standard includes, but
    this is a defense-in-depth measure, not a complete security boundary. The
    primary isolation mechanism is the Podman container with `--network=none`,
    `--read-only`, `--cap-drop=ALL`, and a custom seccomp profile
    (`sandbox/seccomp-fuzz-c.json`). Prompt injection attacks that evade the
    AST allowlist could still execute arbitrary code inside the container (but
    not escape to the host).

## Security Model

The MCP server runs as a **native stdio process** on the host. It does NOT run
inside a Docker container, avoiding the Docker socket mount attack vector.
Docker or Podman is used for sandbox containers that execute exploit PoCs
(auditor/architect phases). The fuzzer's ContainerBackend uses Podman
exclusively for rootless container execution.

All file access goes through `DCS_ALLOWED_PATHS` allowlist validation with symlink resolution. All RawFinding fields are validated before exploit template interpolation. Finding provenance is verified via server-side session store (external callers cannot inject arbitrary findings).

## v1.1 Roadmap

- Interprocedural taint tracking (call graph construction)
- Java and Rust language support
- Additional registry patterns (aliased imports, fully-qualified names)
- gVisor/Firecracker sandbox option for higher-risk deployments
