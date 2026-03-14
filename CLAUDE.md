# deep-code-security -- Claude Code Project Guide

## Project Overview

Multi-language SAST tool with agentic verification and AI-powered fuzzing. Two analysis modes:
1. **Static Analysis (SAST)** -- Three-phase pipeline:
   - **Hunter** -- AST parsing via tree-sitter, taint tracking, source/sink discovery
   - **Auditor** -- Sandbox exploit verification, confidence scoring (bonus-only)
   - **Architect** -- Remediation guidance generation (NOT apply-ready patches)
2. **Dynamic Analysis (Fuzzing)** -- AI-powered fuzzer with coverage-guided feedback:
   - **Fuzzer** -- LLM-guided input generation, sandboxed execution, crash dedup, corpus management

Exposed via MCP server (native stdio, not containerized) and unified CLI.

## Architecture

```
src/deep_code_security/
    shared/          # File discovery, language detection, config, JSON output
        formatters/  # Unified formatter registry (text, json, sarif, html)
    hunter/          # Phase 1: tree-sitter parse -> taint track -> RawFinding[]
    auditor/         # Phase 2: exploit generation -> sandbox exec -> VerifiedFinding[]
    architect/       # Phase 3: context gather -> guidance -> RemediationGuidance[]
    fuzzer/          # Dynamic analysis: AI-powered fuzzer
        ai/          # Claude API integration, prompt templates, response parsing
        execution/   # Sandboxed subprocess execution, _worker.py
        analyzer/    # Source code analysis, signature extraction
        corpus/      # Crash/interesting input storage, serialization
        coverage_tracking/  # Coverage delta computation
        plugins/     # Language-specific target plugins (Python MVP)
        reporting/   # Crash deduplication
        replay/      # Re-execute saved crash inputs
    mcp/             # MCP server (BaseMCPServer, 6 tools, stdio transport)
        shared/      # Vendored from helper-mcps (BaseMCPServer base class)
registries/          # YAML source/sink definitions per language
sandbox/             # Docker images for exploit execution
tests/               # pytest suite (90%+ coverage required)
```

## Critical Rules

### Security (Non-Negotiable)
- **Never `yaml.load()`** -- always `yaml.safe_load()`
- **Never `eval()`, `exec()`, `os.system()`, `subprocess.run(shell=True)`** in production code
  - Exception: `fuzzer/execution/_worker.py` uses `eval()` with restricted globals and
    dual-layer AST validation. See Security Deviation SD-02 in `plans/merge-fuzzy-wuzzy.md`.
- **All subprocess calls use list-form arguments** (never shell=True)
- **All file paths validated through `mcp/path_validator.py`** with DCS_ALLOWED_PATHS allowlist
- **All container operations enforce full security policy**: seccomp + no-new-privileges + cap-drop=ALL
- **Jinja2 SandboxedEnvironment** for PoC template rendering (never raw string formatting)
- **`mcp/input_validator.py`** validates all RawFinding fields before template interpolation
- **Expression strings re-validated** on corpus replay load (closes TOCTOU gap)

### Code Quality
- **Pydantic v2** for all data-crossing models
- **Type hints on all public functions**
- **`__all__` in `__init__.py` files**
- **pathlib.Path** over os.path
- **No mutable default arguments**

### Testing
- Run tests: `make test` (90%+ coverage required)
- Per-component: `make test-hunter`, `make test-auditor`, `make test-architect`, `make test-mcp`, `make test-fuzzer`
- Integration: `make test-integration` (requires Docker/Podman)
- Lint: `make lint`
- Security scan: `make sast`

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Taint scope | Intraprocedural only (v1) | ~10-25% real-world detection; proves architecture |
| Exploit weight | 10% bonus-only | Failed PoCs != false finding; most fail due to missing context |
| Sandbox transport | subprocess CLI | No Docker socket mount (avoids root-equivalent host access) |
| MCP deployment | Native stdio | Containerized MCP + Docker socket = root-equivalent |
| Architect output | Guidance only | Apply-ready patches are frequently wrong; guidance avoids trust erosion |
| Fuzzer sandbox | rlimits-only (CLI) | Container backend deferred; `deep_scan_fuzz` MCP tool blocked until then |
| Fuzzer eval() | Restricted + AST-validated | Justified deviation; dual-layer defense (SD-02) |

## CLI Commands

| Command | Description |
|---------|-------------|
| `dcs hunt <path>` | Static analysis (Hunter phase) |
| `dcs full-scan <path>` | All three SAST phases |
| `dcs verify` | Auditor phase (requires prior hunt) |
| `dcs status` | Server health + fuzzer availability |
| `dcs fuzz <target>` | Run AI-powered fuzzer |
| `dcs replay <corpus_dir>` | Re-execute saved crash inputs |
| `dcs corpus <corpus_dir>` | Inspect corpus contents |
| `dcs fuzz-plugins` | List available fuzzer plugins |
| `dcs report <output_dir>` | View saved fuzz reports |

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
| `DCS_FUZZ_MODEL` | `claude-sonnet-4-6` | Claude model for input generation |
| `DCS_FUZZ_MAX_ITERATIONS` | `10` | Max fuzzing iterations |
| `DCS_FUZZ_INPUTS_PER_ITER` | `10` | Inputs generated per iteration |
| `DCS_FUZZ_TIMEOUT_MS` | `5000` | Per-input execution timeout |
| `DCS_FUZZ_MAX_COST_USD` | `5.0` | API cost budget |
| `DCS_FUZZ_OUTPUT_DIR` | `./fuzzy-output` | Corpus and report output directory |
| `DCS_FUZZ_CONSENT` | `false` | Pre-configured consent for CI (API transmission only) |
| `DCS_FUZZ_GCP_REGION` | `us-east5` | GCP region for Vertex AI |
| `DCS_FUZZ_ALLOWED_PLUGINS` | `python` | Comma-separated allowlist of fuzzer plugin names |
| `DCS_FUZZ_MCP_TIMEOUT` | `120` | Hard wall-clock timeout for MCP fuzz invocations |

## Known Limitations (v1)

1. **Intraprocedural taint only** -- source and sink must be in the same function. Expected detection rate: 10-25% of real-world injection vulnerabilities.
2. **Query brittleness** -- aliased imports (`req = request; req.form`), fully-qualified names (`flask.request.form`), and class attributes (`self.request.form`) are NOT matched.
3. **PoC verification is bonus-only** -- most template PoCs fail due to missing execution context. This is expected.
4. **No cross-language taint** -- Python calling C via FFI is not analyzed.
5. **Fuzzer `_worker.py` uses `eval()`** -- justified deviation from CLAUDE.md eval() ban. Dual-layer AST validation (response_parser.py + _worker.py) with restricted globals provides defense in depth. See SD-02 in `plans/merge-fuzzy-wuzzy.md`.
6. **`deep_scan_fuzz` MCP tool is deferred** -- blocked on container-based sandbox backend (SD-01). Only `deep_scan_fuzz_status` is active.

## File Conventions

- `models.py` per phase -- all Pydantic models
- `orchestrator.py` per phase -- entry point coordinating subcomponents
- Registries in `registries/` YAML files, never hardcoded in Python
- Test fixtures in `tests/fixtures/vulnerable_samples/` and `tests/fixtures/safe_samples/`
