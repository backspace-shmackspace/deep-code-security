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
        suppressions.py  # .dcs-suppress.yaml loading and matching
    hunter/          # Phase 1: scanner backend (Semgrep/tree-sitter) -> taint track -> RawFinding[]
    auditor/         # Phase 2: exploit generation -> sandbox exec -> VerifiedFinding[]
    architect/       # Phase 3: context gather -> guidance -> RemediationGuidance[]
    bridge/          # SAST-to-Fuzz bridge: RawFinding[] -> FuzzTarget[], CorrelationReport
    fuzzer/          # Dynamic analysis: AI-powered fuzzer
        ai/          # Claude API integration, prompt templates, response parsing
        execution/   # Sandboxed subprocess execution, _worker.py
        analyzer/    # Source code analysis, signature extraction
        corpus/      # Crash/interesting input storage, serialization
        coverage_tracking/  # Coverage delta computation
        plugins/     # Language-specific target plugins (Python, C)
        reporting/   # Crash deduplication
        replay/      # Re-execute saved crash inputs
    mcp/             # MCP server (BaseMCPServer, 6 tools always + deep_scan_fuzz and deep_scan_hunt_fuzz when Podman available, stdio transport)
        shared/      # Vendored from helper-mcps (BaseMCPServer base class)
    tui/             # Interactive terminal UI (Textual). Wraps CLI via subprocess for scanning; formatter conversion uses shared.formatters directly
        screens/     # Textual screen classes (target select, scan config, progress, results, history)
registries/          # YAML source/sink definitions per language
sandbox/             # Docker images for exploit execution
tests/               # pytest suite (90%+ coverage required)
```

## Critical Rules

### Security (Non-Negotiable)
- **Never `yaml.load()`** -- always `yaml.safe_load()`
- **Never `eval()`, `exec()`, `os.system()`, `subprocess.run(shell=True)`** in production code
  - Exception: Python fuzzer `fuzzer/execution/_worker.py` uses `eval()` with restricted globals and
    dual-layer AST validation. See Security Deviation SD-02 in `plans/merge-fuzzy-wuzzy.md`.
  - Note: C fuzzer `fuzzer/execution/_c_worker.py` does NOT use `eval()` — it compiles C source
    with gcc and runs the binary. The dual-layer validation applies to AST checks (prohibit
    syscalls, shell execution), not expression evaluation.
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
- Per-component: `make test-hunter`, `make test-auditor`, `make test-architect`, `make test-mcp`, `make test-fuzzer`, `make test-bridge`, `make test-tui`
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
| Fuzzer sandbox CLI | rlimits-only (SubprocessBackend) | Fast, zero-dependency path for local development |
| Fuzzer sandbox MCP | ContainerBackend (Podman) | SD-01 resolved; MCP runs require full container isolation |
| Fuzzer runtime | Podman (not Docker) | Rootless Podman avoids Docker daemon socket (root-equivalent) |
| Fuzzer eval() | Restricted + AST-validated | Justified deviation; dual-layer defense (SD-02) |
| C fuzzer harness execution | gcc compilation + binary exec (not eval) | Avoids Python expression evaluation security risks; leverages AddressSanitizer for memory error detection |
| C fuzzer allowlist defaults | `python` only | Opt-in model: users must explicitly set `DCS_FUZZ_ALLOWED_PLUGINS=python,c` to enable C fuzzing |
| Scanner backend | Semgrep-primary with tree-sitter fallback | Resolves tree-sitter query brittleness; Semgrep OSS provides parity intraprocedural taint with superior pattern matching |

## CLI Commands

| Command | Description |
|---------|-------------|
| `dcs hunt <path>` | Static analysis (Hunter phase) |
| `dcs hunt <path> --ignore-suppressions` | Static analysis ignoring .dcs-suppress.yaml |
| `dcs full-scan <path>` | All three SAST phases |
| `dcs full-scan <path> --ignore-suppressions` | Full scan ignoring .dcs-suppress.yaml |
| `dcs verify` | Auditor phase (requires prior hunt) |
| `dcs status` | Server health + fuzzer availability |
| `dcs fuzz <target>` | Run AI-powered fuzzer |
| `dcs hunt-fuzz <path>` | Hunt then fuzz: SAST -> bridge -> fuzz -> correlation report |
| `dcs hunt-fuzz <path> --ignore-suppressions` | Hunt-fuzz ignoring .dcs-suppress.yaml |
| `dcs replay <corpus_dir>` | Re-execute saved crash inputs |
| `dcs corpus <corpus_dir>` | Inspect corpus contents |
| `dcs fuzz-plugins` | List available fuzzer plugins |
| `dcs report <output_dir>` | View saved fuzz reports |
| `dcs tui` | Launch interactive terminal UI (requires `pip install deep-code-security[tui]`) |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DCS_SCANNER_BACKEND` | `auto` | Scanner backend: `semgrep`, `treesitter`, or `auto` (prefer semgrep if available) |
| `DCS_SEMGREP_TIMEOUT` | `120` | Maximum seconds for Semgrep subprocess |
| `DCS_SEMGREP_RULES_PATH` | `<registry>/semgrep` | Path to DCS Semgrep rule files |
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
| `DCS_FUZZ_CONSENT` | `false` | Pre-configured consent for CI (API transmission only) |
| `DCS_FUZZ_GCP_REGION` | `us-east5` | GCP region for Vertex AI |
| `DCS_FUZZ_ALLOWED_PLUGINS` | `python` | Comma-separated allowlist of fuzzer plugin names (default: python; set to python,c to enable both) |
| `DCS_FUZZ_MCP_TIMEOUT` | `120` | Hard wall-clock timeout for MCP fuzz invocations |
| `DCS_FUZZ_CONTAINER_IMAGE` | `dcs-fuzz-python:latest` | Podman image used by ContainerBackend for MCP fuzz runs |
| `DCS_FUZZ_C_CONTAINER_IMAGE` | `dcs-fuzz-c:latest` | Podman image used by CContainerBackend for C fuzz runs |
| `DCS_FUZZ_C_COMPILE_FLAGS` | `""` | Comma-separated gcc flags for C harness compilation |
| `DCS_FUZZ_C_INCLUDE_PATHS` | `""` | Comma-separated include paths for C harness compilation |
| `DCS_BRIDGE_MAX_TARGETS` | `10` | Max fuzz targets produced by the SAST-to-Fuzz bridge |
| `DCS_OUTPUT_DIR` | `~/.dcs/reports/` | Root directory for TUI report storage (TUI-only, read by `tui/storage.py`) |

## Development Commands

| Command | Description |
|---------|-------------|
| `make build-fuzz-sandbox` | Build the Podman worker image (`dcs-fuzz-python:latest`) |
| `make build-fuzz-c-sandbox` | Build the C fuzzer Podman worker image (`dcs-fuzz-c:latest`) |
| `make test-fuzzer` | Run fuzzer unit tests |
| `make test-c-fuzzer` | Run C fuzzer plugin tests only |
| `make test-tui` | Run TUI unit tests (requires `textual` installed) |
| `make test-integration` | Run integration tests (requires Podman + image) |

Note: Podman (not Docker) is used for the fuzzer container backend. Run
`make build-fuzz-sandbox` (Python fuzzer) and `make build-fuzz-c-sandbox`
(C fuzzer) before running integration tests or using the `deep_scan_fuzz` /
`deep_scan_hunt_fuzz` MCP tools with C targets.

## Known Limitations (v1)

1. **Intraprocedural taint only** -- source and sink must be in the same function. Expected detection rate: 10-25% of real-world injection vulnerabilities.
2. **Query brittleness** -- aliased imports (`req = request; req.form`), fully-qualified names (`flask.request.form`), and class attributes (`self.request.form`) are NOT matched. (Resolved when using the Semgrep backend -- Semgrep's pattern DSL handles aliased imports, fully-qualified names, and class attributes.)
3. **PoC verification is bonus-only** -- most template PoCs fail due to missing execution context. This is expected.
4. **No cross-language taint** -- Python calling C via FFI is not analyzed.
5. **Python fuzzer `_worker.py` uses `eval()`** -- justified deviation from CLAUDE.md eval() ban. Dual-layer AST validation (response_parser.py + _worker.py) with restricted globals provides defense in depth. See SD-02 in `plans/merge-fuzzy-wuzzy.md`.
6. **C language support** -- intraprocedural taint only (same as Python/Go). No preprocessor resolution (`#ifdef` guards are invisible to the scanner). No struct member taint tracking. Pointer aliasing is tracked within the same function only.
7. **C output-parameter sources deferred** -- C source functions that deliver tainted data via output parameters (`recv`, `fread`, `read`, `scanf`, `getline`, `getdelim`) are not effective taint sources in v1. Only functions whose return value IS the tainted data (`argv`, `getenv`, `gets`, `fgets`) work correctly with the LHS-seeding taint engine. Deferred to a future plan increment that adds output-parameter taint summaries.
8. **CWE-416 (use-after-free) detection deferred** -- requires temporal ordering analysis (tracking that `free(ptr)` precedes a subsequent use of `ptr`), which is fundamentally different from the source-to-sink taint model. Deferred to a future plan.
9. **`mktemp()`/`tmpnam()` detection gap** -- registered as CWE-676 sinks, but the taint-flow pipeline requires a source-to-sink path. Most real-world uses call these with hardcoded template strings, so they will NOT be flagged.
10. **C conditional assignment sanitizer -- partial coverage** -- the C hunter recognizes `if (n > max) n = max;` and ternary clamp variants (`n = (n > max) ? max : n;`) as sanitizers for CWE-119/CWE-120/CWE-190, downgrading confidence from "confirmed" to "likely". Macro-based clamps (e.g., `MIN(n, max)`), early-return guards (`if (n > max) return -1;`), and bitwise masks are NOT recognized and will not reduce confidence.
11. **Semgrep OSS taint paths are always synthetic two-step** -- Semgrep OSS does not emit `dataflow_trace` (Pro-only feature). All Semgrep findings have a synthetic two-step TaintPath (source + sink only, no intermediate variable traces), capping taint completeness score at 50. Tree-sitter findings with full paths score 100.
12. **C fuzzer harness validation -- allowlist-based security model** -- The C fuzzer compiles and executes arbitrary C code generated by the AI model inside a Podman container with full seccomp enforcement (`sandbox/seccomp-fuzz-c.json`). Layer 1 (host-side) and Layer 2 (container-side) AST validation prohibit: `system()`, `popen()`, `exec*()` calls; network syscalls (`socket`, `connect`, `bind`, `listen`, `accept`); file operations outside the build tmpfs (`open`, `creat` with absolute paths); non-standard library includes (only `stdlib.h`, `string.h`, `stdint.h`, etc. allowed). Harness size capped at 64 KB. **This is NOT a sandbox escape prevention mechanism** — it is a defense-in-depth measure to reduce prompt injection risk. The Podman container with seccomp is the primary security boundary. See `_c_worker.py` lines 36-87 for validation constants and `sandbox/seccomp-fuzz-c.json` for syscall allowlist.

## File Conventions

- `models.py` per phase -- all Pydantic models
- `orchestrator.py` per phase -- entry point coordinating subcomponents
- Registries in `registries/` YAML files, never hardcoded in Python
- Suppression file always named `.dcs-suppress.yaml` in project root, loaded
  via `shared/suppressions.py`
- Test fixtures in `tests/fixtures/vulnerable_samples/` and
  `tests/fixtures/safe_samples/`
