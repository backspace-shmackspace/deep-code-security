# Plan: Podman Container Backend for Fuzzer Sandbox (SD-01 Resolution)

## Status: APPROVED

## Goals

1. Implement the `ContainerBackend` class in `src/deep_code_security/fuzzer/execution/sandbox.py`, replacing the current `NotImplementedError` stub with a fully functional Podman-based container execution backend.
2. Mirror the auditor's container security policy: `--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, seccomp profile, `--pids-limit`, `--memory`, `--cpus`, `--user=65534:65534`, noexec tmpfs.
3. Create a purpose-built container image (`sandbox/Containerfile.fuzz-python`) that contains the fixed worker module (`_worker.py`) and its dependencies, invocable via `python -m deep_code_security.fuzzer.execution._worker`.
4. Unblock the `deep_scan_fuzz` MCP tool by registering it in the MCP server when the container backend is available.
5. Resolve Security Deviation SD-01 from the merge-fuzzy-wuzzy plan: MCP-triggered fuzz runs must use the container backend exclusively; the rlimit-only `SubprocessBackend` remains available for CLI usage only.
6. Maintain backward compatibility: CLI `dcs fuzz` continues to work with the `SubprocessBackend` (unchanged default behavior), while MCP invocations require and enforce the `ContainerBackend`.
7. Create a dedicated fuzzer seccomp profile (`sandbox/seccomp-fuzz-python.json`) that is more restrictive than the shared `seccomp-default.json`, blocking container escape and cross-process attack primitives not needed by Python 3.12 fuzz target execution.

## Non-Goals

- Implementing a Docker backend. The user has explicitly requested Podman. The `DCS_CONTAINER_RUNTIME` environment variable will accept `podman` (default) and `auto` (which probes for Podman first, then falls back to an error). Docker is not a supported runtime for the fuzzer container backend.
- Adding Go or C fuzzing plugins. This plan is strictly about the container execution backend for the existing Python fuzzer plugin.
- Changing the `_worker.py` execution model. The fixed-module JSON IPC pattern (input.json/output.json) is preserved exactly as-is.
- Modifying the auditor's sandbox or the `dcs-verification` package. The auditor has its own independent container lifecycle managed by the private `dcs-verification` plugin.
- Implementing coverage collection inside containers. Coverage data collection is deferred (see Risks section). The container backend will set `collect_coverage=False` for container-executed runs until a volume mount strategy for `.coverage` data files is validated.
- Multi-architecture container images. The image will target the host architecture only (`podman build` default behavior).
- Running the MCP server inside a container. The MCP server remains a native stdio process per the original architecture.
- Modifying the existing `build-sandboxes` Makefile target. The new `build-fuzz-sandbox` target is standalone.

## Assumptions

1. Podman is installed on the target system and available in `$PATH`. The container backend will fail gracefully with a clear error message if Podman is not found.
2. The host has a functioning OCI-compliant container runtime that Podman delegates to (crun, runc, etc.).
3. The new `seccomp-fuzz-python.json` profile (derived from `seccomp-default.json` with additional blocks) is compatible with the fuzzer worker's syscall requirements (Python 3.12+ runtime only -- no Go/C support needed).
4. The container image build is a manual prerequisite (`make build-fuzz-sandbox`), not an automatic step. The MCP server checks image availability at startup and reports it via `deep_scan_fuzz_status`.
5. The `_worker.py` module and its minimal import chain (`expression_validator.py`, `__init__.py` stubs) can be copied directly into the container image at build time without installing the full `deep-code-security` package.
6. Container execution adds latency (estimated 200-500ms per invocation for container create/start/destroy). This is acceptable for fuzz runs where each input already has a 5-second default timeout.
7. Rootless Podman is supported and preferred. The container backend will not require root privileges.

## Proposed Design

### Architecture Overview

```
CLI invocation (dcs fuzz):
    FuzzOrchestrator -> PythonTargetPlugin -> FuzzRunner -> SandboxManager
        -> SubprocessBackend (rlimits-only, existing behavior)

MCP invocation (deep_scan_fuzz):
    MCP Server -> FuzzOrchestrator -> PythonTargetPlugin -> FuzzRunner -> SandboxManager
        -> ContainerBackend (Podman, mandatory)
            -> podman run [security flags] dcs-fuzz-python:latest
                -> python -m deep_code_security.fuzzer.execution._worker \
                       /workspace/input.json /workspace/output.json
```

The `ContainerBackend` wraps each fuzz input execution in an ephemeral Podman container. The container:

1. Receives the `input.json` via a bind-mounted temp directory (read-write, with `noexec,nosuid` options, for JSON IPC).
2. Receives the target Python module file via a read-only bind mount of the specific file (not the parent directory).
3. Executes the fixed `_worker.py` module inside the container.
4. Writes `output.json` to the bind-mounted temp directory.
5. Is destroyed after execution (ephemeral: `--rm`).

### Path Translation (Host-to-Container)

The JSON IPC pattern requires path translation because the `FuzzRunner` operates with host-side paths, but the worker runs inside a container with different mount points. Two translations are required:

**1. `module_path` in `input.json`:** The `FuzzRunner` resolves this to a host-side absolute path (e.g., `/Users/imurphy/projects/myapp/module.py`). Inside the container, the target file is bind-mounted at `/target/<filename>`. The `FuzzRunner` must rewrite `module_path` in `input.json` to the container-side path when using a container backend.

**2. `cmd` arguments (input.json and output.json paths):** The `FuzzRunner` constructs `cmd = [self._python, "-m", WORKER_MODULE, input_json, output_json]` using host-side temp directory paths. The `ContainerBackend` ignores the `cmd` argument entirely and constructs its own command using container-side paths (`/workspace/input.json`, `/workspace/output.json`). The container image's entrypoint is `python -m deep_code_security.fuzzer.execution._worker`, and the `ContainerBackend` appends `/workspace/input.json /workspace/output.json` as arguments.

**Implementation in `FuzzRunner`:**

```python
# In FuzzRunner.run(), when using container backend:
if isinstance(self._sandbox._backend, ContainerExecutionBackend):
    container_module_path = "/target/" + Path(module_path).name
    params["module_path"] = container_module_path
else:
    params["module_path"] = str(Path(module_path).resolve())
```

The `ContainerBackend.run()` receives `cmd` for protocol compatibility but does not use it. Instead, it constructs the Podman command internally with hardcoded container-side paths. This is explicitly documented in the docstring and is safe because `ContainerBackend` is not a transparent subprocess wrapper -- it is a complete execution environment.

### Container Security Policy

The fuzzer container backend enforces the following security policy:

| Security Control | Value | Rationale |
|---|---|---|
| `--network=none` | No network access | Fuzz targets should not make network calls |
| `--read-only` | Read-only root filesystem | Prevent target code from modifying container FS |
| `--cap-drop=ALL` | No Linux capabilities | Minimum privilege principle |
| `--security-opt=no-new-privileges` | Prevent privilege escalation | Block setuid/setgid |
| `--security-opt seccomp=<path>` | Fuzzer-specific seccomp profile (`seccomp-fuzz-python.json`) | Restrict syscalls to Python runtime needs; blocks container escape primitives |
| `--pids-limit=64` | Max 64 processes | Prevent fork bombs |
| `--memory=512m` | 512MB memory limit | Prevent OOM host impact |
| `--cpus=1.0` | 1 CPU core limit | Prevent CPU exhaustion by fuzz targets |
| `--user=65534:65534` | Run as nobody | Non-root execution |
| `--tmpfs /tmp:rw,noexec,nosuid,size=64m` | Writable /tmp (noexec) | Python runtime needs writable temp space |
| `--volume <host_cwd>:/workspace:rw,noexec,nosuid` | IPC bind mount with noexec | Host writes `input.json` before container start; container writes `output.json`; host reads it after exit. `noexec,nosuid` prevents execution of planted binaries. |
| `--volume <target_file>:/target/<filename>:ro` | Single-file read-only mount | Only the specific target module file is exposed; sibling files (.env, .git, *.pem, *.key) are NOT mounted |
| `--rm` | Auto-remove after exit | No container accumulation |
| `--timeout <seconds>` | Podman-level timeout | Defense-in-depth beyond Python timeout |

### Host-Side Output Validation

After container exit, before reading `output.json`, the `ContainerBackend` (or `FuzzRunner`) performs host-side validation on the IPC directory:

1. **Symlink check:** Verify `output.json` is a regular file (`Path.is_file()` returns `True` and `Path.is_symlink()` returns `False`). Reject if it is a symlink.
2. **Size check:** Verify `output.json` size is within bounds (max 10MB). Reject oversized files.
3. **Unexpected files check:** After container exit, list files in the temp directory. Only `input.json` and `output.json` are expected. Log a warning if unexpected files are found (but do not fail -- some Python runtimes create `__pycache__` despite `PYTHONDONTWRITEBYTECODE`).

This mitigates the risk of a malicious fuzz target planting symlinks or other artifacts in the bind-mounted workspace directory.

### Seccomp Profile (Fuzzer-Specific)

A new seccomp profile `sandbox/seccomp-fuzz-python.json` is created, derived from `sandbox/seccomp-default.json` with the following changes:

**Removed from allow list (moved to explicit block list):**

| Syscall | Reason for Blocking |
|---|---|
| `open_by_handle_at` | Container escape primitive (CVE-2015-1334, Shocker exploit). Requires `CAP_DAC_READ_SEARCH` which is dropped, but defense-in-depth requires seccomp blocking too. |
| `name_to_handle_at` | Used in conjunction with `open_by_handle_at` for container escape. |
| `process_vm_readv` | Read memory of other processes within PID namespace. Not needed by Python fuzz targets. |
| `process_vm_writev` | Write memory of other processes within PID namespace. Not needed by Python fuzz targets. |
| `kcmp` | Compare kernel objects between processes, can leak file descriptor information. Not needed by Python fuzz targets. |

The shared `sandbox/seccomp-default.json` is NOT modified. It continues to serve the auditor sandbox which supports Go and C runtimes that may need the broader syscall set. The fuzzer uses its own dedicated profile.

**Rationale for separate profile:** The auditor supports Python, Go, and C targets. The fuzzer currently supports only Python. A dedicated profile follows the principle of least privilege and avoids coupling the fuzzer's security posture to the auditor's multi-language requirements.

### Container Image Design

**Image name:** `dcs-fuzz-python:latest`

**Build file:** `sandbox/Containerfile.fuzz-python`

The image is a minimal Python 3.12 environment containing only the worker module and its import chain. No third-party packages are installed.

**Minimal file copy approach (no pip install):**

```dockerfile
FROM python:3.12-slim AS runtime
# Create package structure with only the modules the worker needs
COPY src/deep_code_security/__init__.py /app/deep_code_security/
COPY src/deep_code_security/fuzzer/__init__.py /app/deep_code_security/fuzzer/
COPY src/deep_code_security/fuzzer/ai/__init__.py /app/deep_code_security/fuzzer/ai/
COPY src/deep_code_security/fuzzer/ai/expression_validator.py /app/deep_code_security/fuzzer/ai/
COPY src/deep_code_security/fuzzer/execution/__init__.py /app/deep_code_security/fuzzer/execution/
COPY src/deep_code_security/fuzzer/execution/_worker.py /app/deep_code_security/fuzzer/execution/
ENV PYTHONPATH=/app
USER 65534:65534
WORKDIR /workspace
ENTRYPOINT ["python", "-m", "deep_code_security.fuzzer.execution._worker"]
```

Key details:
- No pip, setuptools, or build tools in the final image.
- No third-party dependencies (Pydantic, tree-sitter, etc.). Analysis of `_worker.py`'s import chain confirms it only imports standard library modules and `expression_validator.py` (which also uses only standard library).
- Non-root user 65534 (nobody).
- `LABEL org.opencontainers.image.title="dcs-fuzz-python"` and `LABEL org.opencontainers.image.version="1.0.0"` for auditing.
- No network tools, no compilers, no package managers.

### ContainerBackend Implementation

```python
class ContainerBackend:
    """Podman container execution backend for fuzz target isolation.

    Each FuzzRunner invocation that uses this backend must create its own
    ContainerBackend instance or call run() with per-invocation mount
    configuration. The run() method is stateless -- all mount information
    is passed as arguments.
    """

    CONTAINER_IMAGE = "dcs-fuzz-python:latest"
    SECCOMP_PROFILE_NAME = "seccomp-fuzz-python.json"
    _ALLOWED_ENV_KEYS: frozenset[str] = frozenset({
        "PYTHONPATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONSAFEPATH",
    })

    def __init__(
        self,
        runtime_cmd: str = "podman",
        image: str | None = None,
        seccomp_profile: Path | None = None,
        memory_limit: str = "512m",
        pids_limit: int = 64,
        cpus: float = 1.0,
        tmpfs_size: str = "64m",
    ) -> None: ...

    def is_available(self) -> bool:
        """Check if Podman and the fuzz image are available."""
        ...

    def run(
        self,
        cmd: list[str],
        timeout_seconds: float,
        cwd: str,
        env: dict[str, str] | None = None,
        *,
        target_file: str | None = None,
    ) -> tuple[int, str, str]:
        """Run command inside an ephemeral Podman container.

        The cmd argument is accepted for ExecutionBackend protocol
        compatibility but is IGNORED. The container backend constructs
        its own command using container-side paths.

        The env argument is IGNORED. The container backend constructs
        its own minimal environment using only _ALLOWED_ENV_KEYS with
        hardcoded values. This prevents host environment leakage
        regardless of what the caller passes.

        Args:
            cmd: Ignored. Present for protocol compatibility.
            timeout_seconds: Execution timeout.
            cwd: Host-side temp directory for JSON IPC (bind-mounted
                as /workspace).
            env: Ignored. Present for protocol compatibility.
            target_file: Host-side absolute path to the target module
                file. Bind-mounted as /target/<filename>:ro.

        Returns:
            (returncode, stdout, stderr) tuple.
        """
        ...
```

The `run()` method constructs and executes a `podman run` command:

```
podman run --rm \
    --network=none \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --security-opt seccomp=/abs/path/to/seccomp-fuzz-python.json \
    --pids-limit=64 \
    --memory=512m \
    --cpus=1.0 \
    --user=65534:65534 \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    --volume <host_cwd>:/workspace:rw,noexec,nosuid \
    --volume <target_file>:/target/<filename>:ro \
    --env PYTHONPATH=/target \
    --env PYTHONDONTWRITEBYTECODE=1 \
    --env PYTHONSAFEPATH=1 \
    --timeout <int(timeout_seconds) + 5> \
    dcs-fuzz-python:latest \
    /workspace/input.json /workspace/output.json
```

Key details:
- The `cwd` from `SandboxManager.create_isolated_dir()` is bind-mounted as `/workspace` (read-write, noexec, nosuid). This is where `input.json` is written before container start and `output.json` is read after container exit.
- The target module file (not its parent directory) is bind-mounted as `/target/<filename>` (read-only) with `PYTHONPATH=/target` so the worker can import the fuzz target. Only the single file is exposed -- sibling files (.env, .git/config, *.pem, *.key, etc.) are not accessible.
- The Podman `--timeout` flag is set to `int(timeout_seconds) + 5` as a defense-in-depth backstop (integer conversion via `int()` since Podman requires an unsigned integer). The worker process has its own internal timeout mechanism.
- The `--cpus=1.0` flag limits each container to one CPU core, preventing CPU exhaustion by fuzz targets.
- The `env` parameter from the caller is **ignored**. The `ContainerBackend` constructs its own environment dict containing only `_ALLOWED_ENV_KEYS` with hardcoded values (`PYTHONPATH=/target`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONSAFEPATH=1`). This prevents host environment leakage regardless of what `FuzzRunner._build_env()` passes. API keys, `HOME`, `PATH`, and other sensitive variables never reach the container.

### Stateless Backend Design (TOCTOU Resolution)

The original plan used a `configure_mounts()` / `run()` two-step pattern that stored mount configuration as instance state. This created a TOCTOU race condition when concurrent MCP fuzz runs shared a backend instance.

**Resolution:** The `ContainerBackend.run()` method accepts mount configuration directly via the `target_file` keyword argument. The backend stores no per-run state between calls. This is safe for concurrent use because all per-run context is passed as arguments.

The `ContainerExecutionBackend` protocol is replaced by extending the `run()` method signature with `**kwargs`:

```python
class ExecutionBackend(Protocol):
    """Protocol for execution backends (subprocess, container, etc.)."""

    def run(
        self,
        cmd: list[str],
        timeout_seconds: float,
        cwd: str,
        env: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> tuple[int, str, str]:
        """Run a command and return (returncode, stdout, stderr)."""
        ...
```

The `SubprocessBackend.run()` accepts and ignores `**kwargs`. The `ContainerBackend.run()` extracts `target_file` from `kwargs`. This preserves Liskov Substitution: callers that do not pass `target_file` work with both backends.

**FuzzRunner changes:**

```python
# In FuzzRunner.run():
backend = self._sandbox._backend
is_container = isinstance(backend, ContainerBackend)

if is_container:
    # Rewrite module_path for container-side mount point
    params["module_path"] = "/target/" + Path(module_path).name
else:
    params["module_path"] = str(Path(module_path).resolve())

# ... write input.json ...

returncode, stdout, stderr = backend.run(
    cmd=cmd,
    timeout_seconds=timeout_seconds,
    cwd=tmp_dir,
    env=self._build_env(module_path),
    target_file=str(Path(module_path).resolve()) if is_container else None,
)
```

### Backend Injection Through Plugin Registry

The `FuzzOrchestrator` obtains plugins via `registry.get_plugin(config.plugin_name)`, which creates a new `PythonTargetPlugin()` instance with its own default `SubprocessBackend`. To inject the `ContainerBackend`, a `set_backend()` method is added to the `TargetPlugin` base class:

```python
# In base.py:
class TargetPlugin(ABC):
    def set_backend(self, backend: ExecutionBackend) -> None:
        """Inject an execution backend. Called after construction by the orchestrator."""
        raise NotImplementedError("Subclass must implement set_backend()")
```

```python
# In python_target.py:
class PythonTargetPlugin(TargetPlugin):
    def set_backend(self, backend: ExecutionBackend) -> None:
        """Replace the execution backend (used for container injection)."""
        self._runner = FuzzRunner(sandbox=SandboxManager(backend=backend))
```

```python
# In orchestrator.py:
plugin = registry.get_plugin(config.plugin_name)
if self._backend is not None:
    plugin.set_backend(self._backend)
```

This avoids modifying the plugin registry's construction mechanism and keeps the injection explicit.

### MCP Server Changes

When the container backend is available, the `deep_scan_fuzz` tool is registered. The handler:

1. Validates path, consent, and parameters.
2. Constructs a `FuzzerConfig` with the container backend enforced.
3. Starts `FuzzOrchestrator` in a background thread with `install_signal_handlers=False`.
4. Returns immediately with `{"status": "running", "fuzz_run_id": "..."}`.
5. The client polls `deep_scan_fuzz_status` with the `fuzz_run_id`.
6. A wall-clock timeout (`DCS_FUZZ_MCP_TIMEOUT`, default 120s) caps execution.

**Background thread lifecycle management:**

The background thread wraps `FuzzOrchestrator.run()` in a `try/except/finally` block:

```python
def _fuzz_thread(self, fuzz_run_id: str, orchestrator: FuzzOrchestrator) -> None:
    run_state = self._fuzz_runs[fuzz_run_id]
    try:
        report = orchestrator.run()
        run_state.status = "completed"
        run_state.report = report
    except Exception as e:
        run_state.status = "failed"
        run_state.error = str(e)
        logger.exception("Fuzz run %s failed", fuzz_run_id)
    finally:
        if run_state.status == "running":
            run_state.status = "failed"
            run_state.error = "Unknown error: thread exited without setting status"
```

**Cancellation mechanism:** The wall-clock `threading.Timer` sets `orchestrator._shutdown_requested = True`. The `FuzzOrchestrator` checks this flag between iterations (line 156 of orchestrator.py) and between individual inputs (line 198). After setting the flag, the timer also calls `run_state.status = "timeout"`. The orchestrator completes its current container execution (bounded by `--timeout`) and then exits gracefully.

**Orphan container cleanup:** Each container is started with a `--label dcs.fuzz_run_id=<id>` flag. On MCP server startup, a cleanup pass runs `podman rm -f $(podman ps -aq --filter label=dcs.fuzz_run_id)` to remove any orphaned containers from previous server crashes. This is best-effort and logged as a warning if it fails.

**State eviction:** The `_fuzz_runs` dict uses a bounded size matching the existing `_MAX_SESSION_SCANS` pattern. When the limit is reached, the oldest completed/failed/timeout entries are evicted. Entries in "running" status are never evicted.

**FuzzRunState model:**

```python
class FuzzRunState:
    """Tracks an in-progress or completed fuzz run."""
    fuzz_run_id: str
    status: Literal["running", "completed", "failed", "timeout"]
    started_at: float
    report: FuzzReport | None = None
    error: str | None = None
```

The `_handle_fuzz_status()` method is extended to:
- Report `container_backend_available: True` when the image exists.
- Return fuzz run progress when polled with a `fuzz_run_id`.

### Backend Selection Logic

```python
def _select_backend(config: Config, require_container: bool = False) -> ExecutionBackend:
    """Select the appropriate execution backend.

    Args:
        config: DCS configuration.
        require_container: If True, raise if container backend is unavailable.

    Returns:
        ExecutionBackend instance.

    Raises:
        RuntimeError: If require_container=True and Podman/image not available.
    """
    runtime = config.container_runtime  # "podman" or "auto"

    if runtime == "auto" or runtime == "podman":
        backend = ContainerBackend(runtime_cmd="podman")
        if backend.is_available():
            return backend
        if require_container:
            raise RuntimeError(
                "Container backend required but Podman is not available or "
                "the dcs-fuzz-python:latest image is not built. "
                "Run 'make build-fuzz-sandbox' to build the image."
            )

    if require_container:
        raise RuntimeError(
            f"Container backend required but runtime '{runtime}' is not supported. "
            "Set DCS_CONTAINER_RUNTIME=podman."
        )

    # Fall back to subprocess backend (CLI only)
    return SubprocessBackend()
```

For MCP, `require_container=True`. For CLI, `require_container=False`.

## Interfaces / Schema Changes

### New Pydantic Models

None. The existing `FuzzInput`, `FuzzResult`, and `FuzzReport` models are unchanged. The container backend is purely an execution-layer change.

### Protocol Changes

**File:** `src/deep_code_security/fuzzer/execution/sandbox.py`

The `ExecutionBackend` protocol's `run()` method gains `**kwargs: Any` to allow backend-specific keyword arguments (e.g., `target_file` for `ContainerBackend`). The `SubprocessBackend` accepts and ignores `**kwargs`.

No new sub-protocol is introduced. The `configure_mounts()` pattern is eliminated in favor of stateless `run()` arguments.

**File:** `src/deep_code_security/fuzzer/plugins/base.py`

New method on `TargetPlugin` base class:

```python
def set_backend(self, backend: ExecutionBackend) -> None:
    """Inject an execution backend after construction."""
    raise NotImplementedError("Subclass must implement set_backend()")
```

### MCP Tool Schema Changes

**New tool registration:** `deep_scan_fuzz`

The tool schema is the one already preserved in the commented-out section of `server.py`:

```python
input_schema = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "description": "Path to Python file/module to fuzz"},
        "functions": {"type": "array", "items": {"type": "string"}},
        "iterations": {"type": "integer", "default": 3},
        "inputs_per_iteration": {"type": "integer", "default": 5},
        "model": {"type": "string", "default": "claude-sonnet-4-6"},
        "max_cost_usd": {"type": "number", "default": 2.00},
        "timeout_ms": {"type": "integer", "default": 5000},
        "consent": {"type": "boolean", "default": False},
    },
    "required": ["path", "consent"],
}
```

The `functions` array elements are validated via `validate_function_name()` from `input_validator.py` in the MCP handler before being passed to the orchestrator. Invalid names are rejected with `ToolError`.

**Modified tool response:** `deep_scan_fuzz_status`

The `container_backend_available` field changes from hardcoded `False` to a runtime check.

### Environment Variable Changes

| Variable | Change | New Default |
|---|---|---|
| `DCS_CONTAINER_RUNTIME` | Now used by fuzzer; `auto` probes Podman first. Note: `docker` value is NOT supported for the fuzzer container backend (Podman only). The auditor backend is unaffected. | `auto` (unchanged) |
| `DCS_FUZZ_CONTAINER_IMAGE` | **NEW** | `dcs-fuzz-python:latest` |

### CLI Changes

None to the `dcs fuzz` command. CLI behavior is unchanged (SubprocessBackend by default).

New Makefile target: `build-fuzz-sandbox` (standalone; does not modify existing `build-sandboxes` target).

## Data Migration

None. No persistent data formats change. Container image is a build artifact, not stored data.

## Rollout Plan

### Phase 1: Container Image and Seccomp Profile (Task 1)
Build the Containerfile and seccomp profile. Verify the worker module runs correctly inside the container.

### Phase 2: ContainerBackend Implementation (Tasks 2-3)
Implement the `ContainerBackend` class, integrate with `FuzzRunner`, add backend selection logic, add `set_backend()` to plugin system.

### Phase 3: MCP Integration (Task 4)
Unblock `deep_scan_fuzz`, implement background execution with lifecycle management, polling, timeout, and state eviction.

### Phase 4: Testing and Documentation (Tasks 5-7)
Unit tests (mocked Podman), integration tests (real Podman), CLAUDE.md updates.

**Deployment sequence:**
1. Merge container image, seccomp profile, and backend code (Phases 1-2). CLI continues to work with SubprocessBackend. ContainerBackend is available but not required.
2. Merge MCP integration (Phase 3). `deep_scan_fuzz` becomes available if the image is built.
3. Update documentation and close SD-01.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Podman not installed on target systems | Medium | High | Clear error messages, documentation. The MCP tool gracefully reports `container_backend_available: false`. CLI falls back to SubprocessBackend. |
| Rootless Podman limitations (e.g., seccomp on some kernels) | Low | Medium | Test on both rootful and rootless Podman. If seccomp is unavailable in rootless mode, the backend refuses to run (fail closed) and reports the error. The backend does NOT fall back to a reduced security profile -- security flags are non-negotiable. |
| Container startup latency degrades fuzz throughput | Medium | Medium | Measured and documented. Per-input overhead is bounded by the `--timeout` flag. For MCP runs with 3 iterations x 5 inputs = 15 containers, total overhead is ~3-8 seconds. |
| Single-file target mount prevents targets with relative imports from working | Medium | Medium | Targets that import sibling modules via relative imports will fail inside the container. This is a known limitation of the single-file mount approach and is the correct trade-off: security (preventing sibling file exposure) outweighs convenience. Users with multi-file targets can use CLI (`dcs fuzz`) which uses SubprocessBackend without mount restrictions. A follow-up can add a `--mount-dir` option with explicit opt-in and sensitive file filtering. |
| Coverage data collection fails inside containers | High | Medium | Coverage collection is disabled for container runs in this plan. The `collect_coverage` parameter is set to `False`. MCP fuzz runs do not get coverage-guided feedback. Without coverage delta feedback, the AI engine generates inputs based solely on crash/no-crash signals, reducing multi-iteration input diversity. A follow-up plan will add coverage collection via a dedicated writable volume mount. |
| Seccomp profile blocks syscalls needed by target code | Medium | Medium | The fuzzer-specific seccomp profile allows a broad set of syscalls needed by Python runtimes but is more restrictive than the auditor profile. If a target's dependencies need blocked syscalls (e.g., `process_vm_readv` for debugging tools), the container will produce a clear error in `output.json`. The user can fall back to CLI (SubprocessBackend). Targets using `multiprocessing` will also fail because `socket` syscalls are blocked by the profile. |
| Container image grows stale as DCS is updated | Low | Low | The Makefile target `build-fuzz-sandbox` rebuilds the image. `is_available()` checks image existence but not version. A `--label` with the DCS version is added for manual auditing. |
| Podman's `--timeout` flag behavior differs from Docker | Low | Low | Podman supports `--timeout` natively since v4.0. The flag sends SIGKILL after the specified duration. This is defense-in-depth; the Python-level timeout is the primary mechanism. |
| Concurrent MCP fuzz runs overwhelming the host | Low | Medium | `DCS_MAX_CONCURRENT_SANDBOXES` limits parallelism. The MCP handler rejects new fuzz requests when `_MAX_CONCURRENT_FUZZ_RUNS` (default: 2) active runs exist. Combined with `--cpus=1.0` per container, total CPU usage is bounded. |

## Test Plan

### Test Command

```
make test-fuzzer          # Unit tests for fuzzer (mocked Podman)
make test-integration     # Integration tests (requires Podman)
```

### Unit Tests (No Podman Required)

**File:** `tests/test_fuzzer/test_execution/test_container_backend.py`

Tests with mocked `subprocess.run`:

1. `test_container_backend_constructs_correct_podman_command` -- Verify the full `podman run` command includes all security flags in the correct order, including `--cpus=1.0`.
2. `test_container_backend_ignores_caller_env` -- Verify that the `env` parameter is ignored. Only `PYTHONPATH=/target`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONSAFEPATH=1` appear as `--env` flags; `ANTHROPIC_API_KEY`, `HOME`, `PATH`, etc., are NOT present.
3. `test_container_backend_is_available_true` -- Mock `podman images` returning the image name; verify `is_available()` returns `True`.
4. `test_container_backend_is_available_false_no_podman` -- Mock `FileNotFoundError` from subprocess; verify `is_available()` returns `False`.
5. `test_container_backend_is_available_false_no_image` -- Mock `podman images` returning empty; verify `is_available()` returns `False`.
6. `test_container_backend_timeout` -- Mock subprocess returning timeout; verify `(-1, "", "TIMEOUT")`.
7. `test_container_backend_target_file_single_file_mount` -- Verify target mount uses `/target/<filename>:ro` (single file, not parent directory).
8. `test_container_backend_workspace_mount_noexec` -- Verify workspace mount uses `:rw,noexec,nosuid`.
9. `test_container_backend_rejects_shell_true` -- Verify no `shell=True` in subprocess invocation (static assertion on the source code).
10. `test_container_backend_seccomp_profile_path` -- Verify seccomp profile path is absolute and points to `sandbox/seccomp-fuzz-python.json`.
11. `test_container_backend_stateless` -- Verify `run()` can be called concurrently with different `target_file` values (no shared state).
12. `test_container_backend_cmd_ignored` -- Verify that the `cmd` argument is not used in the constructed podman command.
13. `test_container_backend_uses_container_side_paths` -- Verify the command uses `/workspace/input.json` and `/workspace/output.json`.
14. `test_container_backend_cpus_flag` -- Verify `--cpus=1.0` is present in the podman command.
15. `test_output_json_symlink_rejected` -- Mock a symlinked `output.json`; verify the host-side reader rejects it.

**File:** `tests/test_fuzzer/test_execution/test_backend_selection.py`

1. `test_select_backend_auto_with_podman` -- Mock available Podman; verify `ContainerBackend` is selected.
2. `test_select_backend_auto_without_podman` -- Mock unavailable Podman; verify `SubprocessBackend` is selected.
3. `test_select_backend_require_container_fails` -- Mock unavailable Podman with `require_container=True`; verify `RuntimeError`.
4. `test_select_backend_podman_explicit` -- Set runtime to "podman"; verify `ContainerBackend`.

**File:** `tests/test_fuzzer/test_execution/test_path_translation.py`

1. `test_module_path_translated_for_container` -- Verify `FuzzRunner` writes `/target/<filename>` to `input.json` when using `ContainerBackend`.
2. `test_module_path_absolute_for_subprocess` -- Verify `FuzzRunner` writes host-side absolute path when using `SubprocessBackend`.

**File:** `tests/test_mcp/test_fuzz_tool.py`

1. `test_fuzz_tool_registered_when_container_available` -- Mock `ContainerBackend.is_available()` returning `True`; verify tool is in the server's tool list.
2. `test_fuzz_tool_not_registered_when_container_unavailable` -- Mock unavailable; verify tool is NOT registered.
3. `test_fuzz_tool_rejects_no_consent` -- Call with `consent=False`; verify error response.
4. `test_fuzz_tool_validates_path` -- Call with path outside `DCS_ALLOWED_PATHS`; verify rejection.
5. `test_fuzz_status_reports_container_available` -- Mock available backend; verify `container_backend_available: true`.
6. `test_fuzz_tool_enforces_container_backend` -- Verify handler uses `require_container=True`.
7. `test_fuzz_tool_validates_function_names` -- Call with invalid function names; verify rejection via `validate_function_name()`.
8. `test_fuzz_run_state_eviction` -- Verify completed run states are evicted when limit is reached.
9. `test_fuzz_thread_exception_sets_failed` -- Mock orchestrator that raises; verify run state transitions to "failed".

### Integration Tests (Podman Required)

**File:** `tests/test_integration/test_fuzz_container.py`

Marked with `@pytest.mark.skipif(not _podman_available(), reason="Podman not installed")`.

1. `test_container_runs_simple_target` -- Build the image, run a trivial fuzz target (a function that raises `ValueError` on negative input), verify the crash is captured.
2. `test_container_network_isolation` -- Run a target that attempts `socket.connect()`; verify it fails with a permission error (seccomp/network=none).
3. `test_container_filesystem_read_only` -- Run a target that attempts `open("/etc/passwd", "w")`; verify it fails.
4. `test_container_no_host_env_leakage` -- Set `ANTHROPIC_API_KEY=test-secret` on host; run a target that reads `os.environ`; verify the key is not in `stdout`/`stderr`.
5. `test_container_pid_limit` -- Run a target that forks excessively; verify it is killed.
6. `test_container_memory_limit` -- Run a target that allocates excessive memory; verify OOM kill.
7. `test_container_ephemeral` -- Run a target; verify no container remains after execution (`podman ps -a`).
8. `test_container_timeout_kill` -- Run a target with infinite loop; verify container is killed within `timeout_seconds + 5`.
9. `test_container_single_file_mount` -- Run a target alongside a `.env` file in the same directory; verify the `.env` file is NOT accessible inside the container.
10. `test_container_cpu_limit` -- Run a CPU-intensive target; verify it is throttled (execution takes longer than without `--cpus` limit).
11. `test_container_escape_primitives_blocked` -- Run a target that attempts `open_by_handle_at`; verify seccomp blocks it.

### Acceptance Criteria Verification

Run the full test suite after implementation:

```bash
make test              # All unit tests pass, 90%+ coverage
make test-fuzzer       # Fuzzer-specific unit tests
make test-integration  # Integration tests (with Podman)
make lint              # No lint errors
make sast              # No new bandit findings
```

## Acceptance Criteria

1. `ContainerBackend.run()` executes the worker inside a Podman container with all security flags from the Container Security Policy table, including `--cpus=1.0`.
2. `ContainerBackend.is_available()` returns `True` when Podman is installed and `dcs-fuzz-python:latest` image exists; `False` otherwise.
3. `make build-fuzz-sandbox` builds the `dcs-fuzz-python:latest` image from `sandbox/Containerfile.fuzz-python`.
4. The `deep_scan_fuzz` MCP tool is registered when `ContainerBackend.is_available()` returns `True`.
5. The `deep_scan_fuzz` MCP tool rejects invocations when `consent=False`.
6. MCP fuzz runs use `ContainerBackend` exclusively (rlimit-only rejected for MCP).
7. CLI `dcs fuzz` continues to work with `SubprocessBackend` when Podman is not available.
8. No host environment variables (especially `ANTHROPIC_API_KEY`) leak into the container. The `env` parameter to `run()` is ignored; only `_ALLOWED_ENV_KEYS` with hardcoded values reach the container.
9. Container is destroyed after each fuzz input execution (no container accumulation).
10. All existing tests continue to pass (`make test`).
11. New unit tests achieve 90%+ coverage on the new code.
12. Integration tests pass on a system with Podman installed.
13. `deep_scan_fuzz_status` reports `container_backend_available: true` when the image is built.
14. CLAUDE.md is updated to remove the SD-01 limitation note, document the new Makefile target, document `DCS_CONTAINER_RUNTIME=docker` exclusion for fuzzer backend, and add `DCS_FUZZ_CONTAINER_IMAGE` env var.
15. A dedicated `sandbox/seccomp-fuzz-python.json` profile is created that blocks `open_by_handle_at`, `name_to_handle_at`, `process_vm_readv`, `process_vm_writev`, and `kcmp`.
16. Only the specific target module file is mounted into the container (not the parent directory). Sibling files are not exposed.
17. Host-side `output.json` validation rejects symlinks and oversized files.
18. The `ContainerBackend` is stateless -- no per-run state stored between `run()` calls. Safe for concurrent use.
19. Background fuzz thread lifecycle: exceptions set state to "failed", wall-clock timeout sets state to "timeout", eviction policy matches `_MAX_SESSION_SCANS` pattern.
20. The `functions` parameter in the MCP `deep_scan_fuzz` tool is validated via `validate_function_name()`.

## Task Breakdown

### Task 1: Container Image and Seccomp Profile

**Task 1.1: Create Containerfile**
- Create: `sandbox/Containerfile.fuzz-python`
  - Minimal single-stage build: copy only the required module files (no `pip install`).
  - Only standard library modules needed -- no third-party dependencies in the image.
  - Final image: `python:3.12-slim` base, no pip/setuptools, non-root user 65534.
  - Add `LABEL org.opencontainers.image.title="dcs-fuzz-python"` and `LABEL org.opencontainers.image.version="1.0.0"`.
  - Entrypoint: `["python", "-m", "deep_code_security.fuzzer.execution._worker"]` (args appended by ContainerBackend).
  - Working directory: `/workspace`.

**Task 1.2: Create fuzzer-specific seccomp profile**
- Create: `sandbox/seccomp-fuzz-python.json`
  - Copy `sandbox/seccomp-default.json` as the starting point.
  - Remove `open_by_handle_at`, `name_to_handle_at`, `process_vm_readv`, `process_vm_writev`, and `kcmp` from the allow list.
  - Add these five syscalls to the explicit block list with a comment explaining they are container escape or cross-process attack primitives.
  - Update the allow list comment from "Python 3.12, Go 1.22, and GCC C runtimes" to "Python 3.12 runtime (fuzzer-specific, restricted)".

**Task 1.3: Add Makefile target**
- Modify: `Makefile`
  - Add `build-fuzz-sandbox` target that runs `podman build -f sandbox/Containerfile.fuzz-python -t dcs-fuzz-python:latest .`
  - Do NOT modify the existing `build-sandboxes` target. The `build-fuzz-sandbox` target is standalone.

**Task 1.4: Verify image works**
- Manual verification: build the image and run `podman run --rm dcs-fuzz-python:latest --help` to confirm the worker module is importable.

### Task 2: ContainerBackend Implementation

**Task 2.1: Implement ContainerBackend class**
- Modify: `src/deep_code_security/fuzzer/execution/sandbox.py`
  - Replace the stub `ContainerBackend` class with the full Podman implementation.
  - Add `target_file` keyword argument to `run()` for single-file mount.
  - Add `**kwargs: Any` to `ExecutionBackend.run()` protocol and `SubprocessBackend.run()` (accepted, ignored).
  - Add `is_available()` method that checks for `podman` binary and image existence.
  - Add `_build_podman_cmd()` private method that constructs the full `podman run` command with all security flags.
  - The `run()` method ignores the `cmd` argument and constructs its own command using container-side paths.
  - The `run()` method ignores the `env` argument. Only `_ALLOWED_ENV_KEYS` with hardcoded values are passed to the container via `--env` flags.
  - Import `pathlib.Path`, `shutil.which`.
  - Ensure all subprocess calls use list-form arguments (no `shell=True`).
  - The seccomp profile path is resolved using the project structure: `Path(__file__).resolve().parent.parent.parent.parent / "sandbox" / "seccomp-fuzz-python.json"`. (The config module already uses a similar 4-level parent traversal for registry_path resolution from `shared/config.py`.)
  - Add `_ALLOWED_ENV_KEYS` frozenset: only `PYTHONPATH`, `PYTHONDONTWRITEBYTECODE`, `PYTHONSAFEPATH`.
  - Update `__all__` to export the updated classes.
  - Add host-side output validation: symlink check, size check on `output.json`.

**Task 2.2: Add backend selection function**
- Modify: `src/deep_code_security/fuzzer/execution/sandbox.py`
  - Add `select_backend(config, require_container=False) -> ExecutionBackend` function.
  - The function checks `config.container_runtime` and `config.fuzz_container_image`.
  - Update `__all__`.

**Task 2.3: Add container image config**
- Modify: `src/deep_code_security/shared/config.py`
  - Add `fuzz_container_image: str` attribute read from `DCS_FUZZ_CONTAINER_IMAGE` env var (default: `dcs-fuzz-python:latest`).

### Task 3: FuzzRunner and Plugin Integration

**Task 3.1: Update FuzzRunner for container backend**
- Modify: `src/deep_code_security/fuzzer/execution/runner.py`
  - Before calling `self._sandbox._backend.run()`, check if the backend is a `ContainerBackend` (via `isinstance`).
  - If so:
    - Rewrite `params["module_path"]` to the container-side path (`/target/<filename>`).
    - Pass `target_file=str(Path(module_path).resolve())` as a keyword argument to `run()`.
    - Set `collect_coverage=False` and skip coverage-related file paths (coverage inside containers is deferred).
  - Keep the existing subprocess path unchanged for `SubprocessBackend`.
  - After `run()` returns when using container backend, validate `output.json`: check it is not a symlink, check size bounds.

**Task 3.2: Add set_backend() to TargetPlugin**
- Modify: `src/deep_code_security/fuzzer/plugins/base.py`
  - Add `set_backend(self, backend: ExecutionBackend) -> None` method (raises `NotImplementedError` by default).
- Modify: `src/deep_code_security/fuzzer/plugins/python_target.py`
  - Implement `set_backend()`: creates a new `FuzzRunner(sandbox=SandboxManager(backend=backend))`.

**Task 3.3: Update FuzzOrchestrator for backend propagation**
- Modify: `src/deep_code_security/fuzzer/orchestrator.py`
  - Accept an optional `backend: ExecutionBackend | None` parameter in `__init__()`.
  - After `registry.get_plugin()`, call `plugin.set_backend(backend)` if backend is provided.
  - The MCP handler provides `ContainerBackend()`; CLI provides `None` (default SubprocessBackend).

### Task 4: MCP Integration

**Task 4.1: Register deep_scan_fuzz tool**
- Modify: `src/deep_code_security/mcp/server.py`
  - In `_register_tools()`, check if `ContainerBackend` is available.
  - If available, register `deep_scan_fuzz` with the schema from the existing TODO comment.
  - Uncomment and complete the tool registration code.

**Task 4.2: Implement _handle_fuzz()**
- Modify: `src/deep_code_security/mcp/server.py`
  - Replace the stub with a working handler.
  - Validate `path` via `validate_path()`.
  - Validate `functions` array elements via `validate_function_name()` from `input_validator.py`.
  - Require `consent=True` (reject with `ToolError` if `False`).
  - Construct `FuzzerConfig.from_dcs_config()` with MCP defaults (iterations=3, inputs_per_iteration=5, max_cost_usd=2.00).
  - Select backend with `require_container=True`.
  - Start `FuzzOrchestrator` in a background thread with `install_signal_handlers=False`.
  - Store `FuzzRunState` in a bounded `_fuzz_runs` dict keyed by `fuzz_run_id`.
  - Return `{"status": "running", "fuzz_run_id": "..."}`.
  - Implement wall-clock timeout via `threading.Timer` that sets `orchestrator._shutdown_requested = True` and updates run state to "timeout".
  - Background thread wraps orchestrator in `try/except/finally` to ensure status is always updated.
  - Validate all crash data in the response through `input_validator.py`.
  - Reject new fuzz requests when `_MAX_CONCURRENT_FUZZ_RUNS` active runs exist.

**Task 4.3: Extend _handle_fuzz_status()**
- Modify: `src/deep_code_security/mcp/server.py`
  - Update `container_backend_available` to be a runtime check via `ContainerBackend.is_available()`.
  - When `fuzz_run_id` is provided and matches a stored run, return progress or final results.
  - Add `FuzzRunState` class to track in-progress runs.

**Task 4.4: Add orphan container cleanup**
- Modify: `src/deep_code_security/mcp/server.py`
  - On server startup (in `_initialize()`), run a best-effort cleanup of orphaned containers: `podman rm -f $(podman ps -aq --filter label=dcs.fuzz_run_id)`.
  - Log a warning if cleanup fails (do not block startup).

**Task 4.5: Update CLAUDE.md**
- Modify: `CLAUDE.md`
  - Remove SD-01 limitation from "Known Limitations" section.
  - Update `deep_scan_fuzz` entry from "deferred" to "active (requires Podman + built image)".
  - Add `DCS_FUZZ_CONTAINER_IMAGE` to environment variables table.
  - Add `make build-fuzz-sandbox` to CLI commands table.
  - Update the `deep_scan_fuzz` MCP tool description.
  - Update the architecture diagram to show container backend.
  - Add a note to the `DCS_CONTAINER_RUNTIME` env var entry clarifying that `docker` is not supported for the fuzzer container backend (Podman only). The auditor backend is unaffected.
  - Add `sandbox/seccomp-fuzz-python.json` to the architecture description.

### Task 5: Unit Tests

**Task 5.1: Container backend unit tests**
- Create: `tests/test_fuzzer/test_execution/test_container_backend.py`
  - All 15 test cases listed in the Test Plan section.
  - Uses `unittest.mock.patch` to mock `subprocess.run` (no real Podman needed).

**Task 5.2: Backend selection unit tests**
- Create: `tests/test_fuzzer/test_execution/test_backend_selection.py`
  - All 4 test cases listed in the Test Plan section.

**Task 5.3: Path translation unit tests**
- Create: `tests/test_fuzzer/test_execution/test_path_translation.py`
  - All 2 test cases listed in the Test Plan section.

**Task 5.4: MCP fuzz tool unit tests**
- Create: `tests/test_mcp/test_fuzz_tool.py`
  - All 9 test cases listed in the Test Plan section.
  - Mocks `ContainerBackend.is_available()` and `FuzzOrchestrator.run()`.

### Task 6: Integration Tests

**Task 6.1: Container integration tests**
- Create: `tests/test_integration/test_fuzz_container.py`
  - All 11 test cases listed in the Test Plan section.
  - Guarded by `@pytest.mark.skipif(not _podman_available(), ...)`.
  - Uses the real `dcs-fuzz-python:latest` image (must be pre-built).
  - Includes a simple test fixture at `tests/fixtures/fuzz_targets/simple_target.py`.

**Task 6.2: Create test fixture**
- Create: `tests/fixtures/fuzz_targets/simple_target.py`
  - A minimal Python module with functions that exercise different container security boundaries (ValueError on negative, socket attempt, file write attempt, fork bomb, memory allocator, infinite loop).
- Create: `tests/fixtures/fuzz_targets/.env`
  - A dummy `.env` file with `SECRET_KEY=test-secret` to verify it is NOT accessible inside the container (used by `test_container_single_file_mount`).

### Task 7: Documentation and Cleanup

**Task 7.1: Update pyproject.toml**
- Modify: `pyproject.toml`
  - Add `sandbox/seccomp-fuzz-python.json` to package-data if needed.

**Task 7.2: Update merge-fuzzy-wuzzy plan (informational)**
- No modification. This plan supersedes the SD-01 resolution path documented in `plans/merge-fuzzy-wuzzy.md`. The SD-01 deviation is resolved, not amended.

## Trust Boundary Analysis

### New Trust Boundaries

1. **Host -> Container:** The Podman container is the primary trust boundary. The host provides input data (input.json) and target code (single-file read-only mount) to the container. The container returns output data (output.json) to the host. The container has no access to host filesystem beyond the explicitly mounted paths (one temp directory for IPC, one target file read-only), no network access, and no capability escalation.

2. **MCP Client -> MCP Server -> Container:** An MCP client can trigger fuzz runs via `deep_scan_fuzz`. The MCP server validates the path (via `validate_path()` against `DCS_ALLOWED_PATHS`), enforces consent, and delegates to the container backend. The container backend prevents the fuzz target from escaping the sandbox. Even if the fuzz target is malicious (e.g., a typosquatting attack on a dependency), it cannot:
   - Access the network (`--network=none`)
   - Read sibling files (single-file mount, not parent directory)
   - Read host files (`--read-only`, limited mounts)
   - Escalate privileges (`--cap-drop=ALL`, `--security-opt=no-new-privileges`)
   - Fork-bomb (`--pids-limit=64`)
   - OOM the host (`--memory=512m`)
   - Saturate CPU (`--cpus=1.0`)
   - Exploit container escape primitives (`open_by_handle_at`, `process_vm_readv` blocked by seccomp)

3. **Container -> Host via bind mount:** The `/workspace` mount is read-write (with `noexec,nosuid`) to allow the worker to write `output.json`. The worker writes JSON data that is then read and deserialized by `FuzzRunner` on the host. Before reading, the host validates that `output.json` is a regular file (not a symlink) and within size bounds. The deserialization uses `json.load()` which is safe (no code execution), and the data is validated through Pydantic models.

### Unchanged Trust Boundaries

- **AI API -> Worker (via expression strings):** Unchanged. The dual-layer AST validation (response_parser.py Layer 1 + _worker.py Layer 2) operates identically inside the container.
- **Corpus -> Worker (via replay):** Unchanged. Expression re-validation operates identically.
- **CLI -> Fuzzer:** Unchanged. CLI continues to use SubprocessBackend with rlimits.

## Input Validation Specification

### ContainerBackend Inputs

| Input | Source | Validation | Rejection Behavior |
|---|---|---|---|
| `cmd` (list[str]) | FuzzRunner (internal) | Accepted for protocol compatibility, IGNORED. | N/A |
| `timeout_seconds` | FuzzRunner (from FuzzerConfig) | Must be positive float, capped at 300s. Converted to int for Podman `--timeout` flag. | ValueError |
| `cwd` | SandboxManager.create_isolated_dir() (internal) | Must be an existing directory under system temp. | FileNotFoundError |
| `env` | FuzzRunner._build_env() (internal) | IGNORED. ContainerBackend constructs its own environment using only `_ALLOWED_ENV_KEYS` with hardcoded values. | N/A (silent ignore) |
| `target_file` (keyword arg) | FuzzRunner (from validated module_path) | Must be an existing regular file. Derived from the `validate_path()`-validated `module_path` (MCP flow) or from user-provided path (CLI flow). The parent of a validated path is necessarily within the allowed path tree; no additional denylist is applied. | ValueError if not a file |
| `output.json` (host-side read) | Container output via bind mount | Must be a regular file (not symlink: `Path.is_symlink()` must be `False`). Size must be <= 10MB. | ExecutionError |

### MCP deep_scan_fuzz Inputs

| Input | Source | Validation | Rejection Behavior |
|---|---|---|---|
| `path` | MCP client | `validate_path()` against `DCS_ALLOWED_PATHS` | ToolError (retryable=False) |
| `consent` | MCP client | Must be `True` | ToolError (retryable=False) |
| `functions` | MCP client | Each element validated via `validate_function_name()` from `input_validator.py` | ToolError (retryable=False) |
| `iterations` | MCP client | Integer, capped at 10 | Clamped silently |
| `inputs_per_iteration` | MCP client | Integer, capped at 10 | Clamped silently |
| `max_cost_usd` | MCP client | Float, capped at 5.00 | Clamped silently |
| `timeout_ms` | MCP client | Integer, capped at 10000 | Clamped silently |
| `model` | MCP client | String, validated against allowed model list | ToolError |

## Container Security Policy

This section consolidates the non-negotiable security requirements for the fuzzer container backend.

### Mandatory Flags (Never Omitted)

```
--network=none
--read-only
--cap-drop=ALL
--security-opt=no-new-privileges
--security-opt seccomp=<abs_path>/sandbox/seccomp-fuzz-python.json
--pids-limit=64
--memory=512m
--cpus=1.0
--user=65534:65534
--tmpfs /tmp:rw,noexec,nosuid,size=64m
--rm
```

### IPC Bind Mount (Required for JSON IPC)

```
--volume <host_cwd>:/workspace:rw,noexec,nosuid
```

This is a bind mount (not a tmpfs) because the host must write `input.json` before container start and read `output.json` after container exit. The `noexec,nosuid` mount options prevent execution of planted binaries. Host-side validation (symlink check, size check) provides defense-in-depth.

### Target File Mount (Single-File, Read-Only)

```
--volume <target_file>:/target/<filename>:ro
```

Only the specific target module file is mounted. The parent directory is NOT mounted. This prevents exposure of sibling files (.env, .git/config, *.pem, *.key, SSH keys, etc.).

### Validation in Code

The `_build_podman_cmd()` method constructs the command as a list. The security flags are hardcoded constants, not configurable. There is no mechanism to disable or override them. The method is tested by `test_container_backend_constructs_correct_podman_command` which asserts every flag is present.

### Seccomp Profile (Fuzzer-Specific)

The fuzzer uses `sandbox/seccomp-fuzz-python.json`, a dedicated profile that:
- Defaults to `SCMP_ACT_ERRNO` (deny-by-default).
- Allows syscalls required by Python 3.12 runtime.
- Explicitly blocks: `ptrace`, kernel module ops, `mount`/`umount`, `chroot`, `pivot_root`, namespace ops (`unshare`, `setns`), `bpf`, `perf_event_open`.
- Additionally blocks (compared to `seccomp-default.json`): `open_by_handle_at`, `name_to_handle_at` (container escape primitives), `process_vm_readv`, `process_vm_writev` (cross-process memory access), `kcmp` (kernel object comparison / info leak).

### What This Does NOT Protect Against

- Side-channel attacks (timing, cache) from within the container.
- Kernel exploits from within the container (mitigated by seccomp but not eliminated).
- Targets that require relative imports from sibling modules (will fail; use CLI for multi-file targets).

These are accepted residual risks, consistent with the auditor sandbox's threat model.

## Supply Chain Assessment

### New Dependencies

None. The container backend uses only the Python standard library (`subprocess`, `pathlib`, `shutil`, `json`, `tempfile`). Podman is a system dependency, not a Python package.

### Container Image Base

The `python:3.12-slim` base image is pulled from Docker Hub (or configured Podman registry). This is the same base used by millions of Python containers. The minimal file-copy approach (no `pip install`) eliminates all third-party package dependencies from the container image, minimizing attack surface.

### Existing Dependency Risk

The container image contains only the worker module files copied from source. No PyPI packages are installed:
- `_worker.py` imports only standard library modules and `expression_validator.py`.
- `expression_validator.py` imports only `ast` and `logging`.
- The `__init__.py` files are included for package structure but contain no imports that trigger third-party package loading.

The `anthropic` SDK, `pydantic`, `rich`, `coverage`, `tree-sitter`, and other project dependencies are NOT present in the container.

## Context Alignment

### CLAUDE.md Patterns Followed

1. **"All container operations enforce full security policy: seccomp + no-new-privileges + cap-drop=ALL"** -- The ContainerBackend hardcodes all security flags. This plan resolves the SD-01 deviation where the fuzzer previously violated this rule.
2. **"Never subprocess.run(shell=True)"** -- All Podman invocations use list-form arguments.
3. **"All subprocess calls use list-form arguments"** -- Enforced in `_build_podman_cmd()`.
4. **"Pydantic v2 for all data-crossing models"** -- No new data models cross boundaries; existing Pydantic models are unchanged.
5. **"Type hints on all public functions"** -- All new public methods have type hints.
6. **"pathlib.Path over os.path"** -- Used throughout the ContainerBackend.
7. **"90%+ test coverage required"** -- Test plan covers all new code paths.
8. **"`__all__` in `__init__.py` files"** -- Updated in sandbox.py.
9. **"All file paths validated through `mcp/path_validator.py` with DCS_ALLOWED_PATHS allowlist"** -- MCP flow validates `path` via `validate_path()`. The `target_file` mount path is derived from the validated path's resolution; no denylist-based validation is used.

### Prior Plans This Builds Upon

1. **`plans/merge-fuzzy-wuzzy.md` (APPROVED)** -- This plan resolves Security Deviation SD-01 defined in that plan. The SD-01 section explicitly states the resolution path: "Implement the `ContainerBackend` in `execution/sandbox.py`, reusing the DCS auditor's container security policy." This plan follows that path exactly.

2. **`plans/deep-code-security.md` (APPROVED)** -- The original architecture plan establishes the container security model (seccomp, no-new-privileges, cap-drop=ALL) and the MCP server design (native stdio, Docker CLI for sandbox containers). This plan extends the sandbox model to the fuzzer.

3. **`plans/output-formats.md` (APPROVED)** -- No direct dependency, but the formatter architecture is relevant: `deep_scan_fuzz` MCP responses will use the same serialization pattern as other MCP tools.

### Deviations from Established Patterns

1. **Podman-only (no Docker support for fuzzer backend).** The auditor sandbox and Makefile reference Docker. This plan uses Podman exclusively per the user's explicit request. Rationale: Podman is rootless-by-default, daemonless, and has identical CLI syntax to Docker. The `DCS_CONTAINER_RUNTIME` variable accepts "podman" and "auto" but not "docker" for the fuzzer backend. This is a deliberate narrowing of scope to avoid testing and maintaining two container runtimes for this specific feature. The auditor's container runtime is managed by the separate `dcs-verification` package and is unaffected. CLAUDE.md will be updated to document this restriction (Task 4.5).

2. **Coverage collection disabled in container runs.** The existing `FuzzRunner` collects `coverage.py` data for coverage-guided fuzzing. The container backend disables this because mounting coverage data files across container boundaries requires careful volume mount configuration that is deferred to a follow-up. Rationale: Coverage guidance improves input quality but is not required for crash discovery. Without coverage delta feedback, the AI engine relies on crash/no-crash signals only, reducing multi-iteration input diversity. The core value of the container backend is security isolation, not coverage enhancement. A follow-up plan will add coverage collection via a dedicated writable volume mount.

3. **`run()` method accepts and ignores `cmd` and `env` arguments.** The `ContainerBackend.run()` signature accepts `cmd` and `env` for `ExecutionBackend` protocol compatibility, but ignores both. It constructs its own command using container-side paths and its own minimal environment. This is explicitly documented in the docstring and tested. Rationale: The `ContainerBackend` is not a transparent subprocess wrapper -- it is a complete execution environment that controls all aspects of the Podman invocation. Accepting but ignoring these parameters preserves backward compatibility with `SubprocessBackend` callers.

4. **Single-file target mount (not parent directory).** The auditor mounts target directories with sensitive file exclusions. The fuzzer takes a more restrictive approach: mounting only the specific target file. This means targets with relative imports from sibling modules will fail inside the container. Rationale: The single-file approach is simpler to implement correctly and eliminates the entire class of sibling file exposure vulnerabilities. Users with multi-file targets can use the CLI (`dcs fuzz`) which uses `SubprocessBackend` without mount restrictions.

5. **Dedicated fuzzer seccomp profile.** The shared `seccomp-default.json` is designed for multi-language (Python/Go/C) support. The fuzzer creates its own `seccomp-fuzz-python.json` with additional blocked syscalls. The shared profile is not modified. Rationale: Principle of least privilege -- the fuzzer only needs Python 3.12 support and should not carry the broader attack surface of Go/C syscall allowances.

<!-- Context Metadata
discovered_at: 2026-03-15T09:56:29Z
claude_md_exists: true
recent_plans_consulted: plans/merge-fuzzy-wuzzy.md, plans/output-formats.md, plans/deep-code-security.md
archived_plans_consulted: plans/archive/merge-fuzzy-wuzzy/, plans/archive/output-formats/
-->
