# Code Review: fuzzer-container-backend

**Date:** 2026-03-15
**Reviewer:** code-reviewer agent
**Plan:** `plans/fuzzer-container-backend.md` (Status: APPROVED)

---

## Verdict: REVISION_NEEDED

The core security architecture is sound and the majority of hard requirements are implemented correctly. Three issues block a PASS: the IPC workspace mount is missing `noexec,nosuid` options and uses the wrong mount point (which also prevents the worker from finding its input file), the wall-clock timeout marks state but never signals the orchestrator to stop (leaving background threads running indefinitely after timeout), and the orchestrator unconditionally passes `collect_coverage=True` for container runs despite the plan explicitly deferring coverage collection inside containers.

---

## Critical Findings (must fix)

### C-1: IPC workspace mount missing `noexec,nosuid` and uses wrong container-side path

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/fuzzer/execution/sandbox.py`, line 293

The plan's Container Security Policy table (plan line 98) requires the workspace volume mount to use `:rw,noexec,nosuid` to prevent a malicious fuzz target from planting an executable binary or setuid file in the shared IPC directory. The implementation mounts the directory without these options:

```python
podman_cmd.extend([f"--volume={ipc_dir}:/ipc:rw"])
```

Beyond the missing mount options, the mount point itself is wrong: it mounts at `/ipc` inside the container, but the plan (lines 67, 254, 258) specifies the mount point is `/workspace` and the worker receives `/workspace/input.json` and `/workspace/output.json` as positional arguments. The implementation passes the host-side absolute paths for `input_json` and `output_json` as arguments (lines 299–300), which are host paths like `/tmp/dcs_fuzz_abc/input.json`. Inside the container, `/tmp/dcs_fuzz_abc/` does not exist — only `/ipc/` is mounted. The worker will fail to open its input file, and every container-backend run will silently return no output.

**Fix:** Change the IPC mount to `f"--volume={ipc_dir}:/workspace:rw,noexec,nosuid"`. Change the positional worker arguments to `/workspace/input.json` and `/workspace/output.json` rather than the host-side paths.

### C-2: Wall-clock timeout marks state but does not stop the orchestrator

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/mcp/server.py`, lines 871–888

The plan (line 375) specifies that the `threading.Timer` callback must set `orchestrator._shutdown_requested = True` to signal the orchestrator to stop between iterations. The implementation's `_cancel_timeout()` only updates `run_state.status`:

```python
def _cancel_timeout() -> None:
    if run_state.status == "running":
        run_state.status = "timeout"
        run_state.error = f"Fuzz run exceeded the {config.fuzz_mcp_timeout}s wall-clock timeout."
```

The `orchestrator` object is constructed inside `_run_fuzz()` after the timer is already started, so there is no reference to it in the outer closure. The background thread continues running `orchestrator.run()` — potentially for many more iterations, each with 30-second container executions bounded only by `--cpus=1.0` — long after the MCP tool has reported `"timeout"` to the client. This means the `DCS_FUZZ_MCP_TIMEOUT` enforcement is purely cosmetic; it changes what the client sees without actually bounding resource consumption.

**Fix:** Construct the orchestrator before starting the thread so the timer callback can reach it: move the `FuzzOrchestrator(...)` construction into the outer `_handle_fuzz()` scope and reference it in `_cancel_timeout` via closure. Then `_cancel_timeout` sets both `run_state.status = "timeout"` and `orchestrator._shutdown_requested = True`. The orchestrator already checks this flag between iterations (orchestrator.py lines 171–173) and between individual inputs (lines 212–214).

### C-3: `collect_coverage=True` passed to all container-backend runs — plan violation and runtime failure

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/fuzzer/orchestrator.py`, line 219

The plan explicitly defers coverage collection inside containers (plan line 21, risks section line 535, task 3.1 line 713): "Set `collect_coverage=False` and skip coverage-related file paths (coverage inside containers is deferred)." The orchestrator unconditionally passes `collect_coverage=True` to `plugin.execute()` for every input regardless of backend:

```python
result = plugin.execute(
    fuzz_input=fuzz_input,
    timeout_ms=config.timeout_ms,
    collect_coverage=True,
)
```

When `collect_coverage=True`, `FuzzRunner.run()` writes a host-side `.coverage` path into `input.json`. The worker inside the container receives this path and attempts to write coverage data there. The container has a read-only root filesystem and a restricted tmpfs — it cannot write to an arbitrary host-side path. The coverage write will fail, polluting `stderr`, and may interfere with correct output parsing. The `FuzzRunner` detects `using_container` correctly for path translation but does not override `collect_coverage`.

**Fix:** In `FuzzRunner.run()`, when `using_container` is `True`, force `collect_coverage` to `False` and set `coverage_data_path` to `""` before writing `input.json`. This matches the pattern already used in the path-translation branch and is what task 3.1 required.

---

## Major Findings (should fix)

### M-1: `WORKDIR /workspace` missing from Containerfile

**File:** `/Users/imurphy/projects/deep-code-security/sandbox/Containerfile.fuzz-python`

Task 1.1 (plan line 659) requires `WORKDIR /workspace`. The Containerfile omits it. The plan's architecture (line 258) and the workspace mount section both assume the container working directory is `/workspace`. Without `WORKDIR`, the container starts in the image default (the Python slim base uses `/`). Any relative-path assumption in the worker resolves against the wrong directory.

**Fix:** Add `WORKDIR /workspace` between the `ENV` lines and the `ENTRYPOINT` line.

### M-2: `org.opencontainers.image.version` label missing from Containerfile

**File:** `/Users/imurphy/projects/deep-code-security/sandbox/Containerfile.fuzz-python`

Task 1.1 (plan line 658) requires `LABEL org.opencontainers.image.version="1.0.0"`. The Containerfile has `title` and `description` labels but not `version`. The plan's risk table (line 537) calls out version labels as needed for auditing when the image grows stale.

**Fix:** Add `LABEL org.opencontainers.image.version="1.0.0"` alongside the existing labels.

### M-3: No enforcement of concurrent fuzz run limit

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/mcp/server.py`

The plan (risk table line 539, task 4.2 line 751) specifies: "The MCP handler rejects new fuzz requests when `_MAX_CONCURRENT_FUZZ_RUNS` (default: 2) active runs exist." The implementation uses `_MAX_FUZZ_RUNS = 100` as the total state-store bound and evicts completed entries when full. There is no check on the count of currently `"running"` entries before starting a new thread. An adversary or misconfigured client can trigger many simultaneous container-backed fuzz runs, each consuming up to 1 CPU and 512 MB RAM, with the only bound being the state-store size of 100.

**Fix:** Before creating the background thread, count `sum(1 for rs in self._fuzz_runs.values() if rs.status == "running")` and raise `ToolError` with `retryable=False` if the count reaches a hard limit (the plan suggests 2). Define `_MAX_CONCURRENT_FUZZ_RUNS: int = 2` as a class constant alongside `_MAX_FUZZ_RUNS`.

### M-4: `_build_podman_cmd()` not extracted as a private method

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/fuzzer/execution/sandbox.py`

Task 2.1 (plan line 685) explicitly requires a `_build_podman_cmd()` private method. The entire command is built inline in `run()`, interleaved with the optional `ipc_dir` extension and the subprocess invocation. This makes the method harder to unit-test in isolation and harder to reason about. The existing test `test_run_builds_correct_podman_command` works around this by mocking `subprocess.run`, which is functional but couples the test to the full execution path.

**Fix:** Extract command construction into `_build_podman_cmd(self, target_file: str, ipc_dir: str | None, timeout_seconds: float, run_id: str) -> list[str]` as specified.

### M-5: Wall-clock timeout timer is never cancelled on normal completion

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/mcp/server.py`, lines 884–888

The `timeout_timer` is started unconditionally and has no cancellation on the success or failure paths of `_run_fuzz()`. After a fuzz run completes normally (setting `run_state.status = "completed"`), the timer daemon thread continues running until it fires. The `_cancel_timeout` callback correctly checks `if run_state.status == "running"` before overwriting, so the "completed" status is preserved. However, the live timer holds a closure reference to `run_state` and `orchestrator` (once C-2 is fixed), preventing garbage collection for up to `DCS_FUZZ_MCP_TIMEOUT` seconds (default 120s) per completed run. Under load, this accumulates.

**Fix:** Store the timer reference and call `timeout_timer.cancel()` in both the success and exception paths of `_run_fuzz()` before the thread exits.

### M-6: `podman ps -q` in orphan cleanup misses stopped containers

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/mcp/server.py`, lines 102–103

The orphan cleanup uses `podman ps -q --filter label=dcs.fuzz_run_id`, which only lists running containers. The plan (line 377) specifies `podman ps -aq` to also catch stopped (exited) containers that were not removed — for example, if the server crashed before `--rm` could process the container exit. These exited containers will accumulate on disk.

**Fix:** Change `"ps", "-q"` to `"ps", "-aq"`.

---

## Minor Findings (optional)

### m-1: `_ALLOWED_ENV_KEYS` frozenset is empty but the plan specifies three entries

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/fuzzer/execution/sandbox.py`, line 141

The class attribute `_ALLOWED_ENV_KEYS: frozenset[str] = frozenset()` is empty. The plan and the class docstring state the container gets `PYTHONPATH=/target`, `PYTHONDONTWRITEBYTECODE=1`, and `PYTHONSAFEPATH=1`. These are correctly baked into the Containerfile `ENV` directives, so isolation is not broken. But `_ALLOWED_ENV_KEYS` is documented as the allowlist governing which keys may be forwarded — if `run()` is ever extended to forward keys using this frozenset as a filter, it would forward nothing. Aligning the frozenset with the plan spec prevents future confusion.

**Fix:** Set `_ALLOWED_ENV_KEYS = frozenset({"PYTHONPATH", "PYTHONDONTWRITEBYTECODE", "PYTHONSAFEPATH"})`.

### m-2: Containerfile uses single-stage build, leaving potential pip artifacts

**File:** `/Users/imurphy/projects/deep-code-security/sandbox/Containerfile.fuzz-python`, line 16

The plan specifies "No pip, setuptools, or build tools in the final image." The single-stage build installs the `coverage` package with pip, then attempts `pip uninstall -y pip setuptools wheel`. This does not remove what the `python:3.12-slim` base image ships (pkg_resources, distutils). A two-stage build (`FROM python:3.12-slim AS builder` / `FROM python:3.12-slim AS runtime`) would guarantee a clean final layer. This is a defense-in-depth concern rather than a functional bug, since the worker runs as nobody with a read-only root filesystem.

### m-3: `target_file` path not validated against `DCS_ALLOWED_PATHS` inside the backend

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/fuzzer/execution/sandbox.py`, lines 249–285

`target_file` is resolved with `Path(target_file).resolve()` but is not checked against `DCS_ALLOWED_PATHS`. For MCP invocations the allowlist is enforced upstream by `validate_path()` in `_handle_fuzz()`, so the current trust boundary is correct. For direct `ContainerBackend.run()` calls (unit tests, future integrations), no allowlist check occurs inside the backend. Adding a defense-in-depth check inside the backend would follow the project's pattern of enforcing allowlists at the boundary closest to the filesystem operation.

### m-4: Integration test coverage is partial — 3 of 11 planned tests implemented

**File:** `/Users/imurphy/projects/deep-code-security/tests/test_integration/test_fuzz_container.py`

The plan specifies 11 integration test cases (plan lines 601–611). The file implements 3: `test_container_executes_worker`, `test_container_no_host_env_leakage`, and `test_container_single_file_mount`. Missing are: network isolation (`socket.connect()` attempt), read-only root filesystem (`open("/etc/passwd", "w")`), PID limit enforcement, memory limit enforcement, ephemeral cleanup (`podman ps -a` after run), timeout kill, CPU limit, and container escape primitive blocking (`open_by_handle_at` via seccomp). The network isolation and read-only filesystem tests are the most valuable for validating the security policy.

### m-5: `FuzzRunState.result` is typed as `dict | None` rather than a typed model

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/mcp/server.py`, line 48

The plan defined `report: FuzzReport | None`. The implementation stores a summary `dict` instead, which is intentional (the full `FuzzReport` is not directly JSON-serializable). A `TypedDict` for the summary structure would improve correctness guarantees for the polling response.

### m-6: Unit test `test_run_ignores_env_parameter` assertion is ambiguous

**File:** `/Users/imurphy/projects/deep-code-security/tests/test_fuzzer/test_execution/test_container_backend.py`, lines 137–142

The test checks `not env_flags` where `env_flags` filters on args starting with `--env` or `-e`. This would miss an `--env=KEY=VALUE` form if the implementation ever switched to that style. The check on the full command string for `"should-not-appear"` is the stronger assertion and is correct. Consider consolidating to only the string search for robustness.

---

## Positives

**Security policy is faithfully enforced.** Every flag from the plan's Container Security Policy table appears in `ContainerBackend.run()`: `--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, seccomp profile, `--pids-limit=64`, `--memory=512m`, `--cpus=1.0`, `--user=65534:65534`, `--tmpfs` with `noexec,nosuid`, and `--rm`. This is the core security deliverable of the plan and it is correct.

**Host environment isolation is genuine.** The `env` parameter to `run()` is truly ignored — no `--env` flags are constructed from the caller's environment. The `_ALLOWED_ENV_KEYS = frozenset()` makes this unambiguous at the code level. The integration test `test_container_no_host_env_leakage` confirms this with an `ANTHROPIC_API_KEY` canary.

**Single-file mount is correctly scoped.** `f"--volume={target_file}:/target/{target_basename}:ro"` mounts exactly the named file, not its parent directory. Sibling files (`.env`, `.git/config`, credential files) are inaccessible to the worker. The unit test `test_run_mounts_single_file_only` verifies this with a sibling file present in the same directory.

**Seccomp profile is correctly implemented.** `sandbox/seccomp-fuzz-python.json` has `defaultAction: SCMP_ACT_ERRNO` (deny-by-default) and contains all five syscalls the plan requires in the explicit block list with `SCMP_ACT_ERRNO`: `open_by_handle_at`, `name_to_handle_at`, `process_vm_readv`, `process_vm_writev`, and `kcmp`. The shared `seccomp-default.json` is unchanged.

**Stateless backend design is correctly implemented.** All per-run state (mount paths, target file, run ID) is passed as arguments to `run()`. No shared mutable state exists between calls. This makes `ContainerBackend` safe for concurrent use without locking, which was the TOCTOU resolution the plan called for.

**Output validation is correctly implemented.** The symlink check (`output_path.is_symlink()`) and 10 MB size check on `output.json` are present in `FuzzRunner.run()` (lines 122–125) before `json.load()` is called. This mitigates a compromised container planting a symlink to redirect the host to read an arbitrary file.

**Backend injection chain is complete.** `TargetPlugin.set_backend()` is abstract in `base.py`, `PythonTargetPlugin` implements it by replacing `_runner._sandbox._backend`, and `FuzzOrchestrator` injects the backend after `registry.get_plugin()`. The injection flows correctly from the MCP handler through to the runner.

**`deep_scan_fuzz` registration is correctly gated.** The tool is only registered when `ContainerBackend.is_available()` returns `True` at server startup, directly resolving SD-01. The `deep_scan_fuzz_status` tool always reports `container_backend_available` dynamically via a live call to `is_available()`.

**Consent and input validation are correctly enforced.** The `_handle_fuzz()` handler checks `consent` before any path resolution or thread creation. `validate_function_name()` is called on every element of the `functions` array. The validated `target_path` (not the raw input) is used in `FuzzerConfig`.

**Unit test coverage for the backend is thorough.** `test_container_backend.py` verifies each security flag individually, checks env isolation (no `--env` flags for `SECRET`), verifies single-file mounting, covers `is_available()` in three states, and includes a static source-level assertion that `shell=True` does not appear in `sandbox.py`. `test_backend_selection.py` and `test_path_translation.py` cleanly cover the selection and path-rewriting logic.

**No Automatic FAIL triggers present.** All subprocess calls use list-form arguments. No `shell=True` anywhere in the new code. No `yaml.load()`. No Docker socket mount. No string formatting with finding data. No raw JSON injection at MCP boundaries.

---

## Summary of Changes Required

| ID | File | Change |
|----|------|--------|
| C-1 | `sandbox.py` | Add `noexec,nosuid` to IPC mount; change mount point from `/ipc` to `/workspace`; pass `/workspace/input.json` and `/workspace/output.json` as worker args |
| C-2 | `server.py` | Construct orchestrator before starting thread; have `_cancel_timeout` set `orchestrator._shutdown_requested = True` |
| C-3 | `runner.py` | Force `collect_coverage=False` and `coverage_data_path=""` when `using_container` is `True` |
| M-1 | `Containerfile.fuzz-python` | Add `WORKDIR /workspace` |
| M-2 | `Containerfile.fuzz-python` | Add `LABEL org.opencontainers.image.version="1.0.0"` |
| M-3 | `server.py` | Reject new fuzz requests when concurrent `"running"` count exceeds `_MAX_CONCURRENT_FUZZ_RUNS` (default: 2) |
| M-4 | `sandbox.py` | Extract `_build_podman_cmd()` private method as specified in task 2.1 |
| M-5 | `server.py` | Call `timeout_timer.cancel()` in success and exception paths of `_run_fuzz()` |
| M-6 | `server.py` | Change `ps -q` to `ps -aq` in orphan cleanup |
