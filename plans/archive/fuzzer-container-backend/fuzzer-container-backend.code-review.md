# Code Review: fuzzer-container-backend (Revision 2)

**Date:** 2026-03-15
**Reviewer:** code-reviewer agent
**Plan:** `plans/fuzzer-container-backend.md` (Status: APPROVED)
**Prior Review:** Revision 1 — Verdict: REVISION_NEEDED (3 Critical, 6 Major findings)

---

## Verdict: PASS

All three Critical findings and all six Major findings from the prior review have been resolved. No new Critical or Major issues were introduced by the revision. The implementation is ready to proceed.

---

## Status of Prior Critical Findings

### C-1: IPC workspace mount missing `noexec,nosuid` and wrong container-side path — FIXED

`sandbox.py` now mounts the IPC directory as `--volume={ipc_dir}:/workspace:rw,noexec,nosuid` (line 272). The container-side mount point is `/workspace`, matching the plan's architecture. The worker positional arguments are translated from host-side paths to container-side paths at lines 333–334:

```python
container_input_json = "/workspace/" + Path(input_json).name
container_output_json = "/workspace/" + Path(output_json).name
```

The host-side paths are never passed to the worker inside the container. The new unit tests `test_ipc_mount_uses_workspace_with_security_options` and `test_ipc_worker_args_use_container_side_paths` in `test_container_backend.py` verify both the mount point and the path translation. The fix is complete and correctly implemented.

### C-2: Wall-clock timeout marks state but does not stop the orchestrator — FIXED

The revision uses a mutable list `orchestrator_ref: list[Any] = [None]` as a shared container between the outer scope and the background thread's `_cancel_timeout` closure. The sequence is now:

1. `orchestrator_ref[0]` is set to `None` before the thread starts.
2. The background thread constructs `FuzzOrchestrator`, then publishes it to `orchestrator_ref[0] = orchestrator` before starting the timer.
3. The timer fires `_cancel_timeout`, which reads `orc = orchestrator_ref[0]` and, if non-None, sets `orc._shutdown_requested = True`.

This correctly signals the orchestrator to stop between iterations and between individual inputs. The timer is started after the orchestrator reference is published, eliminating the race where the timer could fire before `orchestrator_ref[0]` is populated. The fix fully resolves the cosmetic-only timeout enforcement.

### C-3: `collect_coverage=True` passed to all container-backend runs — FIXED

`orchestrator.py` line 215 now computes:

```python
collect_coverage = not isinstance(self._backend, ContainerBackend)
```

This sets `collect_coverage=False` for any run where the injected backend is a `ContainerBackend`, and `True` for `SubprocessBackend` runs. The fix is architecturally correct — the check is placed at the iteration level (before the per-input loop), so it evaluates once per iteration rather than once per input, which is the right granularity. The comment on line 213 explicitly documents the deferral reason, referencing the plan's SD-01.

---

## Status of Prior Major Findings

### M-1: `WORKDIR /workspace` missing from Containerfile — FIXED

`Containerfile.fuzz-python` now has `WORKDIR /workspace` at line 45, placed after the `ENV` directives and before the `USER` instruction, matching the plan's task 1.1 specification.

### M-2: `org.opencontainers.image.version` label missing — FIXED

`LABEL org.opencontainers.image.version="1.0.0"` is present at line 11 of `Containerfile.fuzz-python`, alongside the existing `title` and `description` labels.

### M-3: No enforcement of concurrent fuzz run limit — FIXED

`server.py` now defines `_MAX_CONCURRENT_FUZZ_RUNS: int = 2` as a module-level constant at line 40, and `_handle_fuzz` counts active running entries before creating a new one (lines 810–818). A `ToolError` with `retryable=False` is raised when the count reaches the limit. The test class `TestFuzzConcurrentRunLimit` in `test_fuzz_tool.py` verifies both the rejection case (2 active runs) and the acceptance case (1 active + 1 completed run, since completed runs do not count toward the limit).

### M-4: `_build_podman_cmd()` not extracted as a private method — FIXED

`ContainerBackend._build_podman_cmd()` is implemented as a fully-typed private method at lines 213–276 of `sandbox.py`, matching the signature specified in task 2.1: `_build_podman_cmd(self, target_file, ipc_dir, timeout_seconds, run_id) -> list[str]`. The docstring correctly describes all four parameters and the return type. `run()` delegates to it at lines 321–326 and handles the path translation separately.

### M-5: Timer never cancelled on normal completion — FIXED

`_run_fuzz()` now stores the timer reference in a local variable `timer` initialized to `None` (line 863), and the `finally` block at lines 914–919 calls `timer.cancel()` unconditionally on both the success and exception paths. The guard `if timer is not None` correctly handles the case where the exception occurs before `timer` is assigned (e.g., if `select_backend()` raises). This prevents timer accumulation under load.

### M-6: `podman ps -q` misses stopped containers in orphan cleanup — FIXED

`_cleanup_orphan_containers()` at line 104 now uses `["podman", "ps", "-aq", "--filter", "label=dcs.fuzz_run_id"]`, catching both running and stopped/exited containers from a previous server crash.

---

## New Issues Introduced by Revision

None found. The revision is surgical — each prior finding received a targeted fix with no collateral changes to unrelated code paths.

One point warrants mention as a design observation rather than a blocking finding:

**Timer start is deferred until after orchestrator construction.** The timer is started inside `_run_fuzz()` after `orchestrator_ref[0] = orchestrator` is set, which means there is a window between thread start and timer start where the `fuzz_mcp_timeout` clock is not ticking. This window covers `select_backend()`, `FuzzerConfig(...)`, and `FuzzOrchestrator(...)` construction — all fast operations in practice. This is a deliberate and documented trade-off (the comment on line 889 explains it) and is acceptable. The alternative of starting the timer before thread launch would require a second synchronization mechanism. The current approach is correct.

---

## Positives

The following positives from the prior review remain valid and are restated for completeness.

**Security policy is complete and correct.** Every flag from the plan's Container Security Policy table is present: `--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, seccomp profile, `--pids-limit=64`, `--memory=512m`, `--cpus=1.0`, `--user=65534:65534`, `--tmpfs` with `noexec,nosuid`, and `--rm`. This is the core deliverable of the plan and it was correct in the first review and remains correct.

**`_build_podman_cmd()` extraction improved readability and testability.** The command-building logic is now independently testable via `_capture_podman_cmd()` in the unit tests, which calls `backend.run()` and intercepts the built command. Each security flag is tested in isolation. The helper is clean.

**Concurrent run limit uses correct semantics.** Counting only `status == "running"` entries (not completed, failed, or timeout) is the right definition of "active." The test correctly validates that a completed entry in the store does not reduce the available slots for new runs.

**Coverage deferral is clearly communicated.** The `isinstance(self._backend, ContainerBackend)` check in `orchestrator.py` is self-documenting and the adjacent comment ties it to the plan's SD-01. Future work to enable container-side coverage collection has a clear insertion point.

**Host environment isolation is genuine.** No `--env` flags are ever constructed from the caller's environment. The `_ALLOWED_ENV_KEYS = frozenset()` documents this invariant.

**Single-file mount is correctly scoped.** The target file is mounted as `--volume={target_file}:/target/{target_basename}:ro`, not its parent directory. Sibling credential files are inaccessible to the worker.

**Output validation mitigates symlink attack.** The symlink check and 10 MB size cap on `output.json` are in place before `json.load()`. The new `test_output_json_symlink_rejected` test in `test_container_backend.py` verifies that a symlink planted by a malicious container causes `FuzzRunner.run()` to raise `ExecutionError`.

**No Automatic FAIL triggers present.** No `shell=True`, no `yaml.load()`, no Docker socket mount, no string formatting with finding data, no raw JSON injection at MCP boundaries. The static source assertion `test_no_shell_true` in the test suite would catch a regression.

**`deep_scan_fuzz` registration remains correctly gated.** Tool registration depends on `ContainerBackend.is_available()` at server startup. The `deep_scan_fuzz_status` tool always reports availability dynamically via a live call.

---

## Open Minor Findings (Carried Forward, Non-Blocking)

The following minor findings from the prior review were not addressed. None blocks a PASS.

**m-1: `_ALLOWED_ENV_KEYS` frozenset is empty.** The frozenset documents that no host keys are forwarded, which is correct. Aligning it with `{"PYTHONPATH", "PYTHONDONTWRITEBYTECODE", "PYTHONSAFEPATH"}` would match the plan spec and make the intent clearer if the forwarding code path is ever added. Not a functional issue.

**m-2: Single-stage Containerfile build leaves pip artifacts.** The `pip uninstall` approach does not remove all pip-installed metadata. A two-stage build would guarantee a clean final layer. Low risk given the read-only root filesystem and nobody user.

**m-3: `target_file` not validated against `DCS_ALLOWED_PATHS` inside the backend.** MCP callers enforce this upstream; CLI callers do not. Defense-in-depth check inside `ContainerBackend` would be consistent with the project's pattern.

**m-4: Integration test coverage is partial.** 3 of 11 planned integration tests are implemented. Network isolation, read-only filesystem write attempt, and ephemeral cleanup tests remain unimplemented. These are the highest-value missing tests.

**m-5: `FuzzRunState.result` is `dict | None` rather than a typed model.** A `TypedDict` for the summary structure would improve correctness guarantees.

**m-6: `test_run_ignores_env_parameter` assertion is ambiguous.** The `--env=KEY=VALUE` form would evade the startswith filter. The `"should-not-appear"` string search is the stronger assertion. Both are currently present; consolidating to only the string search would be more robust.
