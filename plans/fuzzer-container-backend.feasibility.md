# Feasibility Review: Podman Container Backend for Fuzzer Sandbox (Re-Review)

**Plan:** `./plans/fuzzer-container-backend.md`
**Reviewer:** code-reviewer agent
**Date:** 2026-03-15
**Review round:** 2 (re-review after revision)
**Previous verdict:** REVISION_NEEDED
**Current verdict:** PASS

## Executive Summary

The revised plan addresses all three critical issues and all five major concerns from the
initial review. The path translation gap is resolved with a clear `FuzzRunner`-side
rewrite of `module_path` and a `ContainerBackend` that ignores the `cmd` argument entirely.
The security policy table is now internally consistent with the `podman run` command. The
stateful `configure_mounts()` pattern is eliminated in favor of a stateless `run()` method
with `target_file` passed as a keyword argument. Backend injection through the plugin
registry uses the `set_backend()` method recommended in the initial review. The MCP
background thread lifecycle is fully specified with `FuzzRunState`, eviction, and
cancellation via `_shutdown_requested`.

The plan is ready for implementation. Two new minor concerns are noted below, neither of
which block implementation.

---

## Previously Identified Issues -- Resolution Status

### Critical Issues (all resolved)

| ID | Issue | Status | How Resolved |
|----|-------|--------|--------------|
| C-1 | `module_path` in `input.json` is a host-side path invalid inside container | **Resolved** | Plan section "Path Translation (Host-to-Container)" (lines 61-80) specifies that `FuzzRunner` rewrites `params["module_path"]` to `/target/<filename>` when using `ContainerBackend`, via `isinstance` check. The code snippet at lines 72-78 matches the recommendation exactly. The container-side path `/target/<filename>` is consistent with the single-file bind mount at `--volume <target_file>:/target/<filename>:ro`. |
| C-2 | `cmd` argument contains host-side paths meaningless inside container | **Resolved** | Plan section "Path Translation" (line 67) and the `ContainerBackend.run()` docstring (lines 207-231) explicitly state that the `cmd` argument is accepted for protocol compatibility but **ignored**. The `ContainerBackend` constructs its own command using hardcoded container-side paths (`/workspace/input.json`, `/workspace/output.json`). The entrypoint from the Dockerfile handles the Python executable. Test case `test_container_backend_cmd_ignored` (line 567) verifies this. |
| C-3 | Security policy table contradicts the `podman run` command (`--tmpfs /workspace` vs `--volume /workspace`) | **Resolved** | The security policy table (line 98) now reads `--volume <host_cwd>:/workspace:rw,noexec,nosuid` which matches the `podman run` command (line 247). The Mandatory Flags section (lines 891-893) also uses the bind mount. The `--tmpfs` is now correctly limited to `/tmp` only (line 97). The `noexec,nosuid` mount options were added as recommended. |

### Major Issues (all resolved)

| ID | Issue | Status | How Resolved |
|----|-------|--------|--------------|
| M-1 | `configure_mounts()` introduces statefulness and TOCTOU race | **Resolved** | The `configure_mounts()` pattern is completely eliminated. Section "Stateless Backend Design (TOCTOU Resolution)" (lines 264-312) describes the replacement: `target_file` is passed as a keyword argument directly to `run()`. The `ExecutionBackend` protocol gains `**kwargs: Any` and `SubprocessBackend` ignores them. No per-run state is stored between calls. The plan explicitly states this is safe for concurrent use (line 268). Acceptance criterion 18 (line 645) verifies this. |
| M-2 | No path traversal validation on `target_module_dir` | **Resolved** | The revised plan changes from mounting the target *directory* to mounting a single *file* (line 99: `--volume <target_file>:/target/<filename>:ro`). The Input Validation Specification (line 853) documents that `target_file` must be an existing regular file. For the MCP flow, `target_file` is derived from a path that has already passed `validate_path()` against `DCS_ALLOWED_PATHS`, which performs symlink resolution, `..` rejection, and allowlist checking. The plan correctly notes (line 853) that the parent of a validated path is necessarily within the allowed path tree. The single-file mount also eliminates the sibling-file exposure class entirely. |
| M-3 | Missing `--cpus` flag for CPU exhaustion | **Resolved** | `--cpus=1.0` is now present in the security policy table (line 95), the `podman run` command (line 244), the Mandatory Flags section (line 883), the `__init__` parameter list (line 190), and has a dedicated unit test `test_container_backend_cpus_flag` (line 569) and integration test `test_container_cpu_limit` (line 611). |
| M-4 | No mechanism for backend injection through plugin registry | **Resolved** | Section "Backend Injection Through Plugin Registry" (lines 314-341) specifies the `set_backend()` approach recommended in the initial review. The `TargetPlugin` base class gets an abstract `set_backend()` method. `PythonTargetPlugin` implements it by constructing a new `FuzzRunner` with the injected backend. `FuzzOrchestrator` calls it after `registry.get_plugin()`. Tasks 3.2 and 3.3 (lines 717-727) match. |
| M-5 | MCP background thread lifecycle under-specified | **Resolved** | The revised plan fully specifies: (1) `FuzzRunState` model with fields `fuzz_run_id`, `status`, `started_at`, `report`, `error` (lines 384-391). (2) Background thread wrapper with `try/except/finally` that always sets status (lines 358-373). (3) Cancellation via `threading.Timer` setting `orchestrator._shutdown_requested = True` (lines 375). (4) State eviction with bounded dict matching `_MAX_SESSION_SCANS` pattern (line 379). (5) Orphan container cleanup on startup via label filter (line 377). (6) `_MAX_CONCURRENT_FUZZ_RUNS` concurrency limit (line 751). Test cases cover exception-to-failed transition (line 594) and eviction (line 593). |

### Minor Issues (all addressed or acknowledged)

| ID | Issue | Status | How Addressed |
|----|-------|--------|---------------|
| m-1 | Pydantic dependency in container image unnecessary | **Resolved** | The revised plan adopts the minimal file-copy approach (lines 141-154). No `pip install`, no third-party dependencies. The Dockerfile copies only the 6 required module files. Lines 158 and 936-941 confirm this. |
| m-2 | `--timeout` float-to-int conversion | **Resolved** | Line 260 specifies `int(timeout_seconds) + 5` explicitly, with the parenthetical "(integer conversion via `int()` since Podman requires an unsigned integer)". |
| m-3 | `socket` syscalls blocked, `multiprocessing` targets will fail | **Resolved** | The Risks table entry (line 536) now explicitly states "Targets using `multiprocessing` will also fail because `socket` syscalls are blocked by the profile." |
| m-4 | `self._python` is host Python path, not container Python | **Resolved** | Subsumed by C-2 resolution. The `ContainerBackend` ignores `cmd` entirely and uses the container's entrypoint (`python -m ...` from the Dockerfile). |
| m-5 | `build-sandboxes` Makefile backward compatibility | **Resolved** | Non-Goals (line 24) and Task 1.3 (lines 669-672) explicitly state the new `build-fuzz-sandbox` target is standalone and does NOT modify the existing `build-sandboxes` target. |
| m-6 | No image version pinning or staleness detection | **Acknowledged** | The plan adds labels for manual auditing (lines 160, 658) but `is_available()` still only checks existence. The Risks table (line 537) acknowledges this as low-likelihood/low-impact with the `build-fuzz-sandbox` rebuild as mitigation. This is acceptable for v1 -- a version match warning can be added as a follow-up without design changes. |

---

## New Concerns

### Minor Issues (new)

#### n-1: `FuzzRunState` is not a Pydantic model despite holding data that crosses the MCP boundary

**Location:** Lines 384-391

The `FuzzRunState` is defined as a plain class (no `BaseModel` shown), but it holds a
`FuzzReport` that is serialized into the `deep_scan_fuzz_status` MCP response. CLAUDE.md
requires "Pydantic v2 for all data-crossing models."

However, `FuzzRunState` itself is an internal server-side tracking object (similar to
`_findings_session` which uses `OrderedDict`, not Pydantic). The `FuzzReport` it contains
is already a Pydantic model. The `FuzzRunState` does not serialize itself -- the handler
extracts fields from it into a JSON response dict. So this is consistent with the existing
pattern, but it should be clarified whether `FuzzRunState` is a Pydantic `BaseModel`, a
plain `dataclass`, or a plain class with attributes.

**Recommendation:** Use `dataclasses.dataclass` to get `__init__` and `__repr__` for free
without the Pydantic import overhead. Add a `# Internal tracking only, not serialized`
comment.

**Impact:** None on functionality or security. Style/consistency only.

#### n-2: `thread` attribute missing from `FuzzRunState` model definition

**Location:** Lines 384-391

The initial review recommended including a `thread: threading.Thread` field (excluded from
serialization) in `FuzzRunState` so the MCP server can track running threads for cleanup.
The revised plan defines `FuzzRunState` without a `thread` field. The plan does describe
the thread lifecycle (lines 358-378), but there is no mechanism for the server to join or
reference the thread after creation.

This matters for two scenarios:
1. **Server shutdown:** Without a reference to the thread, the server cannot join running
   fuzz threads during graceful shutdown.
2. **Status reporting:** The `_handle_fuzz_status()` handler cannot check if the thread is
   still alive (to detect threads that silently died without updating status).

**Recommendation:** Add a `_thread` field (private, not serialized) to `FuzzRunState`, or
maintain a separate `_fuzz_threads: dict[str, threading.Thread]` dict in the server. The
implementation can decide which, but the plan should acknowledge thread reference tracking
is needed for cleanup.

**Impact:** Low. The `finally` block in `_fuzz_thread()` (lines 370-372) ensures status
is always updated even if the thread dies unexpectedly. The orphan container cleanup on
startup (line 377) handles the container-level residue from ungraceful shutdowns. The
thread reference is primarily useful for diagnostics.

#### n-3: Single-file mount prevents targets that import from their own package

**Location:** Lines 534, 974

The plan acknowledges this limitation clearly in the Risks table and the Deviations section
(deviation 4). The trade-off (security over convenience) is explicitly justified. However,
the failure mode for users is not well-specified. When a target module does
`from . import helper` or `import mypackage.utils`, the worker will raise an `ImportError`
that surfaces as a "crash" in the fuzz results.

This could produce false positive crashes: the fuzz report would show many `ImportError`
crashes that are not bugs in the target code, polluting the crash corpus. The AI engine
would then see these crashes and potentially adjust its input generation strategy
(incorrectly) based on false signals.

**Recommendation:** Consider adding a note that `ImportError` crashes from relative
imports should be filtered or flagged differently in the fuzz report. Alternatively, the
MCP handler could check whether the target file uses relative imports (a simple `grep` for
`from . import` or `from .` patterns) and warn the user before starting the fuzz run.
This is not required for v1 but would improve user experience.

**Impact:** Low. Users encountering this will see clear `ImportError` messages and can
switch to CLI mode. The trade-off is correctly prioritized.

#### n-4: `PYTHONPATH=/target` inside the container may conflict with the single-file mount

**Location:** Lines 249, 262

The `podman run` command sets `--env PYTHONPATH=/target`, and the target file is mounted
at `/target/<filename>:ro`. The Dockerfile also sets `ENV PYTHONPATH=/app` (line 150) for
the worker module itself.

Inside the container, the effective `PYTHONPATH` will be `/target` (overriding the
Dockerfile's `/app`). This means the worker module at `/app/deep_code_security/...` will
not be importable via `PYTHONPATH` -- it relies on the Dockerfile's `ENV PYTHONPATH=/app`.

Podman's `--env` flag overrides the Dockerfile's `ENV` directive. The worker needs
`PYTHONPATH=/app` (or the `WORKDIR` to include `/app`) to find its own package. With
`PYTHONPATH=/target`, the worker's `python -m deep_code_security.fuzzer.execution._worker`
invocation will fail because Python cannot find the `deep_code_security` package.

**Resolution approach:** Use `--env PYTHONPATH=/app:/target` to include both the worker
package path and the target module path. The Dockerfile should set `/app` in `PYTHONPATH`
as a baseline, and the `ContainerBackend` should append `/target` rather than overriding.

**Impact:** This is a functional correctness issue. The worker will fail to start if
`PYTHONPATH` does not include `/app`. However, the fix is trivial (one-character change:
`PYTHONPATH=/app:/target` instead of `PYTHONPATH=/target`) and does not require design
changes.

**Severity:** This is borderline major (it would cause runtime failure) but the fix is
mechanical and the plan's intent is clear. Flagging it as minor because the implementer
will immediately notice this during Task 1.4 (manual verification) and the fix is
self-evident.

---

## Security Assessment

The revised plan's security posture is strong. Specific observations:

1. **Environment variable stripping is correct.** The `_ALLOWED_ENV_KEYS` frozenset
   (line 177) is restrictive: only `PYTHONPATH`, `PYTHONDONTWRITEBYTECODE`, and
   `PYTHONSAFEPATH`. The `run()` docstring (lines 213-216) explicitly states `env` is
   ignored and the backend constructs its own environment with hardcoded values. This
   prevents `ANTHROPIC_API_KEY`, `HOME`, `PATH`, `AWS_*`, `GOOGLE_*` leakage. Integration
   test `test_container_no_host_env_leakage` (line 605) verifies this.

2. **Single-file mount is the correct security trade-off.** Mounting only the target file
   (not the parent directory) eliminates the entire class of sibling-file exposure
   vulnerabilities. The plan explicitly accepts the convenience trade-off (targets with
   relative imports must use CLI). This is a stronger security posture than the auditor's
   directory mount approach and is appropriate for the MCP trust boundary where the target
   code is less controlled.

3. **Host-side output validation is well-specified.** The symlink check, size check, and
   unexpected file warning (lines 103-111) provide defense-in-depth against a malicious
   target manipulating the bind-mounted workspace. The `output.json` is deserialized via
   `json.load()` (safe, no code execution) and validated through Pydantic models.

4. **Seccomp profile separation is correct.** Creating a dedicated `seccomp-fuzz-python.json`
   that is more restrictive than `seccomp-default.json` follows least privilege. The five
   additional blocked syscalls (`open_by_handle_at`, `name_to_handle_at`, `process_vm_readv`,
   `process_vm_writev`, `kcmp`) are well-justified container escape and cross-process
   attack primitives. Not modifying the shared profile avoids auditor regression.

5. **Stateless `run()` eliminates the TOCTOU race.** The original `configure_mounts()`/`run()`
   two-step pattern created a window where concurrent threads could overwrite mount config.
   The revised design passes `target_file` as a keyword argument to `run()`, making each
   invocation self-contained. This is the cleanest resolution of the three options
   recommended in the initial review.

6. **MCP consent enforcement is consistent.** The `deep_scan_fuzz` tool requires
   `consent=True` (line 742) matching the CLI consent model. The `require_container=True`
   flag (line 744) prevents the MCP handler from falling back to `SubprocessBackend`.

7. **Concurrency is bounded.** `_MAX_CONCURRENT_FUZZ_RUNS` (line 751) limits parallel
   fuzz runs, and `--cpus=1.0` per container bounds per-container CPU usage. Combined
   with `--memory=512m` and `--pids-limit=64`, the host resource exposure from concurrent
   MCP fuzz requests is predictable.

---

## Implementation Complexity Assessment

| Task | Estimated Complexity | Notes |
|------|---------------------|-------|
| Task 1 (Image + seccomp) | Low | Straightforward Dockerfile and JSON profile. Manual verification step (1.4) catches issues early. |
| Task 2 (ContainerBackend) | Medium | Core implementation. The `_build_podman_cmd()` method is the critical path -- must include all security flags. The stateless `run()` design simplifies implementation vs. the original `configure_mounts()` approach. Fix `PYTHONPATH` to include both `/app` and `/target`. |
| Task 3 (FuzzRunner + Plugin) | Medium | `isinstance` check in `FuzzRunner.run()` to branch on backend type. `set_backend()` on `TargetPlugin` is straightforward. Key risk: ensuring `collect_coverage=False` is correctly propagated for container runs. |
| Task 4 (MCP integration) | High | Background thread lifecycle, `FuzzRunState` management, eviction, wall-clock timeout, orphan cleanup, and conditional tool registration. This is the most complex task and most likely to need iteration during implementation. |
| Tasks 5-7 (Tests + docs) | Medium | 30+ test cases across 6 files. Integration tests require pre-built image and Podman. |

Total estimated implementation effort: 3-4 days for an engineer familiar with the codebase.
The plan's task breakdown is realistic. The highest risk is Task 4 (MCP integration)
because it combines async MCP handlers, background threads, shared mutable state (run
tracking dict), and timer-based cancellation.

---

## Backward Compatibility Assessment

No breaking changes identified:

1. **`ExecutionBackend` protocol:** Gains `**kwargs: Any` in `run()`. Existing
   `SubprocessBackend` callers are unaffected (they do not pass kwargs).
2. **`TargetPlugin` base class:** Gains `set_backend()` method (raises
   `NotImplementedError` by default). Third-party plugins that do not override it will
   raise an error only if someone tries to inject a backend, which is an intentional
   failure mode.
3. **CLI `dcs fuzz`:** Unchanged. Continues to use `SubprocessBackend`.
4. **MCP `deep_scan_fuzz_status`:** `container_backend_available` changes from hardcoded
   `False` to a runtime check. Response schema is unchanged.
5. **Makefile:** New `build-fuzz-sandbox` target added. Existing `build-sandboxes` target
   is not modified.
6. **Environment variables:** `DCS_FUZZ_CONTAINER_IMAGE` is new (with a default). No
   existing variables change behavior.

---

## What Went Well

1. **Every critical issue was addressed with specificity.** The plan does not just say
   "we will fix path translation" -- it shows the exact code, explains why `cmd` is
   ignored, and adds test cases verifying the behavior. This level of detail in the
   revision is exemplary.

2. **The stateless `run()` design is cleaner than the original.** By passing `target_file`
   as a keyword argument and using `**kwargs` for protocol compatibility, the plan avoids
   both the TOCTOU race and the need for a separate `ContainerExecutionBackend` protocol.
   The Liskov Substitution analysis (line 288) is explicitly stated.

3. **Security trade-offs are explicitly justified.** The single-file mount limitation,
   coverage collection deferral, Podman-only scope, and dedicated seccomp profile are all
   accompanied by rationale and fallback options (CLI for affected users). The "Deviations
   from Established Patterns" section (lines 966-976) is thorough.

4. **The test plan grew with the design.** The initial review had 11 integration tests
   and 15 unit tests. The revised plan adds `test_container_backend_stateless` (line 566),
   `test_container_backend_cmd_ignored` (line 567),
   `test_container_backend_uses_container_side_paths` (line 568),
   `test_container_backend_cpus_flag` (line 569),
   `test_output_json_symlink_rejected` (line 570), path translation tests (lines 579-583),
   and MCP lifecycle tests (lines 593-594) -- 7 new test cases targeting the specific
   gaps identified in the initial review.

5. **The Input Validation Specification is comprehensive.** Both the `ContainerBackend`
   inputs (lines 846-854) and the MCP `deep_scan_fuzz` inputs (lines 858-867) are
   documented with source, validation method, and rejection behavior for every parameter.

6. **The orphan container cleanup on startup is a practical addition.** Using
   `--label dcs.fuzz_run_id=<id>` for filtering and best-effort removal on MCP server
   initialization (line 377, Task 4.4) handles the common case of server crashes leaving
   behind running containers. This was not in the initial plan or the review
   recommendations -- it was added proactively.

---

## Verdict: PASS

The revised plan resolves all critical issues, all major concerns, and all but one minor
concern from the initial review. The new minor concerns (n-1 through n-4) are
implementation-level details that do not require plan revision:

- n-1 (FuzzRunState not Pydantic): Style consistency, no functional impact.
- n-2 (thread reference tracking): Covered by the `finally` block and orphan cleanup.
- n-3 (ImportError false positives from single-file mount): Acknowledged limitation with
  clear user fallback (CLI mode).
- n-4 (PYTHONPATH override): Functional issue, but trivially fixable during implementation
  (use `/app:/target` instead of `/target`). The implementer should note this before
  starting Task 2.

**Action items for the implementer (not plan changes):**

1. When implementing Task 2.1, set `PYTHONPATH=/app:/target` (not just `/target`) in the
   `--env` flag to ensure both the worker module and the target module are importable.
2. When implementing Task 4.2, add a `_thread` attribute to `FuzzRunState` (or a parallel
   tracking dict) so the server can reference running threads during shutdown.
3. During Task 1.4 (manual verification), confirm that
   `python -m deep_code_security.fuzzer.execution._worker --help` works inside the
   container with the constructed `PYTHONPATH`.

The plan is ready for implementation.
