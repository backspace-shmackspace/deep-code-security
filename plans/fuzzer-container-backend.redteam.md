# Red Team Review (Revision 2): Podman Container Backend for Fuzzer Sandbox

**Plan reviewed:** `plans/fuzzer-container-backend.md` (revised)
**Reviewer role:** Security Analyst (security-analyst specialist)
**Date:** 2026-03-15
**Previous review:** 2026-03-15 (2 Critical, 6 Major, 6 Minor, 3 Info)

---

## Verdict: PASS

No Critical findings remain. The revision addressed both Critical and all Major findings from the previous review. Two new Minor findings and one new Info finding were identified. The plan is approvable with the caveat that the Minor findings should be corrected before implementation begins.

---

## Previously Identified Findings -- Resolution Status

### CRITICAL-01: Workspace bind mount symlink/write attack -- RESOLVED

**Previous finding:** The workspace bind mount was read-write with no host-side validation, allowing a malicious fuzz target to plant symlinks that the host would follow when reading `output.json`. The security policy table also contradicted the implementation (tmpfs vs bind mount).

**Resolution in revision:** The plan now includes a dedicated "Host-Side Output Validation" section (lines 103-111) specifying three checks before reading `output.json`:
1. Symlink check: `Path.is_file()` must be `True` and `Path.is_symlink()` must be `False`.
2. Size check: `output.json` must be <= 10MB.
3. Unexpected files check: only `input.json` and `output.json` expected; warnings logged for extras.

The security policy table (line 98) now correctly shows `--volume <host_cwd>:/workspace:rw,noexec,nosuid` (bind mount with noexec), matching the implementation. The IPC Bind Mount section (lines 889-895) explicitly documents the bind mount rationale and the defense-in-depth compensating controls. The previous tmpfs contradiction is eliminated.

**Assessment:** The chosen approach (option b from the original remediation) is adequate. The symlink check before `json.load()` closes the primary attack vector. The `noexec,nosuid` mount options prevent binary execution. The size check prevents resource exhaustion. This is a sound defense-in-depth stack.

### CRITICAL-02: Target directory mount exposes sibling files -- RESOLVED

**Previous finding:** The plan mounted the target module's parent directory, exposing `.env`, `.git/config`, `*.pem`, `*.key`, and other sensitive sibling files to the fuzz target code.

**Resolution in revision:** The plan now mounts only the specific target file (line 99):
```
--volume <target_file>:/target/<filename>:ro
```

This is explicitly documented in multiple locations: the Architecture Overview (line 56), the Container Security Policy table (line 99), the Target File Mount section (lines 897-903), and the Acceptance Criteria (criterion 16). The plan also documents the trade-off: targets with relative imports from sibling modules will fail inside the container, and users should use CLI for multi-file targets (Risk table, line 534).

**Assessment:** This is the most secure option (option a from the original remediation). Single-file mount eliminates the entire class of sibling file exposure. The trade-off is well-documented and appropriate -- security outweighs convenience for MCP-triggered runs.

### MAJOR-01: TOCTOU race in configure_mounts() -- RESOLVED

**Previous finding:** The two-step `configure_mounts()` / `run()` pattern stored mount state as instance data, creating a race condition for concurrent MCP fuzz runs.

**Resolution in revision:** The plan eliminates `configure_mounts()` entirely. The `ContainerBackend.run()` method is now stateless -- mount configuration is passed via the `target_file` keyword argument (lines 204-230). The "Stateless Backend Design" section (lines 264-312) explicitly documents this resolution. The class docstring states "The run() method is stateless -- all mount information is passed as arguments" (lines 169-173). The `ExecutionBackend` protocol gains `**kwargs: Any` for backend-specific arguments. `SubprocessBackend` accepts and ignores `**kwargs`.

**Assessment:** Fully resolved. Passing mount config as arguments to `run()` is the correct pattern -- it is inherently thread-safe with no shared mutable state.

### MAJOR-02: No CPU quota -- RESOLVED

**Previous finding:** No `--cpus` flag, allowing CPU exhaustion.

**Resolution in revision:** `--cpus=1.0` is now in the Container Security Policy table (line 95), the Mandatory Flags section (line 883), the `podman run` command (line 244), the `__init__` parameters (line 190), and the Acceptance Criteria (criterion 1). A dedicated unit test (`test_container_backend_cpus_flag`) and integration test (`test_container_cpu_limit`) are specified.

**Assessment:** Fully resolved. `--cpus=1.0` per container combined with `_MAX_CONCURRENT_FUZZ_RUNS=2` bounds total CPU impact to 2 cores.

### MAJOR-03: Dangerous syscalls in seccomp profile -- RESOLVED

**Previous finding:** `process_vm_readv`, `process_vm_writev`, and `kcmp` were allowed in the seccomp profile.

**Resolution in revision:** The plan creates a dedicated `sandbox/seccomp-fuzz-python.json` profile (lines 113-129) that removes these syscalls from the allow list and adds them to the explicit block list. The shared `seccomp-default.json` is not modified (it continues to serve the auditor). The rationale is documented: "The auditor supports Python, Go, and C targets. The fuzzer currently supports only Python. A dedicated profile follows the principle of least privilege."

**Assessment:** Fully resolved. The separate profile approach is preferred -- it follows least privilege without regressing the auditor's multi-language support.

### MAJOR-04: open_by_handle_at container escape primitive -- RESOLVED

**Previous finding:** `open_by_handle_at` and `name_to_handle_at` were allowed in the seccomp profile, creating a defense-in-depth gap for the Shocker container escape (CVE-2015-1334).

**Resolution in revision:** Both syscalls are moved to the explicit block list in the new `seccomp-fuzz-python.json` profile (lines 120-122). The table includes the CVE reference and the defense-in-depth rationale.

**Assessment:** Fully resolved.

### MAJOR-05: Background thread lifecycle deficiencies -- RESOLVED

**Previous finding:** No cancellation mechanism, no exception handling in background thread, no orphan container cleanup, no state eviction.

**Resolution in revision:** All four sub-issues are addressed (lines 354-380):
1. **Cancellation mechanism:** `threading.Timer` sets `orchestrator._shutdown_requested = True`. The orchestrator checks this flag at line 156 (between iterations) and line 198 (between inputs). The timer also sets `run_state.status = "timeout"`. Verified against actual `orchestrator.py` -- `_shutdown_requested` is checked at both points.
2. **Exception handling:** `try/except/finally` in `_fuzz_thread()` (lines 358-372). Exceptions set status to "failed". The `finally` block catches the case where the thread exits without setting status.
3. **Orphan container cleanup:** Label-based cleanup on server startup via `podman rm -f $(podman ps -aq --filter label=dcs.fuzz_run_id)` (line 377). Best-effort, logged as warning.
4. **State eviction:** Bounded `_fuzz_runs` dict matching `_MAX_SESSION_SCANS` pattern. Oldest completed/failed/timeout entries evicted. Running entries never evicted (line 379).

**Assessment:** Fully resolved. The cancellation mechanism is sound because `_shutdown_requested` is checked between each individual input execution (line 198 in the actual orchestrator code), and the Podman `--timeout` flag provides a hard backstop for any single container execution.

### MAJOR-06: Security policy table contradicts implementation on workspace mount -- RESOLVED

**Previous finding:** Three sections described three different configurations for `/workspace` (tmpfs, bind mount, not mentioned).

**Resolution in revision:** All three sections now agree:
- Security policy table (line 98): `--volume <host_cwd>:/workspace:rw,noexec,nosuid`
- Implementation command (line 247): `--volume <host_cwd>:/workspace:rw,noexec,nosuid`
- IPC Bind Mount section (lines 889-895): explicit bind mount with documented rationale

The contradiction is eliminated.

**Assessment:** Fully resolved.

### Minor-01: Fragile parent-directory traversal for seccomp path -- PARTIALLY RESOLVED (see NEW-01)

**Previous finding:** 5-level `parent` traversal from `sandbox.py` to reach `sandbox/seccomp-default.json` is fragile.

**Resolution in revision:** The plan changed to 4-level traversal (line 690) and references the config module's similar pattern: "The config module already uses a similar 4-level parent traversal for registry_path resolution from `shared/config.py`."

**Assessment:** The analogy to config.py is incorrect and introduces a bug. See NEW-01 below.

### Minor-02: No image version pinning or integrity verification -- PARTIALLY RESOLVED

**Previous finding:** `dcs-fuzz-python:latest` with no integrity or version check.

**Resolution in revision:** The plan adds `LABEL org.opencontainers.image.version="1.0.0"` (line 160) and mentions it is for "manual auditing." The `is_available()` method still only checks image existence, not version or digest.

**Assessment:** Partially resolved. The version label enables manual auditing but automated verification is absent. The risk is low for single-user deployments (the typical use case). Acceptable as-is for v1.

### Minor-03: functions parameter not validated in MCP handler -- RESOLVED

**Previous finding:** `functions` array elements were not validated before being passed to the orchestrator.

**Resolution in revision:** The plan specifies (line 485): "The `functions` array elements are validated via `validate_function_name()` from `input_validator.py` in the MCP handler before being passed to the orchestrator." This is also in the Acceptance Criteria (criterion 20) and the Input Validation Specification table (line 862). A unit test `test_fuzz_tool_validates_function_names` is included.

**Assessment:** Fully resolved.

### Minor-04: noexec not enforced on workspace bind mount -- RESOLVED

**Previous finding:** The workspace bind mount lacked `:noexec,nosuid` options.

**Resolution in revision:** The workspace mount now includes `:rw,noexec,nosuid` in all three locations (security policy table line 98, implementation command line 247, IPC Bind Mount section line 892).

**Assessment:** Fully resolved.

### Minor-05: Makefile change modifies existing build-sandboxes target -- RESOLVED

**Previous finding:** Task 1.2 modified the shared `build-sandboxes` target, breaking existing Docker users.

**Resolution in revision:** Non-Goals (line 24) now states: "Modifying the existing `build-sandboxes` Makefile target. The new `build-fuzz-sandbox` target is standalone." Task 1.3 (line 669-672) creates only `build-fuzz-sandbox` and explicitly states "Do NOT modify the existing `build-sandboxes` target."

**Assessment:** Fully resolved.

### Minor-06: Coverage disabled with understated impact -- RESOLVED

**Previous finding:** Impact assessment of "Low" was too optimistic.

**Resolution in revision:** The risk table (line 535) now describes the impact more accurately: "Without coverage delta feedback, the AI engine generates inputs based solely on crash/no-crash signals, reducing multi-iteration input diversity." The impact is labeled "Medium." The deviations section (line 970) provides full rationale including the core value trade-off.

**Assessment:** Fully resolved. The impact is honestly stated.

### Info-01: Rootless seccomp fallback is dangerous -- RESOLVED

**Previous finding:** The plan suggested falling back to a "reduced security profile" if seccomp was unavailable.

**Resolution in revision:** The risk table (line 532) now states: "If seccomp is unavailable in rootless mode, the backend refuses to run (fail closed) and reports the error. The backend does NOT fall back to a reduced security profile -- security flags are non-negotiable." (Emphasis in original.)

**Assessment:** Fully resolved. Fail-closed is the correct behavior.

### Info-02: Auditor security policy drift risk -- UNCHANGED (Accepted)

**Previous finding:** No mechanism to keep auditor and fuzzer security policies synchronized.

**Resolution in revision:** Not directly addressed, which is acceptable. The fuzzer now has its own dedicated seccomp profile, making the policy intentionally distinct. The shared principles (cap-drop, no-new-privileges, etc.) are derived from the approved architecture plan, not from the auditor implementation.

**Assessment:** Acceptable as-is. The separate profile actually reduces the drift concern -- the policies are independently specified and independently auditable.

### Info-03: module_path host-to-container path translation -- RESOLVED

**Previous finding:** `input.json` contained the host-side `module_path`, but the worker inside the container needed the container-side path.

**Resolution in revision:** The plan includes a dedicated "Path Translation (Host-to-Container)" section (lines 61-80) documenting both required translations. `FuzzRunner` rewrites `module_path` in `input.json` to `/target/<filename>` when using a container backend. The `ContainerBackend` ignores the `cmd` argument and constructs its own command using container-side paths. Path translation tests are specified (`test_module_path_translated_for_container`).

**Assessment:** Fully resolved. The path translation logic is correct and testable.

---

## New Findings

### NEW-01: Seccomp profile path uses incorrect parent traversal depth (4 levels instead of 5)

**Severity:** Minor
**STRIDE:** N/A (functional bug)

The plan specifies (line 690):
```python
Path(__file__).resolve().parent.parent.parent.parent / "sandbox" / "seccomp-fuzz-python.json"
```

The plan claims this is "a similar 4-level parent traversal" to what `Config.registry_path` uses. However, this analogy is wrong:

- `config.py` is at `src/deep_code_security/shared/config.py` -- 4 parents reaches the project root (`.`).
- `sandbox.py` is at `src/deep_code_security/fuzzer/execution/sandbox.py` -- 4 parents reaches `src/`, NOT the project root.

The `sandbox/` directory is at the project root. From `sandbox.py`, 5 parents are needed to reach the project root. The plan's "fix" for Minor-01 from the original review introduced an off-by-one error -- it reduced the traversal from 5 to 4, but the original 5 was correct.

With 4 parents, the path resolves to `src/sandbox/seccomp-fuzz-python.json`, which does not exist. This will cause a runtime failure when the `ContainerBackend` attempts to locate the seccomp profile.

**Remediation required:** Either:
- (a) Use 5-level parent traversal (the original plan was correct on this count).
- (b) Follow the original Minor-01 recommendation and use `importlib.resources` or a configuration constant to avoid fragile parent counting. The `Config` class could expose a `project_root` property, and the seccomp path could be derived from `config.project_root / "sandbox" / "seccomp-fuzz-python.json"`.

Option (b) is preferred -- it eliminates the fragility that caused this regression.

### NEW-02: Workspace bind mount has no size limit, enabling disk exhaustion

**Severity:** Minor
**STRIDE:** Denial of Service
**DREAD:** D:3 R:7 E:3 A:5 D:5 = 4.6

The original security policy table in the v1 plan specified `size=64m` for the `/workspace` tmpfs. The revision correctly changed from tmpfs to bind mount, but bind mounts do not support a `size=` option. This means the workspace has no size limit.

A malicious fuzz target inside the container can write arbitrarily large files to `/workspace` (bound-mounted to a host temp directory), potentially filling the host's `/tmp` partition or root filesystem. While the container has `--memory=512m`, memory limits do not restrict file I/O -- a process can write gigabytes to disk with minimal memory usage.

The `output.json` size check (max 10MB, line 108) only protects against oversized output files that the host would read. It does not prevent the container from writing large garbage files with other names.

The `--read-only` flag on the root filesystem prevents writes elsewhere inside the container, but `/workspace` is explicitly writable and backed by the host filesystem.

**Remediation:**
- Add a `tmpfs` overlay for `/workspace` inside the container with a size limit, and use `podman cp` for IPC instead of a bind mount. This is the most secure option but adds latency.
- Alternatively, document this as an accepted risk (the temp directory is cleaned up after container exit by `cleanup_dir()`), and add a post-execution check that verifies the total size of the temp directory is within bounds (e.g., 64MB) before reading `output.json`. If oversized, log a warning and clean up.
- At minimum, document that disk exhaustion by a single fuzz input execution is bounded by the Podman `--timeout` (timeout_seconds + 5) and the container's write throughput.

### NEW-03: Container stderr may expose host paths in MCP responses

**Severity:** Info
**STRIDE:** Information Disclosure

The `ContainerBackend.run()` captures Podman's stderr and returns it as part of the `(returncode, stdout, stderr)` tuple. Podman's error messages may include host-side paths (e.g., the full path to the seccomp profile, the bind mount source paths, or Podman runtime errors referencing host directories). These are passed through `FuzzResult.stderr` and potentially returned in MCP `deep_scan_fuzz_status` responses.

This is a minor information disclosure: an MCP client (which operates in a different trust context from the host) could learn the host username, project directory structure, or temp directory paths from container error messages.

The existing server code does not sanitize stderr before returning it to MCP clients (verified: the `_handle_fuzz_status` response structure includes fuzz run results which contain `stderr` from target execution).

**Remediation:** Sanitize or truncate container stderr before including it in MCP responses. Replace host paths with placeholders or strip them entirely. This is a low-priority improvement.

---

## STRIDE Analysis

### Spoofing

| Threat | Assessment | Mitigation Status |
|---|---|---|
| Forged container image | Minor-02 (partially resolved): Image version label added but no automated verification | Acceptable for v1 (local-only builds) |
| MCP client spoofing fuzz_run_id | Low risk: UUID-based, per-server-instance storage | Adequate |
| Forged seccomp profile | Minor risk if host is compromised; seccomp path is hardcoded from project source | Adequate |

### Tampering

| Threat | Assessment | Mitigation Status |
|---|---|---|
| Container output via symlink in workspace | RESOLVED: Host-side symlink check before reading output.json | Adequate |
| Container modifying target code | Mitigated: single-file `:ro` mount | Adequate |
| Container tampering with output.json content | Mitigated: `json.load()` + Pydantic validation on host side | Adequate |
| Corpus file tampering | Existing mitigation: expression re-validation on replay | Adequate |
| TOCTOU race in backend state | RESOLVED: Stateless `run()` with per-call arguments | Adequate |

### Repudiation

| Threat | Assessment | Mitigation Status |
|---|---|---|
| Container operations not DCS-logged | MCP-level `_audit_log()` covers tool invocations. Container labels enable Podman-level auditing. Orphan cleanup on startup provides best-effort recovery. | Adequate |
| Fuzz run results silently dropped | RESOLVED: `try/except/finally` ensures status always updated. Eviction policy prevents unbounded state growth. | Adequate |

### Information Disclosure

| Threat | Assessment | Mitigation Status |
|---|---|---|
| Host environment variable leakage | Mitigated: `_ALLOWED_ENV_KEYS` frozenset with hardcoded values; `env` parameter ignored | Adequate |
| Host filesystem exposure via target mount | RESOLVED: Single-file mount; sibling files not accessible | Adequate |
| Container-to-container info leakage | Mitigated: ephemeral `--rm`, no shared volumes | Adequate |
| Error messages exposing host paths | NEW-03: Podman stderr may contain host paths | Minor gap (Info) |
| Cross-process memory reads | RESOLVED: `process_vm_readv/writev` blocked in fuzzer seccomp profile | Adequate |

### Denial of Service

| Threat | Assessment | Mitigation Status |
|---|---|---|
| CPU exhaustion | RESOLVED: `--cpus=1.0` per container | Adequate |
| Memory exhaustion | Mitigated: `--memory=512m` | Adequate |
| Fork bomb | Mitigated: `--pids-limit=64` | Adequate |
| Disk exhaustion via workspace | NEW-02: Bind mount has no size limit | Minor gap |
| Container accumulation | Mitigated: `--rm` + orphan cleanup on startup | Adequate |
| Concurrent MCP requests | Mitigated: `_MAX_CONCURRENT_FUZZ_RUNS` rejects excess requests | Adequate |

### Elevation of Privilege

| Threat | Assessment | Mitigation Status |
|---|---|---|
| Container escape via kernel exploit | Mitigated: dedicated seccomp profile with additional blocks | Adequate |
| Privilege escalation via setuid | Mitigated: `--cap-drop=ALL` + `--security-opt=no-new-privileges` + non-root user | Adequate |
| Escape via open_by_handle_at | RESOLVED: Blocked in fuzzer seccomp profile | Adequate |
| Container breakout via writable workspace | Mitigated: `noexec,nosuid` on bind mount; symlink check on host side | Adequate |
| Podman socket exploitation | N/A: CLI subprocess, no socket | N/A |

---

## Container Security Assessment

The revised plan presents a well-structured container security posture with appropriate defense-in-depth:

**Strengths:**
1. The mandatory flag set (network=none, read-only, cap-drop=ALL, no-new-privileges, seccomp, pids-limit, memory, cpus, non-root user) covers all standard container hardening measures.
2. The dedicated fuzzer seccomp profile (`seccomp-fuzz-python.json`) follows least privilege by blocking syscalls needed only by Go/C runtimes.
3. Single-file target mount is the most secure option and eliminates sibling file exposure entirely.
4. The `env` parameter is ignored and replaced with a hardcoded allowlist -- this is correct and prevents host environment leakage regardless of caller behavior.
5. Fail-closed behavior when seccomp is unavailable (no security degradation fallback).
6. Container labels enable orphan cleanup on server restart.

**Residual risks (accepted):**
1. Kernel-level container escape (mitigated by seccomp + capabilities drop, but not eliminated).
2. Side-channel attacks from within the container (timing, cache -- out of scope for this threat model).
3. Targets with relative imports fail inside the container (documented trade-off; CLI fallback available).
4. Coverage-guided feedback disabled for MCP fuzz runs (documented trade-off; follow-up planned).

---

## Supply Chain Risk

**Low risk.** The container image uses `python:3.12-slim` as the base (widely used, Docker Official Image) and copies only project source files -- no `pip install`, no third-party packages in the container. The worker module's import chain (`_worker.py` -> `expression_validator.py`) uses only standard library modules (`ast`, `json`, `re`, `sys`, `pathlib`, `importlib.util`, `traceback`, `logging`, `io`). No new PyPI dependencies are introduced by this plan.

The Podman binary itself is a system dependency installed outside the project's control. The plan does not pin a minimum Podman version, but `--timeout` support (required for defense-in-depth) was added in Podman v4.0. A version check in `is_available()` would be a nice-to-have but is not required.

---

## Summary of Required Changes

| ID | Severity | Status | Action |
|---|---|---|---|
| CRITICAL-01 | Critical | RESOLVED | Symlink check, noexec mount, consistent documentation |
| CRITICAL-02 | Critical | RESOLVED | Single-file target mount |
| MAJOR-01 | Major | RESOLVED | Stateless run() with per-call arguments |
| MAJOR-02 | Major | RESOLVED | --cpus=1.0 added |
| MAJOR-03 | Major | RESOLVED | Dedicated seccomp profile blocks process_vm_readv/writev/kcmp |
| MAJOR-04 | Major | RESOLVED | open_by_handle_at/name_to_handle_at blocked in seccomp |
| MAJOR-05 | Major | RESOLVED | Cancellation, exception handling, orphan cleanup, eviction |
| MAJOR-06 | Major | RESOLVED | Security policy table matches implementation |
| Minor-01 | Minor | PARTIALLY RESOLVED | See NEW-01: traversal depth is wrong (4 vs 5) |
| Minor-02 | Minor | PARTIALLY RESOLVED | Version label added; automated check absent (acceptable for v1) |
| Minor-03 | Minor | RESOLVED | function names validated via validate_function_name() |
| Minor-04 | Minor | RESOLVED | noexec,nosuid on workspace mount |
| Minor-05 | Minor | RESOLVED | build-fuzz-sandbox is standalone; build-sandboxes untouched |
| Minor-06 | Minor | RESOLVED | Impact upgraded to Medium with honest trade-off description |
| Info-01 | Info | RESOLVED | Fail-closed when seccomp unavailable |
| Info-02 | Info | ACCEPTED | Separate profiles reduce drift concern |
| Info-03 | Info | RESOLVED | Path translation documented and tested |
| NEW-01 | Minor | NEW | Seccomp path: 4-level parent traversal is wrong; needs 5 or config-based resolution |
| NEW-02 | Minor | NEW | Workspace bind mount has no size limit; potential disk exhaustion |
| NEW-03 | Info | NEW | Container stderr may leak host paths in MCP responses |
