# Re-Review: fuzzer-container-backend.md (Revised)

## Verdict: PASS (with one required edit)

The revised plan comprehensively addresses all four required edits and both critical
findings from the original review and red team review. The security posture is
significantly improved: workspace bind mount now has `noexec,nosuid`, host-side output
validation (symlink check, size check) is specified, target file mounting is single-file
instead of parent-directory, CPU quota is added, a dedicated fuzzer seccomp profile is
created, the TOCTOU race is eliminated via stateless `run()` arguments, and background
thread lifecycle management is fully specified. One new issue was identified (incorrect
parent chain count for seccomp profile path resolution), which must be fixed before
implementation.

---

## Previously Identified Conflicts -- Resolution Status

### C-1: `/workspace` mount contradiction (tmpfs vs bind mount) -- RESOLVED

The Container Security Policy table (line 98) now correctly shows:

```
--volume <host_cwd>:/workspace:rw,noexec,nosuid
```

A separate "IPC Bind Mount" section (lines 889-895) documents the bind mount with its
rationale and security mitigations. The Mandatory Flags section (lines 873-887) lists only
`--tmpfs /tmp:...` and does not include a conflicting `/workspace` entry. The contradiction
is fully eliminated.

### C-2: `DCS_CONTAINER_RUNTIME` Docker exclusion documentation -- RESOLVED

The Environment Variable Changes table (line 495) now includes: "Note: `docker` value is
NOT supported for the fuzzer container backend (Podman only). The auditor backend is
unaffected." Task 4.5 (line 772) explicitly includes a bullet to add this note to
CLAUDE.md. No residual issue.

### C-3: `ContainerBackend.run()` env filtering clarification -- RESOLVED

The `run()` docstring (lines 211-216) now explicitly states:

> The env argument is IGNORED. The container backend constructs its own minimal environment
> using only `_ALLOWED_ENV_KEYS` with hardcoded values. This prevents host environment
> leakage regardless of what the caller passes.

Line 262 reiterates this in the implementation details section. Line 687 repeats it in the
task specification. The intent is unambiguous. No residual issue.

### C-4: `target_module_dir` validation rationale -- RESOLVED

The Input Validation Specification (line 853) now reads: "Derived from the
`validate_path()`-validated `module_path` (MCP flow) or from user-provided path (CLI flow).
The parent of a validated path is necessarily within the allowed path tree; no additional
denylist is applied." The denylist approach is eliminated. No residual issue.

---

## Red Team Findings -- Resolution Status

### CRITICAL-01 (workspace symlink attack) -- RESOLVED

The revised plan adds host-side output validation (lines 106-111): symlink check
(`Path.is_symlink()` must be `False`), size check (max 10MB), and unexpected files check
(log warning). The workspace mount now uses `:rw,noexec,nosuid` (lines 98, 247). The
test plan includes `test_output_json_symlink_rejected` (line 570). No residual issue.

### CRITICAL-02 (sibling file exposure via parent directory mount) -- RESOLVED

The revised plan mounts only the specific target file, not the parent directory (lines 56,
99, 259). The mount is `--volume <target_file>:/target/<filename>:ro`. Sibling files (.env,
.git/config, *.pem, *.key) are explicitly noted as not accessible (lines 99, 259, 827,
903). Integration test `test_container_single_file_mount` (line 610) validates this. No
residual issue.

### MAJOR-01 (TOCTOU race in configure_mounts) -- RESOLVED

The `configure_mounts()` pattern is eliminated entirely. The `run()` method accepts
`target_file` as a keyword argument (line 205), making the backend stateless. The
`ContainerExecutionBackend` sub-protocol is removed in favor of `**kwargs` on
`ExecutionBackend` (lines 270-288). The stateless design section (lines 264-268) documents
the rationale. Test `test_container_backend_stateless` (line 566) verifies concurrent
safety. No residual issue.

### MAJOR-02 (no CPU quota) -- RESOLVED

`--cpus=1.0` is added to the Container Security Policy table (line 95), the Mandatory Flags
section (line 883), the `podman run` command (line 244), and Goal #2 (line 8). Tests
`test_container_backend_cpus_flag` (line 569) and `test_container_cpu_limit` (line 611)
cover it. No residual issue.

### MAJOR-03 and MAJOR-04 (seccomp profile too permissive) -- RESOLVED

A dedicated `sandbox/seccomp-fuzz-python.json` profile is created (Goal #7, lines 113-129).
It explicitly blocks `open_by_handle_at`, `name_to_handle_at`, `process_vm_readv`,
`process_vm_writev`, and `kcmp` (lines 120-126). The shared `seccomp-default.json` is not
modified. Test `test_container_escape_primitives_blocked` (line 612) validates the blocking.
No residual issue.

### MAJOR-05 (background thread lifecycle) -- RESOLVED

The revised plan specifies: cancellation via `orchestrator._shutdown_requested` flag set by
`threading.Timer` (line 375), `try/except/finally` block that ensures status is always
updated (lines 358-373), state eviction policy matching `_MAX_SESSION_SCANS` pattern (line
379), and orphan container cleanup via `podman rm -f` with label-based selection on server
startup (lines 377, 759-762). Concurrent fuzz run limit via `_MAX_CONCURRENT_FUZZ_RUNS`
(line 539, 751). No residual issue.

### MAJOR-06 (workspace mount contradiction) -- RESOLVED

Same as C-1 above. The security policy table, implementation section, and mandatory flags
section are now consistent. No residual issue.

### Minor-01 (seccomp path fragility) -- PARTIALLY RESOLVED (see N-1 below)

The plan at line 690 now cites the config module's 4-level parent traversal as precedent.
However, the parent count is incorrect. See new finding N-1.

### Minor-02 (no image version pinning) -- ACKNOWLEDGED

Not addressed in the revision. The plan retains `dcs-fuzz-python:latest` with labels for
manual auditing. This is an acceptable residual risk for a locally-built image.

### Minor-03 (functions validation) -- RESOLVED

`validate_function_name()` is now specified for the `functions` array at lines 485, 592,
647, 741, and 862. No residual issue.

### Minor-04 (noexec on workspace mount) -- RESOLVED

The workspace mount now uses `:rw,noexec,nosuid` (lines 98, 247, 892). No residual issue.

### Minor-05 (Makefile breaking change) -- RESOLVED

The plan explicitly states the new `build-fuzz-sandbox` target is standalone and the
existing `build-sandboxes` target is not modified (lines 24, 502, 672). No residual issue.

### Minor-06 (coverage disabled impact assessment) -- RESOLVED

The risk table (line 535) now rates coverage collection failure as "High" likelihood and
"Medium" impact. The deviation section (lines 970-971) provides a clear rationale and
commits to a follow-up plan. No residual issue.

### Info-01 (rootless seccomp fallback) -- RESOLVED

The risk table (line 532) now states: "the backend refuses to run (fail closed) and reports
the error. The backend does NOT fall back to a reduced security profile -- security flags
are non-negotiable." No residual issue.

### Info-03 (host-side module_path in input.json) -- RESOLVED

The path translation mechanism is fully specified in the "Path Translation" section (lines
61-80), with `FuzzRunner` rewriting `params["module_path"]` to `/target/<filename>` when
using the container backend. Test `test_module_path_translated_for_container` (line 581)
covers this. No residual issue.

---

## New Conflicts

### N-1: Seccomp profile path has incorrect parent chain count (Must Fix)

**Rule:** Correctness of implementation specification.

Task 2.1 (line 690) specifies:

> The seccomp profile path is resolved using the project structure:
> `Path(__file__).resolve().parent.parent.parent.parent / "sandbox" /
> "seccomp-fuzz-python.json"`. (The config module already uses a similar 4-level parent
> traversal for registry_path resolution from `shared/config.py`.)

The parent count is wrong. The file is at
`src/deep_code_security/fuzzer/execution/sandbox.py`. Counting parents:

| Level | Path |
|-------|------|
| `.parent` (1) | `src/deep_code_security/fuzzer/execution/` |
| `.parent` (2) | `src/deep_code_security/fuzzer/` |
| `.parent` (3) | `src/deep_code_security/` |
| `.parent` (4) | `src/` |
| `.parent` (5) | project root |

Four parents reaches `src/`, not the project root. The `sandbox/` directory is at the
project root. The plan needs **five** parents from `sandbox.py`.

The cited precedent (`shared/config.py`) uses four parents correctly because `config.py` is
one directory level shallower (`shared/` vs `fuzzer/execution/`):

| Level | Path |
|-------|------|
| `.parent` (1) | `src/deep_code_security/shared/` |
| `.parent` (2) | `src/deep_code_security/` |
| `.parent` (3) | `src/` |
| `.parent` (4) | project root |

The plan's parenthetical note that "the config module already uses a similar 4-level parent
traversal" is misleading -- the same number of parents does not yield the same result from
a deeper file path.

**Required edit:** In Task 2.1 (line 690), change the path to:
`Path(__file__).resolve().parent.parent.parent.parent.parent / "sandbox" /
"seccomp-fuzz-python.json"` (five parents, not four). Update the parenthetical note to
acknowledge that `sandbox.py` is one level deeper than `config.py` and therefore requires
one additional parent traversal.

---

## Historical Alignment

### H-1: Consistent with SD-01 resolution path (PASS)

The `merge-fuzzy-wuzzy.md` SD-01 section (line 805) specifies: "Implement the
`ContainerBackend` in `execution/sandbox.py`, reusing the DCS auditor's container security
policy." This plan follows that path exactly. The security flags match the auditor's sandbox
policy from `deep-code-security.md` (lines 405-413), with the addition of `--cpus=1.0`
(which strengthens the policy beyond what the auditor specifies). No conflict.

### H-2: Consistent with MCP tool deferral (PASS)

`merge-fuzzy-wuzzy.md` (line 197) defers `deep_scan_fuzz` until the container backend
exists. CLAUDE.md Known Limitations #6 documents the same. This plan unblocks it with the
correct precondition (container backend available). The conditional registration logic
(lines 345, 586-587, 631) is consistent with the deferral model. No conflict.

### H-3: `deep-code-security.md` container runtime preference (PASS)

`deep-code-security.md` (line 60) states "Podman rootless preferred." The plan narrows to
Podman-only for the fuzzer backend, which is a restriction, not a contradiction. The
deviation is documented (line 968) with rationale and the CLAUDE.md update task (line 772)
includes documenting this restriction. The auditor remains unaffected. No conflict.

### H-4: Auditor security policy parity (PASS)

The auditor's mandatory flags from `deep-code-security.md` (lines 405-413) are:
`--network=none`, `--read-only`, `--tmpfs /tmp:rw,noexec,nosuid,size=64m`, `--cap-drop=ALL`,
`--security-opt=no-new-privileges`, `--security-opt seccomp=...`, `--pids-limit=64`,
`--memory=512m`, `--user=65534:65534`. The plan includes all of these (lines 873-887) plus
`--cpus=1.0` and `--rm`. The fuzzer is strictly more restrictive than the auditor. No
conflict.

### H-5: MCP server remains native stdio (PASS)

The plan does not attempt to containerize the MCP server. Non-Goals (line 23) explicitly
states this. Consistent with CLAUDE.md Key Design Decisions ("Containerized MCP + Docker
socket = root-equivalent"). No conflict.

### H-6: `_worker.py` eval() deviation preserved (PASS)

The plan does not modify `_worker.py`'s execution model (Non-Goals, line 19). The SD-02
deviation from `merge-fuzzy-wuzzy.md` is unchanged. The container provides an additional
isolation layer around the existing eval() pattern. No conflict.

### H-7: Context Alignment section exists and is substantive (PASS)

The plan includes a `## Context Alignment` section (lines 944-976) that:
- Lists 9 specific CLAUDE.md patterns followed with citations
- References 3 prior plans with specific relationship descriptions
- Documents 5 deviations with rationale (increased from 3 in the original draft)

This is substantive and thorough.

### H-8: Context metadata block (PASS)

The metadata block (lines 978-983) has `claude_md_exists: true`, correct.
`recent_plans_consulted` lists three relevant prior plans. `archived_plans_consulted` lists
two archived review directories. No issues.

---

## Required Edits (Minimal, Actionable)

1. **Fix seccomp profile parent chain count (N-1):** In Task 2.1 (line 690), change the
   seccomp profile path from
   `Path(__file__).resolve().parent.parent.parent.parent / "sandbox" / ...` to
   `Path(__file__).resolve().parent.parent.parent.parent.parent / "sandbox" / ...` (five
   parents). Update the parenthetical note to say "config.py uses 4 parents from
   `shared/config.py` (3 levels deep from `src/`); `sandbox.py` uses 5 parents from
   `fuzzer/execution/sandbox.py` (4 levels deep from `src/`)."

---

## Optional Suggestions

### S-1: Consider using Config-based project root resolution for seccomp path

The five-level parent chain (even when corrected) is fragile and will break if the module
is relocated. Consider resolving the project root via the same mechanism used by `Config`
(which already computes project root from `shared/config.py`) and passing the seccomp
profile path as a `Config` attribute. This centralizes root detection and eliminates the
fragile parent chain entirely. For example, add `seccomp_fuzz_profile: Path` to `Config`
that defaults to `Config._project_root / "sandbox" / "seccomp-fuzz-python.json"`.

### S-2: Consider Podman version check in `is_available()`

The `--timeout` flag was introduced in Podman v4.0. The plan relies on it as defense-in-
depth (line 101, 260). Consider having `is_available()` check the Podman version (via
`podman version --format '{{.Client.Version}}'`) and either require >= 4.0 or gracefully
omit `--timeout` with a logged warning if older.

### S-3: Consider adding `--label` to the podman run command specification

The orphan cleanup mechanism (line 377) references `--label dcs.fuzz_run_id=<id>`, but this
label flag is not listed in the Container Security Policy table (lines 86-101) or the
Mandatory Flags section (lines 873-887). Consider adding it to the podman run command
specification (line 236) and the security policy table for completeness. The label is not a
security flag but is required for the cleanup mechanism to work.

---

## What Went Well

- **Comprehensive red team remediation.** Every critical and major finding from the red team
  review was addressed with specific design changes, not just documentation fixes. The
  single-file mount (CRITICAL-02), stateless run() (MAJOR-01), CPU quota (MAJOR-02),
  dedicated seccomp profile (MAJOR-03/04), and thread lifecycle management (MAJOR-05) are
  all substantive security improvements.

- **Security policy parity-plus with auditor.** The fuzzer sandbox is strictly more
  restrictive than the auditor sandbox: single-file mount vs directory mount, dedicated
  seccomp profile with additional blocked syscalls, and `--cpus=1.0` limit. This is the
  correct direction -- the fuzzer executes user-provided code, making it a higher-risk
  operation.

- **Host-side output validation is defense-in-depth.** The symlink check, size check, and
  unexpected files check (lines 106-111) protect against a class of attacks that the
  container security flags alone cannot prevent (malicious writes to the IPC bind mount).

- **Stateless backend design eliminates concurrency bugs.** Replacing the two-step
  `configure_mounts()` / `run()` pattern with stateless `run(**kwargs)` is architecturally
  cleaner and eliminates the entire class of TOCTOU race conditions for concurrent MCP
  fuzz runs.

- **Thorough test plan.** 15 unit tests + 4 backend selection tests + 2 path translation
  tests + 9 MCP tool tests + 11 integration tests = 41 total tests. The integration tests
  specifically target security boundaries (env leakage, network isolation, filesystem
  readonly, PID limits, memory limits, single-file mount, escape primitives).

- **Fail-closed design for missing seccomp.** The plan explicitly states the backend refuses
  to run without seccomp (line 532), rather than falling back to a weaker profile. This is
  the correct security posture.

- **Clean SD-01 resolution.** The plan faithfully implements the resolution path described
  in `merge-fuzzy-wuzzy.md` without scope creep or architectural drift.
