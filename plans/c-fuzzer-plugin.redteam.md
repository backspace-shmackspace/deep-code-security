# Red Team Review: C Fuzzer Plugin Plan (Revised)

**Plan:** `./plans/c-fuzzer-plugin.md`
**Reviewer:** security-analyst (red team)
**Date:** 2026-03-20
**Plan Status at Review:** DRAFT (revised, incorporating feasibility and librarian feedback)
**Prior Review:** This is the second red team review. The prior review issued FAIL with 2 Critical findings (F-01: noexec removal on workspace, F-02: regex-based harness validation). The revised plan addresses both.

---

## Verdict: PASS

No Critical findings remain. The revised plan addresses the two prior Critical findings:

1. **Prior F-01 (noexec on workspace):** Resolved. The revised plan introduces a `CContainerBackend` subclass with a separate `/build` tmpfs for compilation/execution (without `noexec`) while preserving `noexec,nosuid` on the `/workspace` IPC mount. This is the exact approach recommended in the prior review.

2. **Prior F-02 (regex-based validation):** Resolved. The revised plan replaces regex validation with tree-sitter-c AST analysis for harness validation. It blocks inline assembly (`asm_statement`, `gnu_asm_expression`), `#define`/`#undef` preprocessor directives, prohibited function calls (including `dlsym`, `dlopen`), and restricted `#include` directives. The plan correctly documents that AST validation is "defense-in-depth quality control, not the security boundary."

The remaining findings are Major and Minor issues that should be addressed during implementation but do not represent fundamental design flaws or security invariant violations.

---

## Findings

### F-01: Corpus serialization of C `FuzzInput` objects creates a replay hazard [Major]

**Severity:** Major

**What the plan says:** Section 5 uses `args = ("'__c_harness__'",)` as a sentinel (a properly quoted Python string literal that passes `ast.literal_eval()`). The plan lists "Corpus replay for C" as a Non-Goal (line 23). Section 5 states "The C response parser does NOT call `validate_expression()`." Section 5 also includes `metadata["plugin"] = "c"` for downstream detection.

**The concern:** The orchestrator's main loop (`orchestrator.py` line 254) calls `corpus.add_crash(result)` for any non-success result, regardless of plugin type. This means C crash results WILL be serialized to the corpus directory. The `corpus/serialization.py` `deserialize_fuzz_result()` function (lines 58-101) calls `validate_expression()` on every `args` entry during deserialization. The sentinel `"'__c_harness__'"` passes `ast.literal_eval()` (producing the string `"__c_harness__"`), so `validate_expression()` will accept it. So far, so good.

The hazard is in the replay path. If a user runs `dcs replay <corpus_dir>` on a directory containing C crash entries, the replay system will attempt to re-execute the C `FuzzInput` through the Python worker path (since replay has no awareness of plugin types). The Python worker will receive `target_function` referencing a C function, `module_path` will be empty or invalid, and the execution will fail with a confusing `ImportError` or `AttributeError` rather than a clear "C replay not supported" message.

This is a functional correctness issue, not a security issue. But it undermines user trust when crash replay produces confusing errors for half the corpus entries in a mixed-language project.

**Recommendation:** Add a guard to the replay system that checks `metadata.get("plugin")` and skips C inputs with a clear diagnostic: "Skipping C crash entry (C corpus replay not yet supported). See Non-Goals in the C fuzzer plugin plan." This is a small addition to the replay module, not a full C replay implementation. Add it to the Files to Modify list.

---

### F-02: `CContainerBackend._build_podman_cmd` uses positional insertion that depends on an undocumented invariant [Major]

**Severity:** Major

**What the plan says:** Section 8 shows `podman_cmd.insert(-1, "--tmpfs=/build:rw,nosuid,nodev,size=128m")` to insert the `/build` mount before the image name (the last element of the command list returned by the parent).

**The concern:** The correctness of `insert(-1, ...)` depends on the invariant that the parent's `_build_podman_cmd` always returns a list where `self._image` is the last element. Examining the parent implementation (`sandbox.py` lines 236-276), this invariant currently holds:

```python
podman_cmd.append(self._image)
return podman_cmd
```

However, this is an implicit invariant. If a future modification to the parent appends additional elements after the image (e.g., container arguments, environment variables), the `insert(-1, ...)` in the subclass will place the tmpfs flag in the wrong position -- potentially after the image name, where it would be interpreted as a container argument rather than a podman flag.

The parent's `run()` method already extends the command AFTER `_build_podman_cmd` returns (lines 332-335, appending container-side paths for input/output JSON). This is fine because the extension happens in `run()`, not in `_build_podman_cmd`. But the subclass override needs to be robust against parent evolution.

**Recommendation:** Document the invariant as a code comment in the parent `_build_podman_cmd`: "NOTE: self._image MUST be the last element of the returned list. Subclasses (e.g., CContainerBackend) depend on this for mount flag insertion." Alternatively, refactor the parent to expose a `_build_security_flags()` and `_build_mounts()` method that subclasses can extend, with the image appended last by a final assembly step.

---

### F-03: No zombie reaper for harness child processes inside the container [Major]

**Severity:** Major

**What the plan says:** Section 3 specifies that `_c_worker.py` runs as the ENTRYPOINT (PID 1 inside the container) and invokes the compiled harness binary via `subprocess.run()`.

**The concern:** Inside the container, `_c_worker.py` is PID 1. When the harness binary forks child processes (up to the `--pids-limit=64` limit), those children may become orphaned if the harness binary exits before they do. Orphaned processes are reparented to PID 1 (the Python worker). If the worker does not reap them, they become zombies. While the `--pids-limit=64` prevents a fork bomb, even a few zombies can consume PID slots and cause the subsequent `gcov` subprocess invocation to fail.

The existing `SandboxManager.reap_zombies()` runs on the HOST side after each execution, but nothing reaps zombies inside the container.

AddressSanitizer itself can fork in some configurations (e.g., `fork()` within the target function being tested), and ASan's `LeakSanitizer` runs atexit hooks that may interact with zombie children.

**Recommendation:** Add `--init` to the C container's podman command. This injects a minimal init process (like `catatonit`) as PID 1, which handles zombie reaping automatically. The Python worker becomes PID 2. This is a single flag addition to `_build_podman_cmd` in `CContainerBackend` and requires no code changes to the worker. The `--init` flag is supported in Podman 2.0+ and Docker 18.06+.

---

### F-04: `DCS_FUZZ_C_COMPILE_FLAGS` and `DCS_FUZZ_C_INCLUDE_PATHS` are not validated against injection [Major]

**Severity:** Major

**What the plan says:** Section 16 introduces `DCS_FUZZ_C_COMPILE_FLAGS` (comma-separated additional gcc flags) and `DCS_FUZZ_C_INCLUDE_PATHS` (comma-separated include paths). Section 3 passes `compile_flags` from `input.json` to gcc via subprocess with list-form arguments.

**The concern:** There are two attack surfaces:

1. **Compile flags injection:** While `subprocess.run()` with list-form arguments prevents shell injection, gcc itself accepts flags that can read arbitrary files or alter compilation behavior:
   - `-include /etc/shadow` would include the contents of `/etc/shadow` as C source (gcc reads the file at compile time). Inside the container, `/etc/shadow` is on the read-only root filesystem and is not sensitive. But if `DCS_FUZZ_C_INCLUDE_PATHS` causes additional host paths to be mounted, those paths could contain sensitive files.
   - `-specs=<file>` loads a gcc specs file that can alter the compilation pipeline.
   - `-wrapper <command>` wraps gcc invocations with another command.

2. **Include paths as mount vectors:** The feasibility review (m-7) noted that `DCS_FUZZ_C_INCLUDE_PATHS` paths need to be mounted in the container. The plan does not specify whether these paths are mounted or validated. If they are mounted read-only, they become accessible to the compiled binary (which can read any mounted path). If they are validated against `DCS_ALLOWED_PATHS`, the risk is bounded.

The plan's user for these environment variables is a developer who already has host access, so the escalation potential is limited. However, in a shared CI environment where `DCS_FUZZ_C_INCLUDE_PATHS` might be set via a pipeline configuration, unvalidated paths could expose files outside the intended scan scope.

**Recommendation:**
1. Validate `DCS_FUZZ_C_INCLUDE_PATHS` entries against `DCS_ALLOWED_PATHS` before mounting them.
2. Validate `DCS_FUZZ_C_COMPILE_FLAGS` entries against a denylist of dangerous gcc flags: `-include`, `-imacros`, `-specs`, `-wrapper`, `-fplugin`, `-dumpbase`. Reject any flag containing `=` followed by a path unless the path is validated.
3. For v1, the simplest approach: document that `DCS_FUZZ_C_INCLUDE_PATHS` is only supported in SubprocessBackend mode (where the host filesystem is directly accessible) and is ignored by ContainerBackend. This avoids the mount complexity entirely. Add this to the plan.

---

### F-05: AST validation Step 7 does not handle calls through `parenthesized_expression` [Minor]

**Severity:** Minor

**What the plan says:** Section 3a Step 7 walks `call_expression` nodes and checks if the function field is an `identifier` node against the prohibited set. The plan documents that function pointer aliasing is not caught.

**The concern:** A trivial evasion: `(system)("cmd")`. In tree-sitter-c, the call `(system)("cmd")` produces a `call_expression` where the function field is a `parenthesized_expression` wrapping an `identifier`. The validator checks `if the function field is an identifier node`, which would fail because the function field is a `parenthesized_expression`. The call would pass validation.

This is in the same category as function pointer aliasing (documented limitation, container is the defense). However, unlike function pointer aliasing (which requires the attacker to declare a pointer variable), parenthesized expressions are a zero-effort evasion that requires no setup.

**Recommendation:** When checking the function field of a `call_expression`, recursively unwrap `parenthesized_expression` nodes to find the inner `identifier`. This is a 3-line code change that closes a trivial bypass. The plan already establishes the principle of tree-sitter AST walking; this is a refinement of that approach.

---

### F-06: The `/build` tmpfs size of 128 MB is generous for single-file compilation [Minor]

**Severity:** Minor

**What the plan says:** Section 8 specifies `--tmpfs=/build:rw,nosuid,nodev,size=128m`.

**The concern:** For single-file C compilation with ASan (`-fsanitize=address -g -O0`), the compiled binary is typically 500 KB - 5 MB. The ASan runtime adds ~2 MB. gcov instrumentation adds ~1 MB. Total artifacts for a single-file target: under 10 MB in typical cases.

128 MB provides 120+ MB of slack on the executable tmpfs mount. A malicious binary could write up to 128 MB of additional executable content to `/build`. While the container security policy (seccomp, no network, cap-drop=ALL) limits what this content can do, reducing the available staging area is defense-in-depth.

**Recommendation:** Reduce `/build` tmpfs to 64 MB. This provides ample space for compilation artifacts (10 MB typical, 30 MB worst case for a large file with debug symbols) while reducing the staging area available to a malicious binary. If 64 MB proves insufficient for specific targets, it can be increased via configuration.

---

### F-07: Container base image `gcc:13-bookworm` is not pinned to a digest [Minor]

**Severity:** Minor

**What the plan says:** Section 6 uses `FROM gcc:13-bookworm`. Section "Supply Chain Assessment" rates this as "Low risk. Official gcc image maintained by Docker. Pinned to gcc 13 for reproducibility."

**The concern:** Docker Hub tags are mutable. `gcc:13-bookworm` can be updated upstream to a new build at any time. In a supply chain attack scenario (which has occurred with Docker Hub images), a compromised image could introduce malicious binaries into the container. More realistically, a tag update could change ASan behavior or gcov output format, causing test failures.

Pinning to `gcc:13-bookworm` is better than `gcc:latest` but does not provide bit-for-bit reproducibility. A digest pin (`gcc:13-bookworm@sha256:<hash>`) does.

**Recommendation:** Pin to a specific digest in the Containerfile with a comment noting the date and the unpinned tag for reference. Add a quarterly review cadence for digest updates. This is standard practice for production container images. Not blocking for initial implementation.

---

### F-08: Two-branch orchestrator dispatch creates a maintenance burden for future plugins [Minor]

**Severity:** Minor

**What the plan says:** Section 13 shows `if config.plugin_name == "c": ... else: ...` in the orchestrator for AIEngine construction, `_dry_run`, and SAST prompt builder. Section "Deviations" item 6 explicitly acknowledges this as appropriate for v1 with two languages.

**The concern:** The plan has 4+ separate dispatch points in the orchestrator. When a third plugin (e.g., Go) is added, each dispatch point must gain a third branch. If any dispatch point is missed, the new plugin silently uses Python prompts/parsers.

This is explicitly acknowledged and deferred. Including it here for completeness.

**Recommendation:** Accept for v1 as documented. When a third plugin is planned, refactor to a `PromptConfig` that each plugin provides (system prompt, prompt builders, response parser). The `TargetPlugin` ABC could gain a `get_prompt_config()` method.

---

### F-09: No stdout/stderr size cap in `_c_worker.py` subprocess capture [Minor]

**Severity:** Minor

**What the plan says:** Section 3 Step 5 captures stdout, stderr, and exit code from the harness binary.

**The concern:** `subprocess.run(capture_output=True)` buffers the entire output in memory. An ASan report is typically 5-50 KB, which is fine. But a malicious or buggy harness could print megabytes to stdout/stderr, consuming memory within the 1 GB container limit. This could cause the worker to OOM before it writes `output.json`, resulting in a "WorkerCrash" result with no useful diagnostic information.

The Python worker has the same theoretical risk, but Python targets rarely produce megabytes of output. C targets (especially with ASan verbose mode or intentional output flooding) are more likely to do so.

**Recommendation:** Use `subprocess.Popen` with explicit output reading and a size cap (e.g., 128 KB for stderr to accommodate ASan reports with stack traces, 32 KB for stdout). Discard additional output. Alternatively, redirect stdout/stderr to files on the `/build` tmpfs (size-limited to 128 MB) and read only the first N bytes after execution completes.

---

### F-10: Include allowlist may be too restrictive for practical harness generation [Minor]

**Severity:** Minor

**What the plan says:** Section 3a Step 6 allows 11 standard headers: `<stdlib.h>`, `<string.h>`, `<stdint.h>`, `<limits.h>`, `<stdio.h>`, `<math.h>`, `<stdbool.h>`, `<stddef.h>`, `<errno.h>`, `<float.h>`, `<assert.h>`.

**The concern:** Common C fuzzing patterns use:
- `<ctype.h>` for character classification (`isdigit()`, `isalpha()`), frequently needed for input validation fuzzing.
- `<inttypes.h>` for portable integer format macros (`PRIu64`, `SCNd32`).
- `<setjmp.h>` for non-local jumps (used by some fuzzing harness patterns for crash recovery).

If the AI generates a harness that includes any of these, it fails validation and wastes an API call. Over many iterations, this contributes to the compilation circuit breaker firing prematurely.

`<setjmp.h>` has security implications (it enables non-local control flow that could bypass cleanup) and should probably remain excluded. But `<ctype.h>` and `<inttypes.h>` are pure data-classification headers with no security-relevant functions.

**Recommendation:** Add `<ctype.h>` and `<inttypes.h>` to the allowlist. Keep `<setjmp.h>` excluded. Instruct the AI in the system prompt to use only the allowed headers. If the AI consistently requests excluded headers, add them after security review.

---

### F-11: Coverage collection inside ContainerBackend needs explicit override for C [Minor]

**Severity:** Minor

**What the plan says:** Section 10 states: "The orchestrator's `collect_coverage = not isinstance(self._backend, ContainerBackend)` check is overridden for C: the C plugin always passes `collect_coverage=True` regardless of backend type."

**The concern:** The plan describes the intent but does not specify how this override is implemented. The `collect_coverage` flag is computed in the orchestrator (`orchestrator.py` line 223), not in the plugin. The plugin receives `collect_coverage` as a parameter to `execute()`. If the orchestrator sets `collect_coverage=False` for ContainerBackend before passing it to the C plugin, the C plugin receives `False` and the gcov data is not collected.

The plan says the C plugin "always passes `collect_coverage=True`" but if the orchestrator already computed `False`, the plugin would need to ignore the parameter and force `True` internally. This is a subtle coupling issue.

**Recommendation:** Specify one of:
1. The orchestrator checks `config.plugin_name == "c"` and overrides `collect_coverage = True` for C, regardless of backend type.
2. The `CTargetPlugin.execute()` method ignores the `collect_coverage` parameter and always collects coverage, with a comment explaining why.
3. The `collect_coverage` computation in the orchestrator becomes plugin-aware: `collect_coverage = plugin.supports_container_coverage() or not isinstance(self._backend, ContainerBackend)`.

Option 1 is simplest and matches the plan's "two-branch dispatch" pattern.

---

### F-12: Seccomp profile assumption "no additional syscalls needed" should be empirically validated [Info]

**Severity:** Info

**What the plan says:** Section 7 states: "The plan does NOT assume 'no additional syscalls needed.' Instead, the implementation task includes empirical validation."

**Analysis:** This is a significant improvement from the prior plan version, which assumed no additional syscalls. The revised plan correctly specifies an empirical validation process: (1) start with Python profile, (2) run test harness with ASan under strace, (3) identify blocked syscalls, (4) add minimally required additions. This is the correct approach.

The plan also identifies likely candidates: `personality` for ASan ASLR control and `prctl(PR_SET_VMA)` for shadow memory naming. These are accurate predictions based on ASan's known behavior.

**Recommendation:** No action needed. The empirical validation approach is correct. Document the strace methodology and results in the seccomp profile file as comments for future auditors.

---

### F-13: Container timeout calculation should be documented as a formula [Info]

**Severity:** Info

**What the plan says:** Section "Container Security Policy" specifies: "Container timeout: `compilation_timeout (30s) + execution_timeout (from DCS_FUZZ_TIMEOUT_MS) + 10s buffer`."

**Analysis:** This is a clear improvement over the prior plan. The formula `30 + (DCS_FUZZ_TIMEOUT_MS/1000) + 10` is well-defined. For the default `DCS_FUZZ_TIMEOUT_MS=5000`, the container timeout is 45 seconds. The host-side `subprocess.run(timeout=...)` adds an additional 5-second buffer (inherited from the parent `ContainerBackend.run()` at `sandbox.py` line 345: `timeout=timeout_seconds + 5`).

Total worst-case wall-clock time per harness: 45 (container timeout) + 5 (host buffer) = 50 seconds. For 10 inputs per iteration, worst-case iteration time: ~500 seconds (~8.3 minutes). This is within the MCP timeout (`DCS_FUZZ_MCP_TIMEOUT` default 120 seconds for 3 iterations). With 3 iterations at worst case, total: ~1500 seconds (25 minutes), which exceeds the 120-second MCP timeout. The MCP timeout's `_cancel_timeout` will fire and signal graceful shutdown.

**Recommendation:** Consider increasing `DCS_FUZZ_MCP_TIMEOUT` default for C fuzzing, or documenting that the default 120-second MCP timeout accommodates approximately 2 iterations of C fuzzing at worst case. Alternatively, the C-specific timeout values (30s compile + 5s execute) should be documented in the CLAUDE.md environment variable table.

---

## STRIDE Analysis Summary

| Threat | Assessment | Plan's Mitigation | Residual Risk |
|--------|-----------|-------------------|---------------|
| **Spoofing** | Can crafted code make the C worker report false results? | `output.json` is written by the worker after binary execution. Binary could pre-write a fake `output.json` to `/workspace`, but worker overwrites it post-execution. | Low -- TOCTOU window exists only during binary execution timeouts. |
| **Tampering** | Can the harness binary modify the IPC channel? | `/workspace` retains `noexec,nosuid`. Binary can write data files but cannot plant executables in IPC. | Low -- data-only writes to IPC are low-risk. |
| **Repudiation** | Can C fuzzing results be silently dropped? | Circuit breaker errors logged. Compilation failures tracked and fed back to AI. `metadata["plugin"] = "c"` tags all C results. | Low. |
| **Information Disclosure** | Can the harness binary access host files? | Container mounts only target file (read-only) and IPC directory. No other host paths unless `DCS_FUZZ_C_INCLUDE_PATHS` is configured. | Low (Medium if include paths are not validated -- see F-04). |
| **Denial of Service** | Can a harness exhaust resources? | PID limit 64, memory 1 GB, CPU 1.0, compilation timeout 30s, execution timeout configurable, container timeout formula documented. | Low. |
| **Elevation of Privilege** | Can the harness escape the container? | seccomp + cap-drop=ALL + no-new-privileges + user 65534 + network=none + read-only root. | Low -- standard Podman container hardening. |

---

## Container Security Assessment

The revised plan's container security design is sound. The key improvements from the prior version:

1. **`/workspace` retains `noexec,nosuid`** -- identical to the Python container. The prior plan's Critical finding (F-01) is fully resolved.
2. **`/build` is a separate tmpfs** -- `rw,nosuid,nodev,size=128m` (without `noexec`). This isolates the binary execution surface from the IPC channel.
3. **`CContainerBackend` is a subclass** -- the Python `ContainerBackend._build_podman_cmd` is not modified. Its security invariants are structurally preserved.
4. **Seccomp profile is empirically validated** -- not assumed identical to Python.

The remaining concern is the 128 MB `/build` tmpfs size (F-06), which is generous. The container security policy otherwise matches or exceeds the Python container's posture (the 1 GB memory limit is larger but justified for compilation).

---

## Supply Chain Risk Assessment

No new host-side Python dependencies. Container-side additions (`tree-sitter`, `tree-sitter-c` from PyPI, `python3-minimal` from Debian APT) are already project dependencies. pip is removed after installation. The `gcc:13-bookworm` base image is not digest-pinned (F-07) but is from an official Docker Hub source.

Overall supply chain risk: **Low**. No new trust boundaries beyond the existing Python container.

---

## Summary Table

| # | Finding | Severity | Category | Status vs Prior Review |
|---|---------|----------|----------|----------------------|
| F-01 | Corpus replay hazard for C `FuzzInput` entries | Major | Functional Correctness | New finding |
| F-02 | Positional insertion in podman command depends on undocumented invariant | Major | Maintainability | Refined from prior F-04 |
| F-03 | No zombie reaper for harness children inside container | Major | Reliability | New finding |
| F-04 | Compile flags and include paths not validated | Major | Input Validation | Carried from prior F-07 (feasibility m-7) |
| F-05 | Parenthesized expression bypasses prohibited function check | Minor | Defense-in-Depth | New finding |
| F-06 | `/build` tmpfs 128 MB is generous | Minor | Container Security | Refined from prior F-01 |
| F-07 | Container base image not digest-pinned | Minor | Supply Chain | Carried forward |
| F-08 | Two-branch orchestrator dispatch does not scale | Minor | Maintainability | Carried forward |
| F-09 | No stdout/stderr size cap in worker subprocess | Minor | Resource Management | New finding |
| F-10 | Include allowlist may be too restrictive | Minor | Usability | Refined from feasibility m-3 |
| F-11 | Coverage override for C ContainerBackend underspecified | Minor | Specification Gap | Refined from prior F-11 |
| F-12 | Seccomp empirical validation approach is correct | Info | Verification | Prior F-12 resolved |
| F-13 | Container timeout formula should be documented in env var table | Info | Documentation | New finding |

**Critical: 0 | Major: 4 | Minor: 7 | Info: 2**

---

## Recommended Actions Before Implementation

1. **(F-01)** Add a replay guard that checks `metadata.get("plugin")` and skips C inputs with a clear message. Add to Files to Modify list.
2. **(F-02)** Document the "image is last element" invariant in the parent `_build_podman_cmd` as a code comment.
3. **(F-03)** Add `--init` to the C container's podman command in `CContainerBackend._build_podman_cmd`.
4. **(F-04)** Specify that `DCS_FUZZ_C_INCLUDE_PATHS` is SubprocessBackend-only in v1, ignored by ContainerBackend. Validate compile flags against a denylist of dangerous gcc options.
5. **(F-05)** Recursively unwrap `parenthesized_expression` in the call expression check.
6. **(F-06)** Consider reducing `/build` tmpfs from 128 MB to 64 MB.

---

<!-- Context Metadata
reviewed_at: 2026-03-20
plan_file: plans/c-fuzzer-plugin.md
plan_status: DRAFT (revised)
reviewer: security-analyst (red team), second review
prior_review_verdict: FAIL (2 Critical)
current_verdict: PASS (0 Critical, 4 Major)
codebase_files_examined:
  - src/deep_code_security/fuzzer/plugins/base.py
  - src/deep_code_security/fuzzer/plugins/python_target.py
  - src/deep_code_security/fuzzer/plugins/registry.py
  - src/deep_code_security/fuzzer/execution/_worker.py
  - src/deep_code_security/fuzzer/execution/runner.py
  - src/deep_code_security/fuzzer/execution/sandbox.py
  - src/deep_code_security/fuzzer/models.py
  - src/deep_code_security/fuzzer/config.py
  - src/deep_code_security/fuzzer/orchestrator.py
  - src/deep_code_security/fuzzer/ai/engine.py
  - src/deep_code_security/fuzzer/ai/response_parser.py
  - src/deep_code_security/fuzzer/ai/expression_validator.py
  - src/deep_code_security/fuzzer/corpus/manager.py
  - src/deep_code_security/fuzzer/corpus/serialization.py
  - src/deep_code_security/bridge/resolver.py
  - src/deep_code_security/mcp/server.py
  - src/deep_code_security/shared/config.py
  - plans/deep-code-security.md
  - plans/c-fuzzer-plugin.feasibility.md
  - plans/c-fuzzer-plugin.review.md
prior_reviews_incorporated: feasibility (PASS), librarian (FAIL -> revised), red team v1 (FAIL -> revised)
-->
