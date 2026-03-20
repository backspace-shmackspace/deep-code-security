# Feasibility Review (Round 2): C Fuzzer Plugin

**Plan:** `./plans/c-fuzzer-plugin.md`
**Reviewer:** code-reviewer (feasibility)
**Date:** 2026-03-20
**Verdict:** PASS

---

## Overall Assessment

The revised plan is thorough, security-conscious, and implementable. All four round-1 Critical findings have been properly resolved. The plan builds correctly on the existing plugin architecture and makes well-reasoned tradeoffs. The remaining concerns below are adjustments, not blockers.

---

## Round-1 Critical Finding Resolution Audit

### 1. IPC mount separation (CContainerBackend subclass with separate /build tmpfs) -- RESOLVED

**Original finding (Red Team F-01, Feasibility C-1):** Removing `noexec` from `/workspace` weakens a security invariant from the approved `fuzzer-container-backend` plan.

**What the revised plan does:** Section 8 introduces a `CContainerBackend` subclass (not a parameter toggle on the parent) that:
- Keeps `/workspace` with `rw,noexec,nosuid` (identical to Python) for JSON IPC only.
- Adds a separate `/build` tmpfs at `rw,nosuid,nodev,size=128m` (without `noexec`) for compilation and binary execution.
- Overrides `_build_podman_cmd` to insert the `/build` tmpfs via `podman_cmd.insert(-1, "--tmpfs=...")` before the image name.
- Does NOT modify the parent `ContainerBackend._build_podman_cmd` at all.

**Assessment:** This is the correct design. The Python security invariant remains structural (hardcoded in the parent, not caller-dependent). The `/build` tmpfs is ephemeral, includes `nodev`, and is destroyed with the container. The IPC channel at `/workspace` is never executable. The approach is auditable: a reviewer can see the full C mount policy in a single class without checking parent callers.

**One minor note:** The `_build_podman_cmd` override calls `super()._build_podman_cmd()` and then uses `podman_cmd.insert(-1, ...)` to place the `--tmpfs` flag before the image name (the last element). This is fragile if the parent method ever appends arguments after the image name (e.g., ENTRYPOINT args). In the current code (lines 264-276 of `sandbox.py`), the image is indeed the last element, so this works today. The plan's inline code comment explains the insertion point reasoning, which is good. But an explicit assertion or comment in the implementation like `assert podman_cmd[-1] == self._image` would make this robust against parent changes.

**Verdict on this finding: Properly resolved.**

### 2. Tree-sitter AST harness validation replacing regex -- RESOLVED

**Original finding (Red Team F-02, Feasibility C-2):** Regex-based harness validation is trivially bypassable via macro obfuscation, function pointer aliasing, inline assembly, and extern declarations.

**What the revised plan does:** Section 3a specifies a 7-step tree-sitter-c AST validation procedure:
1. Parse with tree-sitter-c (reject on parse failure).
2. Size check (64 KB limit).
3. Exactly one `main()` function via `function_definition` node walk.
4. Reject `asm_statement`, `__asm__`, `gnu_asm_expression` nodes.
5. Reject `preproc_def`, `preproc_function_def`, `preproc_undef` nodes (blocks `#define`-based obfuscation).
6. Validate `#include` directives against an allowlist via `preproc_include` nodes.
7. Reject prohibited function calls via `call_expression` node walk (checks the function identifier against a deny set).

The plan explicitly documents the limitations:
- Function pointer aliasing is NOT caught by AST validation (correctly -- the container policy is the defense).
- Extern forward declarations bypass include checks but the function call check (step 7) catches the actual call.
- Computed includes are prevented because `#define` is rejected in step 5.

Both layers (Layer 1 in `c_response_parser.py` on the host, Layer 2 in `_c_worker.py` inside the container) use tree-sitter-c, and the container image includes tree-sitter-c for Layer 2.

**Assessment:** This is a substantial improvement over the round-1 regex approach. The AST-based validation correctly catches the three most accessible evasion vectors (macros, inline assembly, prohibited calls by name) while honestly documenting what it cannot catch (function pointer aliasing). The plan is explicit that validation is "defense-in-depth quality control, not the security boundary" (Section 3, final paragraph). This is the right framing.

**Verdict on this finding: Properly resolved.**

### 3. `__c_harness__` sentinel fix -- RESOLVED

**Original finding (Librarian Conflict 1, Feasibility m-1):** The bare identifier `__c_harness__` fails both `ast.literal_eval()` (ValueError) and the allowlist check in `expression_validator.py` (not in `SAFE_NAMES`).

**What the revised plan does:** The sentinel is now `("'__c_harness__'",)` -- a properly quoted Python string literal (Assumption 2, Section 5). This passes `ast.literal_eval()` (producing the string `"__c_harness__"`). The C response parser does NOT invoke `validate_expression()` -- expression validation is explicitly described as Python-specific. The `metadata["plugin"] = "c"` tag allows downstream code to detect C inputs and skip Python-specific processing.

**Assessment:** I verified against the actual expression validator code. `"'__c_harness__'"` is a valid Python string literal: `ast.literal_eval("'__c_harness__'")` returns the string `"__c_harness__"`. The sentinel would survive expression validation if it were ever encountered, but the C response parser bypasses it entirely. The `metadata["plugin"]` tag (per Red Team F-06 recommendation) provides a discriminant for corpus deserialization and replay. Both aspects of the fix are sound.

**Verdict on this finding: Properly resolved.**

### 4. @property methods on CTargetPlugin -- RESOLVED

**Original finding (Librarian Conflict 2):** The round-1 pseudo-code used class attributes (`name = "c"`, `file_extensions = [".c"]`) instead of `@property` methods, which violates the ABC contract and introduces a mutable default argument.

**What the revised plan does:** Section 9 now explicitly states the plugin uses `@property` methods for `name` and `file_extensions`, matching the `TargetPlugin` ABC contract and the `PythonTargetPlugin` pattern. `file_extensions` returns a `tuple` (immutable) instead of a `list` to comply with the "no mutable default arguments" rule. The plan notes the tuple is runtime-compatible with the ABC's `-> list[str]` annotation.

**Assessment:** I verified against the ABC (`base.py` lines 27-36). The abstract properties are decorated `@property @abstractmethod`, requiring concrete `@property` implementations. The `tuple` return for `file_extensions` is compatible at runtime (both are `Sequence[str]`). The plan correctly identifies the type annotation mismatch and offers a mitigation (`list((".c",))` on each call if strict type checking requires it). This is pragmatic and correct.

**Verdict on this finding: Properly resolved.**

---

## Additional Round-1 Findings Resolution

### Red Team F-03 (AIEngine hardcoded SYSTEM_PROMPT) -- RESOLVED

Section 13 now specifies concrete modifications:
- `AIEngine.__init__` gains four optional parameters with defaults pointing to Python implementations.
- `_call_api()` uses `self._system_prompt` instead of the module-level `SYSTEM_PROMPT`.
- `generate_initial_inputs()` uses `self._initial_prompt_builder()`.
- `refine_inputs()` uses `self._refinement_prompt_builder()`.
- `_parse_with_validation()` uses `self._response_parser_fn()`.
- Orchestrator dispatch code shows the concrete `if config.plugin_name == "c":` branch with imports.

I verified against the actual `engine.py` code. The hardcoded `SYSTEM_PROMPT` at line 277, `build_initial_prompt` at line 155, `build_refinement_prompt` at line 210, and `parse_ai_response` at line 301 are all identified for replacement with instance-level callables. The modifications are backward compatible (Python defaults used when no overrides).

### Red Team F-04 (FuzzRunner Python coupling) -- RESOLVED

Section 8a specifies `CFuzzRunner` as a separate class (not a subclass). The rationale is sound: `FuzzRunner` is deeply coupled to Python worker semantics (`module_path`, `qualified_name`, `args`, `kwargs`, `PYTHONPATH`, `_worker.py`). Overriding nearly every method provides no benefit. The separate class encapsulates C-specific `input.json` format and worker invocation while sharing the `SandboxManager` pattern. The security flags remain hardcoded in `CContainerBackend._build_podman_cmd`.

### Red Team F-05 (is_available Python-specific) -- RESOLVED

Section 8 specifies `ContainerBackend.is_available(image: str | None = None)` with an optional image parameter. The MCP server registration logic (Section 14) checks both Python and C image availability at startup and registers `deep_scan_fuzz` if *any* fuzz image exists. At request time, the handler checks the specific plugin's image. This is the correct approach.

### Feasibility M-2 (_dry_run Python-only) -- RESOLVED

Section 13 includes explicit `_dry_run()` dispatch with a code example showing the `if self.config.plugin_name == "c":` branch importing `build_c_initial_prompt`.

### Feasibility M-4 (gcov TOCTOU) -- RESOLVED

Section 3 specifies that gcov is invoked in a fresh subdirectory (`/build/gcov_out/`) to prevent TOCTOU manipulation. The risk is documented as a data quality issue, not a security issue.

### Feasibility M-5 (compilation circuit breaker) -- RESOLVED

Section 15 specifies the circuit breaker design: per-iteration failure rate, 80% threshold, 3 consecutive iteration counter, reset on successful iteration, `CircuitBreakerError` on trip. Compilation error messages are included in the refinement prompt.

### Feasibility M-6 (crash dedup metadata) -- RESOLVED

Section 11 (Crash Analysis) explicitly states that `crash_signature()` hashes `exc_type` and the last traceback file+line location, NOT `FuzzInput.metadata`. I verified against the actual `crash_signature()` function in `corpus/manager.py` (lines 50-60): it uses `result.exception` and `result.traceback` only, not `result.input.metadata`. The plan is correct that the same vulnerability triggered by different harnesses will produce the same crash signature.

### Red Team F-11 (coverage disabled for ContainerBackend) -- RESOLVED

Section 10 explicitly addresses this: "The C plugin always passes `collect_coverage=True` regardless of backend type, because gcov data is collected and returned within the container via the JSON IPC protocol." This is correct because the C worker runs gcov inside the container and includes coverage data in `output.json`, unlike the Python case where coverage.py writes to host-side paths.

---

## New Concerns in the Revised Plan

### Major-1: The `_build_podman_cmd` override insert position is fragile

**Where:** Section 8, `CContainerBackend._build_podman_cmd` code.

**Issue:** The method calls `super()._build_podman_cmd(...)` and then inserts the `/build` tmpfs flag at position `-1` (before the last element, assumed to be the image name). I verified the parent code (`sandbox.py` lines 236-276): the last operation before returning is `podman_cmd.append(self._image)` at line 274. However, the parent's `run()` method (lines 278-350) extends the command with ENTRYPOINT arguments *after* calling `_build_podman_cmd()`, so the override's insert-before-last logic is correct for the scope of `_build_podman_cmd`. But if the parent is ever refactored to append ENTRYPOINT args inside `_build_podman_cmd` instead of in `run()`, the insert position breaks silently.

**Recommendation:** Add an assertion or guard in the implementation: `assert podman_cmd[-1] == self._image, "Parent changed _build_podman_cmd structure"`. This costs nothing and catches structural drift.

**Severity:** Major (silent breakage risk on parent refactor).

### Major-2: Bridge resolver language dispatch by file extension needs fallback handling

**Where:** Section 12 (Bridge Integration).

**Issue:** The plan says the bridge resolver switches from `finding.language.lower() != "python"` to dispatching by file extension of `sink_file` (`.py` -> Python extractor, `.c` -> C extractor). This is a good approach that avoids coupling to the plugin registry. However, the plan does not specify what happens for files with extensions that match neither `.py` nor `.c` (e.g., `.go`, `.h`). The current code skips non-Python findings; the revised code should skip non-Python-or-C findings with a log message.

Additionally, the plan does not address `.h` header files. A sink may be located in a `.h` file (inline function in a header). The file extension dispatch should treat `.h` as C (or skip it with a documented reason).

**Recommendation:** Specify the dispatch behavior for unknown extensions (skip with warning) and for `.h` files (treat as C, or skip if header-only analysis is not supported).

**Severity:** Major (functional gap).

### Minor-1: Container image does not pin tree-sitter/tree-sitter-c versions

**Where:** Section 6 (Containerfile).

**Issue:** The Containerfile runs `pip3 install --no-cache-dir tree-sitter tree-sitter-c` without version pins. Since tree-sitter has had breaking API changes (v0.21 -> v0.23), a future pip install could pull an incompatible version. The host side pins `tree-sitter-c>=0.23.0,<0.23.5` in `pyproject.toml` (line 28).

**Recommendation:** Pin versions in the container to match the host: `pip3 install --no-cache-dir 'tree-sitter>=0.23.0,<0.24.0' 'tree-sitter-c>=0.23.0,<0.23.5'`.

### Minor-2: `DCS_FUZZ_C_INCLUDE_PATHS` mount strategy is unspecified for ContainerBackend

**Where:** Section 16 (Configuration Changes).

**Issue:** The `DCS_FUZZ_C_INCLUDE_PATHS` environment variable provides additional include paths for gcc. In SubprocessBackend mode, these are passed as `-I` flags directly. In ContainerBackend mode, the directories containing header files must be mounted into the container for gcc to access them. The plan does not specify how `CContainerBackend._build_podman_cmd` mounts include paths, or whether each path is validated against `DCS_ALLOWED_PATHS`.

**Recommendation:** Specify that each path in `DCS_FUZZ_C_INCLUDE_PATHS` is validated against `DCS_ALLOWED_PATHS`, resolved via `os.path.realpath()`, and mounted read-only in the container at the same absolute path. This is a necessary security check because arbitrary paths would let a caller mount sensitive host directories into the container.

### Minor-3: The plan does not specify `--plugin c` on the `dcs hunt-fuzz` CLI command

**Where:** Section 12 (Bridge Integration), CLI Commands table in CLAUDE.md.

**Issue:** The MCP tool `deep_scan_fuzz` gains a `plugin` field (Section 14), but the `dcs hunt-fuzz` CLI command (CLAUDE.md line) currently hardcodes `plugin_name="python"` in the server code (`server.py` line 1040 and 1306). The plan's Section 12 says the bridge is expanded for C, but does not mention updating `dcs hunt-fuzz` CLI or MCP `deep_scan_hunt_fuzz` to accept a plugin parameter.

**Recommendation:** Add `--plugin` CLI flag to `dcs hunt-fuzz` and a `plugin` field to the `deep_scan_hunt_fuzz` MCP tool schema. List `cli.py` and the `_handle_hunt_fuzz` MCP handler in the Files to Modify table.

### Minor-4: The compilation circuit breaker location is ambiguous

**Where:** Section 15 (Compilation Circuit Breaker).

**Issue:** The section says the counter is "maintained in the `FuzzOrchestrator` (or `CTargetPlugin`)". This ambiguity should be resolved. The orchestrator is the correct location because it owns the iteration loop and calls `plugin.execute()` per input. The circuit breaker logic should check `FuzzResult.exception` after each `execute()` call, which happens in the orchestrator's iteration loop (lines 225-253 of `orchestrator.py`).

**Recommendation:** Specify that the circuit breaker lives in the orchestrator (specifically the `run()` method's iteration loop) and is active only when `config.plugin_name == "c"`. This avoids adding C-specific state to the generic orchestrator when fuzzing Python.

### Minor-5: Seccomp profile empirical validation task needs a test gate

**Where:** Section 7 (C Seccomp Profile).

**Issue:** The plan correctly identifies that the seccomp profile must be empirically validated via strace (addressing Red Team F-12). However, this validation is listed only as an "implementation task" without a test gate. If the seccomp profile is incorrect, the integration test will fail with cryptic `EPERM` errors.

**Recommendation:** Add an explicit integration test case: "Run a known-good harness (buffer overflow fixture) inside the C container and verify that the harness crashes with ASan output (not `EPERM` from seccomp)." This test implicitly validates the seccomp profile.

---

## Implementation Complexity Assessment

| Component | Estimate | Notes |
|-----------|----------|-------|
| C signature extractor | 1-2 days | Straightforward tree-sitter pattern. Existing `signature_extractor.py` provides the template. |
| C prompts + response parser | 2-3 days | Response parser is the harder part (tree-sitter-c AST validation). Prompt engineering is iterative. |
| C worker (`_c_worker.py`) | 3-4 days | Compile + execute + ASan parsing + gcov parsing + tree-sitter-c validation (Layer 2). The ASan parsing regex is the fiddly part. |
| `CFuzzRunner` | 1 day | Separate class, C-specific `input.json` format. |
| `CTargetPlugin` | 1 day | Thin integration layer. |
| `CContainerBackend` | 0.5 days | Subclass override is compact. |
| Container image + seccomp | 1-2 days | Image build is quick. Seccomp validation via strace takes time. |
| `AIEngine` extensibility | 1 day | Small, backward-compatible change. |
| Orchestrator dispatch + circuit breaker | 1 day | Two-branch dispatch + per-iteration failure tracking. |
| Bridge integration | 1-2 days | Language dispatch + C extractor. |
| MCP integration | 1 day | Schema change + per-plugin availability. |
| Tests (21 test files listed) | 5-6 days | 12 unit test files, 1 integration test, adversarial tests. |
| **Total** | **18-24 days** | Realistic for a single engineer over 4-5 weeks. |

The plan's rollout phases (Core Plugin -> Container Backend -> Bridge Integration -> Documentation) are well-ordered. Phase 1 can be tested with SubprocessBackend before the container is ready.

---

## Backward Compatibility Assessment

| Change | Risk | Assessment |
|--------|------|-----------|
| `AIEngine` constructor gains optional params | None | All new params have defaults pointing to existing Python implementations. |
| `CContainerBackend` subclass added to `sandbox.py` | None | Additive. Parent `ContainerBackend` is unchanged. |
| `ContainerBackend.is_available(image=None)` gains optional param | None | Default behavior unchanged when called without argument. |
| Bridge resolver language filter expanded | Low | Currently Python-only. C findings were skipped; now they are processed. No regression for Python. |
| MCP `deep_scan_fuzz` schema gains optional `plugin` field | None | Default `"python"`. Existing callers unaffected. |
| `Config` gains `fuzz_c_container_image` field | None | Additive. |
| `pyproject.toml` adds C plugin entry point | None | Additive. |
| `DCS_FUZZ_ALLOWED_PLUGINS` default unchanged | None | Default remains `"python"`. Users must opt-in. |

**No breaking changes identified.** All modifications are additive with backward-compatible defaults.

---

## Dependency Assessment

| Dependency | Status | Risk |
|-----------|--------|------|
| `tree-sitter-c` (host) | Already in `pyproject.toml` line 28 | None |
| `tree-sitter` + `tree-sitter-c` (container) | PyPI install in Containerfile | Low -- pin versions to match host |
| `gcc:13-bookworm` (container base) | Docker Hub official | Low -- well-maintained, pinned to gcc 13 |
| `python3-minimal` (container) | Debian APT | Low -- standard package, includes all needed stdlib modules |

**No new Python host-side dependencies.** Container dependency chain is minimal and well-understood.

---

## Test Coverage Assessment

The plan specifies 21 files (12 test files + 3 fixture files + 1 integration test + 1 adversarial test + 4 others). Coverage appears comprehensive:

**Strengths:**
- Adversarial test file (`test_c_harness_validation_adversarial.py`) explicitly tests known evasion patterns and documents which ones are NOT caught by validation (function pointer aliasing).
- Test for sentinel value verifying it does NOT flow through `validate_expression()`.
- Test for `CContainerBackend` mount flags verifying `/workspace` has `noexec` and `/build` does not.
- Test for `AIEngine` extensibility verifying backward compatibility.
- Test for compilation circuit breaker.
- Test for `_dry_run` with C plugin.

**Gaps (minor):**
1. No test for `DCS_FUZZ_C_INCLUDE_PATHS` with ContainerBackend (how paths are mounted).
2. No test for bridge resolver handling `.h` files or unknown extensions.
3. No performance regression test for large C files (though tree-sitter handles this well).

---

## Verdict: PASS

The revised plan has properly resolved all four round-1 Critical findings and all Major findings. The design is security-sound, implementable, and backward compatible. The remaining concerns are adjustments that can be addressed during implementation without requiring plan revision.

### Recommended Adjustments (non-blocking)

1. **Major-1:** Add an assertion in `CContainerBackend._build_podman_cmd` that `podman_cmd[-1] == self._image` to guard against parent refactors changing the command structure.

2. **Major-2:** Specify bridge resolver behavior for unknown file extensions (skip with warning) and `.h` header files.

3. **Minor-1:** Pin tree-sitter/tree-sitter-c versions in the Containerfile to match host `pyproject.toml` constraints.

4. **Minor-2:** Specify that `DCS_FUZZ_C_INCLUDE_PATHS` entries are validated against `DCS_ALLOWED_PATHS` and mounted read-only in the container.

5. **Minor-3:** Add `--plugin` flag to `dcs hunt-fuzz` CLI and `plugin` field to `deep_scan_hunt_fuzz` MCP tool schema. List these in Files to Modify.

6. **Minor-4:** Resolve the circuit breaker location ambiguity: place it in the orchestrator's `run()` method, active only for C.

7. **Minor-5:** Add a seccomp validation integration test case (run a known-good ASan harness, verify ASan crash output rather than `EPERM`).

---

<!-- Context Metadata
reviewed_at: 2026-03-20
plan_file: plans/c-fuzzer-plugin.md
plan_status: DRAFT
reviewer: code-reviewer (feasibility, round 2)
round: 2
previous_verdict: PASS (with adjustments)
round1_critical_findings_resolved: 4/4
codebase_files_examined:
  - src/deep_code_security/fuzzer/plugins/base.py
  - src/deep_code_security/fuzzer/plugins/python_target.py
  - src/deep_code_security/fuzzer/plugins/registry.py
  - src/deep_code_security/fuzzer/execution/runner.py
  - src/deep_code_security/fuzzer/execution/sandbox.py
  - src/deep_code_security/fuzzer/models.py
  - src/deep_code_security/fuzzer/config.py
  - src/deep_code_security/fuzzer/orchestrator.py
  - src/deep_code_security/fuzzer/ai/engine.py
  - src/deep_code_security/fuzzer/ai/response_parser.py
  - src/deep_code_security/fuzzer/ai/expression_validator.py
  - src/deep_code_security/fuzzer/corpus/manager.py
  - src/deep_code_security/bridge/resolver.py
  - src/deep_code_security/mcp/server.py
  - src/deep_code_security/shared/config.py
  - plans/deep-code-security.md
  - plans/c-fuzzer-plugin.md
  - plans/c-fuzzer-plugin.feasibility.md (round 1)
  - plans/c-fuzzer-plugin.redteam.md (round 1)
  - plans/c-fuzzer-plugin.review.md (round 1)
-->
