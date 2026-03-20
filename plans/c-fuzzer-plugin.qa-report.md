# QA Report: c-fuzzer-plugin

**Plan:** `plans/c-fuzzer-plugin.md`
**Date:** 2026-03-20
**Verdict:** PASS_WITH_NOTES

---

## Acceptance Criteria Coverage

### AC-1: `dcs fuzz --plugin c /path/to/file.c` discovers fuzz targets and returns `FuzzResult`

**MET**

`CTargetPlugin.discover_targets()` in `src/deep_code_security/fuzzer/plugins/c_target.py` accepts a `.c` file or directory, calls `extract_c_targets_from_file()`, and maps results to `TargetInfo` objects. `CTargetPlugin.execute()` calls `CFuzzRunner.run()` and returns a `FuzzResult`. The plugin is registered in `pyproject.toml` under `deep_code_security.fuzzer_plugins`. The plugin registry enforces the `DCS_FUZZ_ALLOWED_PLUGINS` allowlist check before loading (see AC-10). The full round-trip (`dcs fuzz --plugin c`) is covered by `test_c_target.py` with mocked runner and by `test_integration/test_c_fuzz_container.py` for end-to-end.

---

### AC-2: `dcs hunt-fuzz /path` on a C codebase produces SAST findings AND maps them to fuzz targets when C plugin is enabled

**MET**

`src/deep_code_security/bridge/resolver.py` now dispatches by language and file extension: `.c` files are routed to `_extract_c_targets()`, which calls `c_signature_extractor.extract_c_targets_from_file()`. C findings are skipped (with a logged warning) when `"c"` is absent from `DCS_FUZZ_ALLOWED_PLUGINS`. The `_TargetAccumulator` tracks `plugin_name="c"` for `.c` files. Tests in `tests/test_bridge/test_c_resolver.py` cover the dispatch, allowlist skip, mixed-language lists, and error handling.

---

### AC-3: `CTargetPlugin.name` == "c", `file_extensions` == (".c",) tuple

**MET**

`CTargetPlugin.name` is a `@property` returning `"c"` (line 59-61 of `c_target.py`). `CTargetPlugin.file_extensions` is a `@property` returning `(".c",)` — a `tuple`, not a `list` (lines 63-71). Tests `TestCTargetPluginProperties.test_name`, `test_file_extensions_is_tuple`, `test_file_extensions_contains_c`, and `test_file_extensions_immutable` in `test_c_target.py` verify all three conditions explicitly.

---

### AC-4: `c_response_parser.py` rejects harnesses with inline asm, #define/#undef, fork/system/exec* calls, non-whitelisted includes, missing main()

**MET**

`src/deep_code_security/fuzzer/ai/c_response_parser.py` implements the full 7-step AST validation in `validate_harness_source()`:

- Step 4: rejects `asm_statement`, `gnu_asm_expression`, `ms_based_clause` node types, plus `__asm__` text search.
- Step 5: rejects `preproc_def`, `preproc_function_def`, `preproc_undef` nodes and `#undef` via `preproc_call` inspection.
- Step 6: validates `preproc_include` against an 11-entry frozenset (`_ALLOWED_INCLUDES`).
- Step 7: walks `call_expression` nodes and rejects any identifier from `_PROHIBITED_CALLS` (21-entry frozenset covering `system`, `popen`, `execl*`, `execv*`, `fork`, `vfork`, `socket`, `connect`, `bind`, `listen`, `accept`, `dlopen`, `dlsym`, `ptrace`, `kill`, `raise`, `signal`, `sigaction`).
- Step 3: requires exactly one `main()` function.

`test_c_response_parser.py` has individual test cases for every prohibited function and directive category.

---

### AC-5: `_c_worker.py` Layer 2 validation rejects the same categories independently

**MET WITH NOTES**

`src/deep_code_security/fuzzer/execution/_c_worker.py` implements `_validate_harness_source()` as an independent Layer 2 check with the same prohibited function list (`PROHIBITED_FUNCTION_CALLS`) and allowed includes (`ALLOWED_INCLUDES`). Steps 3-7 are mirrored.

**Note (non-blocking):** There is a minor asymmetry in the asm rejection logic. Layer 1 (`c_response_parser.py`) also checks for `ms_based_clause` node type. Layer 2 (`_c_worker.py`) checks only `asm_statement` and `gnu_asm_expression` node types; it does not check `ms_based_clause`. On Linux gcc containers (the supported runtime), MSVC-style asm extensions do not compile anyway, so this is not a security gap, but the layers are not perfectly symmetric as the plan specifies.

Additionally, Layer 1 also checks for `preproc_undef` as a named node type, while Layer 2 only handles it via the `preproc_call` + `preproc_directive` child inspection. In practice both catch `#undef` but via different code paths.

`test_c_worker_validation.py` covers all major rejection categories for the worker independently.

---

### AC-6: `CContainerBackend` sets `--tmpfs=/build:rw,nosuid,nodev` (no noexec on /build) and `--tmpfs=/workspace:noexec,nosuid`

**MET**

`CContainerBackend._build_podman_cmd()` in `src/deep_code_security/fuzzer/execution/sandbox.py` (line 439) inserts `"--tmpfs=/build:rw,nosuid,nodev,size=128m"` before the image name. The `/workspace` mount is inherited from the parent `ContainerBackend._build_podman_cmd()` at line 279: `f"--volume={ipc_dir}:/workspace:rw,noexec,nosuid"`.

`test_c_container_backend.py` explicitly verifies:
- `/build` tmpfs is present
- `/build` does NOT have `noexec`
- `/build` has `nosuid` and `nodev`
- `/workspace` has `noexec` and `nosuid`
- The two mounts are separate arguments
- Python `ContainerBackend` does not gain a `/build` mount (regression test)

---

### AC-7: `AIEngine` is extensible: accepts `system_prompt`, `initial_prompt_builder`, `refinement_prompt_builder`, `response_parser_fn`

**MET**

`src/deep_code_security/fuzzer/ai/engine.py` `AIEngine.__init__()` accepts all four parameters (plus `sast_prompt_builder`) at lines 120-124. When provided, they override the Python defaults (`self._system_prompt`, `self._initial_prompt_builder`, `self._refinement_prompt_builder`, `self._sast_prompt_builder`, `self._response_parser_fn`). `_call_api()` uses `self._system_prompt` (line 301). `generate_initial_inputs()`, `generate_sast_guided_inputs()`, `refine_inputs()`, and `_parse_with_validation()` all delegate to the instance-level callables. Backward compatibility is preserved: calling `AIEngine()` with no overrides uses the existing Python defaults exactly.

`test_ai_engine_extensibility.py` tests both the override path and backward-compatible defaults.

---

### AC-8: Compilation circuit breaker stops after 3 iterations with >80% compilation failure

**MET**

`src/deep_code_security/fuzzer/orchestrator.py` declares `_COMPILE_FAIL_THRESHOLD = 0.80` and `_COMPILE_FAIL_MAX_CONSECUTIVE = 3`. After each iteration where `config.plugin_name == "c"`, the orchestrator counts results whose `exception` starts with `"CompilationError:"`, computes the rate, increments `self._compile_fail_consecutive` if rate exceeds threshold, and raises `CircuitBreakerError` when the consecutive counter reaches 3. A successful iteration resets the counter to 0.

`TestCompilationCircuitBreaker` in `test_c_target.py` exercises the logic directly by simulating result lists and verifying the counter behavior. However, see note below under Missing Tests.

---

### AC-9: `FuzzInput.args == ("'__c_harness__'",)` for all C inputs; `ast.literal_eval` of the string produces `"__c_harness__"`

**MET**

`c_response_parser.py` defines `_C_HARNESS_SENTINEL: tuple[str, ...] = ("'__c_harness__'",)` (line 35) and assigns it unconditionally in `_parse_single_c_input()` (line 288: `args=_C_HARNESS_SENTINEL`). The string `"'__c_harness__'"` is a properly quoted Python string literal; `ast.literal_eval("'__c_harness__'")` produces the string `"__c_harness__"`.

`test_c_response_parser.py` contains `test_args_sentinel_value` and `test_metadata_plugin_is_c` verifying the sentinel is set and `ast.literal_eval` round-trips correctly.

---

### AC-10: `DCS_FUZZ_ALLOWED_PLUGINS` must include "c" to enable the C plugin

**MET**

The plugin registry (`src/deep_code_security/fuzzer/plugins/registry.py`) reads `DCS_FUZZ_ALLOWED_PLUGINS` (defaulting to `"python"`) and skips any plugin not in the allowlist at both load time and get-time. The bridge resolver (`bridge/resolver.py` lines 89-99) additionally checks `"c" not in allowed_plugins` independently and logs a warning before skipping C findings.

`test_c_target.py` and `test_c_resolver.py` both test the allowlist exclusion path.

---

### AC-11: `pyproject.toml` registers C plugin under the `fuzzer_plugins` entry point group

**MET**

`pyproject.toml` lines 65-67:
```toml
[project.entry-points."deep_code_security.fuzzer_plugins"]
python = "deep_code_security.fuzzer.plugins.python_target:PythonTargetPlugin"
c = "deep_code_security.fuzzer.plugins.c_target:CTargetPlugin"
```

`_c_worker.py` is also listed under `[tool.setuptools.package-data]` (line 77) to ensure it is bundled in the installed package.

---

### AC-12: `Makefile` has `build-fuzz-c-sandbox` target using Podman

**MET**

`Makefile` lines 108-110:
```makefile
# Build the C fuzzer sandbox container image (Podman)
build-fuzz-c-sandbox:
	podman build -t dcs-fuzz-c:latest -f sandbox/Containerfile.fuzz-c .
```

`sandbox/Containerfile.fuzz-c` and `sandbox/seccomp-fuzz-c.json` both exist. The `Makefile` `.PHONY` line (line 1-4) includes `build-fuzz-c-sandbox`. A convenience `test-c-fuzzer` target is also present (lines 69-78) that runs all C plugin unit tests by explicit file path.

---

### AC-13: `MCP deep_scan_fuzz` tool accepts optional `plugin` field

**MET**

`src/deep_code_security/mcp/server.py` lines 377-386 add `"plugin"` to the `deep_scan_fuzz` input schema with type `"string"`, enum `["python", "c"]`, and default `"python"`. At request time (line 981), `plugin = str(params.get("plugin", "python")).lower()` routes the call. For `"c"`, the handler checks `ContainerBackend.is_available(image=config.fuzz_c_container_image)` before proceeding; if the C image is absent it returns a structured error directing the user to `make build-fuzz-c-sandbox`.

Tool registration itself fires only when at least one image (Python or C) is available, checked per-plugin via the `image=` parameter on `ContainerBackend.is_available()`.

---

## Missing Tests or Edge Cases

1. **No dedicated `test_compilation_circuit_breaker.py` file.** The plan's test plan (item 10) calls for `test_compilation_circuit_breaker.py` as a standalone test module. The actual tests for the circuit breaker logic exist in `test_c_target.py` under `TestCompilationCircuitBreaker`, but they test the counter arithmetic in isolation — they do not drive the orchestrator's `run()` loop end-to-end with a mocked plugin. An integration-level test that runs `FuzzOrchestrator.run()` with a C plugin stub that always returns `CompilationError` results, verifying that `CircuitBreakerError` is raised after exactly 3 iterations, is absent.

2. **No `test_dry_run_c.py`.** The plan's test plan (item 9) calls for a dedicated file verifying that `_dry_run` with `config.plugin_name == "c"` uses `build_c_initial_prompt` and prints the "C plugin" label. This is untested.

3. **`test_c_bridge_resolver.py` does not cover all plan-listed scenarios.** The test plan (item 6) calls for testing `dcs hunt-fuzz` producing correlated fuzz results. The existing `test_c_resolver.py` tests the resolver function unit behavior; end-to-end `dcs hunt-fuzz` on a C codebase with correlated output is only addressed by the integration test (which requires Podman).

4. **Layer 2 asm asymmetry untested.** The `ms_based_clause` node type present in Layer 1 (`c_response_parser.py`) but absent from Layer 2 (`_c_worker.py`) rejection logic is not explicitly tested. A harness containing `__declspec`-style MSVC extensions that produce an `ms_based_clause` AST node would pass Layer 2 validation. This is low risk on Linux gcc but the asymmetry is undocumented in tests.

5. **No test for `validate_expression()` NOT being called in the C parser.** The plan explicitly states the C response parser must not invoke `validate_expression()`. The docstrings document this, but there is no test that mocks `validate_expression` and asserts it is never called during C input parsing.

6. **`test_c_harness_validation_adversarial.py` exists but was not fully inspected.** The adversarial test file is present and covers the documented limitation (function pointer aliasing not caught). Coverage of all adversarial cases from plan item 12 should be confirmed when running `make test-fuzzer`.

---

## Notes (Non-Blocking Observations)

**N-1: Minor Layer 1 / Layer 2 asm validation asymmetry.**
Layer 1 (`c_response_parser.py`) checks for `ms_based_clause` node type (MSVC-style asm); Layer 2 (`_c_worker.py`) does not. This is not a security gap in the gcc container environment but reduces validation parity between the two layers. Worth documenting in a follow-up comment or aligning in a minor patch.

**N-2: Circuit breaker test drives arithmetic, not the live orchestrator loop.**
`TestCompilationCircuitBreaker` in `test_c_target.py` simulates the counter math directly rather than calling `FuzzOrchestrator.run()` with a mocked pipeline. The orchestrator is excluded from coverage measurement (`fuzzer/orchestrator.py` is in `[tool.coverage.report] omit`), so this is consistent with the existing test strategy, but the end-to-end trigger path for the circuit breaker is not exercised in the unit test suite.

**N-3: `validate_target()` accepts `.h` files.**
`CTargetPlugin.validate_target()` returns `True` for `.h` files (line 219: `if p.suffix not in (".c", ".h")`), but `file_extensions` only declares `(".c",)`. This means a user passing a `.h` file to `discover_targets()` will pass `validate_target()` but then call `extract_c_targets_from_file()` on a header, which may return zero targets or partial results. This is a usability inconsistency, not a security issue.

**N-4: `DCS_FUZZ_C_COMPILE_FLAGS` and `DCS_FUZZ_C_INCLUDE_PATHS` are referenced in plan Section 16 but not observed wired into `FuzzerConfig`.**
The `shared/config.py` adds `fuzz_c_container_image` but the plan also specifies `DCS_FUZZ_C_COMPILE_FLAGS` and `DCS_FUZZ_C_INCLUDE_PATHS` environment variables. These were not found in `config.py` or `FuzzerConfig`. If compile flags and include paths cannot be configured, the circuit breaker's error message (which references `DCS_FUZZ_C_INCLUDE_PATHS`) may be misleading. This warrants a follow-up check or a small config addition.

**N-5: `deep_scan_hunt_fuzz` MCP tool hardcodes `plugin_name="python"` (line 1406 of `server.py`).**
The plan's Non-Goals section acknowledges this: "MCP `deep_scan_fuzz` C support [via `deep_scan_hunt_fuzz`] is included in this plan, but the C container image must be available for it to work." However, `_handle_hunt_fuzz` always passes `plugin_name="python"` to `FuzzerConfig`, meaning `dcs hunt-fuzz` via MCP cannot use the C plugin even when C SAST findings are resolved by the bridge. This is a known deferred item but its current state (non-functional rather than planned) should be tracked.
