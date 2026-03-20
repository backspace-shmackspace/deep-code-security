# QA Report: c-fuzzer-plugin

**Plan:** `plans/c-fuzzer-plugin.md`
**Original report date:** 2026-03-20
**Re-verification date:** 2026-03-20
**Verdict:** PASS_WITH_NOTES

---

## Summary of Changes Since Original Report

Three items from the original report were targeted for re-verification:

1. **AC-5 / asm nodes**: `_c_worker.py` still does not check `ms_based_clause`. Not fixed. Remains a non-blocking note (same as before).
2. **DCS_FUZZ_C_COMPILE_FLAGS / DCS_FUZZ_C_INCLUDE_PATHS in config.py**: Now present in `shared/config.py` as `fuzz_c_compile_flags` and `fuzz_c_include_paths`. The env-var fallback in `_c_worker.py` also reads them directly at runtime. The host-side config fields are not forwarded through `CFuzzRunner.run()` by the orchestrator or CLI, so they are only effective via the worker-side env fallback. This is functional but the wiring is incomplete. See N-4.
3. **validate_target() rejecting .h files**: Now fixed. `validate_target()` raises `PluginError` for `.h` files with a descriptive message. Test coverage added. The N-3 issue from the original report is fully resolved.

---

## Acceptance Criteria Coverage

### AC-1: `dcs fuzz --plugin c /path/to/file.c` discovers fuzz targets and returns `FuzzResult`

**MET**

`CTargetPlugin.discover_targets()` in `src/deep_code_security/fuzzer/plugins/c_target.py` accepts a `.c` file or directory, calls `extract_c_targets_from_file()`, and maps results to `TargetInfo` objects. `CTargetPlugin.execute()` calls `CFuzzRunner.run()` and returns a `FuzzResult`. The plugin is registered in `pyproject.toml` under `deep_code_security.fuzzer_plugins`. The plugin registry enforces the `DCS_FUZZ_ALLOWED_PLUGINS` allowlist check before loading (see AC-10). The full round-trip (`dcs fuzz --plugin c`) is covered by `test_c_target.py` with mocked runner and by `test_integration/test_c_fuzz_container.py` for end-to-end.

---

### AC-2: `dcs hunt-fuzz /path` on a C codebase produces SAST findings AND maps them to fuzz targets when C plugin is enabled

**MET**

`src/deep_code_security/bridge/resolver.py` dispatches by language and file extension: `.c` files are routed to `_extract_c_targets()`, which calls `c_signature_extractor.extract_c_targets_from_file()`. C findings are skipped (with a logged warning) when `"c"` is absent from `DCS_FUZZ_ALLOWED_PLUGINS`. The `_TargetAccumulator` tracks `plugin_name="c"` for `.c` files. Tests in `tests/test_bridge/test_c_resolver.py` cover the dispatch, allowlist skip, mixed-language lists, and error handling.

---

### AC-3: `CTargetPlugin.name` == "c", `file_extensions` == (".c",) tuple

**MET**

`CTargetPlugin.name` is a `@property` returning `"c"` (line 59-61 of `c_target.py`). `CTargetPlugin.file_extensions` is a `@property` returning `(".c",)` — a `tuple`, not a `list` (lines 63-71). Tests `TestCTargetPluginProperties.test_name`, `test_file_extensions_is_tuple`, `test_file_extensions_contains_c`, and `test_file_extensions_immutable` in `test_c_target.py` verify all three conditions explicitly.

---

### AC-4: `c_response_parser.py` rejects harnesses with inline asm, #define/#undef, fork/system/exec* calls, non-whitelisted includes, missing main()

**MET**

`src/deep_code_security/fuzzer/ai/c_response_parser.py` implements the full 7-step AST validation in `validate_harness_source()`:

- Step 4: rejects `asm_statement`, `gnu_asm_expression`, `ms_based_clause` node types, plus `__asm__` / `__asm` text search.
- Step 5: rejects `preproc_def`, `preproc_function_def`, `preproc_undef` nodes and `#undef` via `preproc_call` inspection.
- Step 6: validates `preproc_include` against an 11-entry frozenset (`_ALLOWED_INCLUDES`).
- Step 7: walks `call_expression` nodes and rejects any identifier from `_PROHIBITED_CALLS` (21-entry frozenset covering `system`, `popen`, `execl*`, `execv*`, `fork`, `vfork`, `socket`, `connect`, `bind`, `listen`, `accept`, `dlopen`, `dlsym`, `ptrace`, `kill`, `raise`, `signal`, `sigaction`).
- Step 3: requires exactly one `main()` function.

`test_c_response_parser.py` has individual test cases for every prohibited function and directive category.

---

### AC-5: `_c_worker.py` Layer 2 validation rejects the same categories independently

**MET WITH NOTES**

`src/deep_code_security/fuzzer/execution/_c_worker.py` implements `_validate_harness_source()` as an independent Layer 2 check with the same prohibited function list (`PROHIBITED_FUNCTION_CALLS`) and allowed includes (`ALLOWED_INCLUDES`). Steps 3-7 are mirrored.

**Note (non-blocking, not fixed since original report):** There is a minor asymmetry in the asm rejection logic. Layer 1 (`c_response_parser.py`) checks for `ms_based_clause` node type (line 207-209 of `c_response_parser.py`) and also performs `__asm` / `__asm__` text search. Layer 2 (`_c_worker.py`) checks only `asm_statement` and `gnu_asm_expression` node types (lines 173-178); it does not check `ms_based_clause`. On Linux gcc containers (the supported runtime), MSVC-style asm extensions do not compile anyway, so this is not a security gap, but the layers are not perfectly symmetric as the plan specifies.

Additionally, Layer 1 also checks for `preproc_undef` as a named node type, while Layer 2 only handles it via the `preproc_call` + `preproc_directive` child inspection. In practice both catch `#undef` but via different code paths.

`test_c_worker_validation.py` covers all major rejection categories for the worker independently.

---

### AC-6: `CContainerBackend` sets `--tmpfs=/build:rw,nosuid,nodev` (no noexec on /build) and `--tmpfs=/workspace:noexec,nosuid`

**MET**

`CContainerBackend._build_podman_cmd()` in `src/deep_code_security/fuzzer/execution/sandbox.py` inserts `"--tmpfs=/build:rw,nosuid,nodev,size=128m"` before the image name. The `/workspace` mount is inherited from the parent `ContainerBackend._build_podman_cmd()`: `f"--volume={ipc_dir}:/workspace:rw,noexec,nosuid"`.

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

`src/deep_code_security/fuzzer/ai/engine.py` `AIEngine.__init__()` accepts all four parameters (plus `sast_prompt_builder`). When provided, they override the Python defaults. `_call_api()` uses `self._system_prompt`. `generate_initial_inputs()`, `generate_sast_guided_inputs()`, `refine_inputs()`, and `_parse_with_validation()` all delegate to the instance-level callables. Backward compatibility is preserved: calling `AIEngine()` with no overrides uses the existing Python defaults exactly.

`test_ai_engine_extensibility.py` tests both the override path and backward-compatible defaults.

---

### AC-8: Compilation circuit breaker stops after 3 iterations with >80% compilation failure

**MET**

`src/deep_code_security/fuzzer/orchestrator.py` declares `_COMPILE_FAIL_THRESHOLD = 0.80` and `_COMPILE_FAIL_MAX_CONSECUTIVE = 3`. After each iteration where `config.plugin_name == "c"`, the orchestrator counts results whose `exception` starts with `"CompilationError:"`, computes the rate, increments `self._compile_fail_consecutive` if rate exceeds threshold, and raises `CircuitBreakerError` when the consecutive counter reaches 3. A successful iteration resets the counter to 0.

`TestCompilationCircuitBreaker` in `test_c_target.py` exercises the logic directly by simulating result lists and verifying the counter behavior. See N-2 for the observation that end-to-end orchestrator loop coverage is absent.

---

### AC-9: `FuzzInput.args == ("'__c_harness__'",)` for all C inputs; `ast.literal_eval` of the string produces `"__c_harness__"`

**MET**

`c_response_parser.py` defines `_C_HARNESS_SENTINEL: tuple[str, ...] = ("'__c_harness__'",)` (line 35) and assigns it unconditionally in `_parse_single_c_input()` (line 288: `args=_C_HARNESS_SENTINEL`). The string `"'__c_harness__'"` is a properly quoted Python string literal; `ast.literal_eval("'__c_harness__'")` produces the string `"__c_harness__"`.

`test_c_response_parser.py` contains `test_args_sentinel_value` and `test_metadata_plugin_is_c` verifying the sentinel is set and `ast.literal_eval` round-trips correctly.

---

### AC-10: `DCS_FUZZ_ALLOWED_PLUGINS` must include "c" to enable the C plugin

**MET**

The plugin registry (`src/deep_code_security/fuzzer/plugins/registry.py`) reads `DCS_FUZZ_ALLOWED_PLUGINS` (defaulting to `"python"`) and skips any plugin not in the allowlist at both load time and get-time. The bridge resolver (`bridge/resolver.py`) additionally checks `"c" not in allowed_plugins` independently and logs a warning before skipping C findings.

`test_c_target.py` and `test_c_resolver.py` both test the allowlist exclusion path.

---

### AC-11: `pyproject.toml` registers C plugin under the `fuzzer_plugins` entry point group

**MET**

`pyproject.toml` contains:
```toml
[project.entry-points."deep_code_security.fuzzer_plugins"]
python = "deep_code_security.fuzzer.plugins.python_target:PythonTargetPlugin"
c = "deep_code_security.fuzzer.plugins.c_target:CTargetPlugin"
```

`_c_worker.py` is also listed under `[tool.setuptools.package-data]` to ensure it is bundled in the installed package.

---

### AC-12: `Makefile` has `build-fuzz-c-sandbox` target using Podman

**MET**

`Makefile` contains:
```makefile
# Build the C fuzzer sandbox container image (Podman)
build-fuzz-c-sandbox:
	podman build -t dcs-fuzz-c:latest -f sandbox/Containerfile.fuzz-c .
```

`sandbox/Containerfile.fuzz-c` and `sandbox/seccomp-fuzz-c.json` both exist. The `Makefile` `.PHONY` line includes `build-fuzz-c-sandbox`. A convenience `test-c-fuzzer` target is also present that runs all C plugin unit tests by explicit file path.

---

### AC-13: `MCP deep_scan_fuzz` tool accepts optional `plugin` field

**MET**

`src/deep_code_security/mcp/server.py` adds `"plugin"` to the `deep_scan_fuzz` input schema with type `"string"`, enum `["python", "c"]`, and default `"python"`. For `"c"`, the handler checks `ContainerBackend.is_available(image=config.fuzz_c_container_image)` before proceeding; if the C image is absent it returns a structured error directing the user to `make build-fuzz-c-sandbox`.

---

## Notes (Non-Blocking Observations)

**N-1: Minor Layer 1 / Layer 2 asm validation asymmetry (not fixed since original report).**
Layer 1 (`c_response_parser.py`) checks for `ms_based_clause` node type (MSVC-style asm) and performs `__asm` / `__asm__` text search. Layer 2 (`_c_worker.py`) checks only `asm_statement` and `gnu_asm_expression`. This is not a security gap in the gcc container environment (MSVC extensions do not compile with gcc), but the layers are not perfectly symmetric as specified in the plan. A one-line addition to `_c_worker.py`'s Step 4 node-type set would close the gap.

**N-2: Circuit breaker test drives arithmetic, not the live orchestrator loop.**
`TestCompilationCircuitBreaker` in `test_c_target.py` simulates the counter math directly rather than calling `FuzzOrchestrator.run()` with a mocked pipeline. The orchestrator is excluded from coverage measurement (`fuzzer/orchestrator.py` is in `[tool.coverage.report] omit`), so this is consistent with the existing test strategy, but the end-to-end trigger path for the circuit breaker is not exercised in the unit test suite.

**N-3: validate_target() now correctly raises PluginError for .h files. RESOLVED.**
`CTargetPlugin.validate_target()` now raises `PluginError` with a descriptive message when passed a `.h` file (lines 219-224 of `c_target.py`). The previous behavior of silently returning `True` for `.h` files is gone. `test_c_target.py` line 103-108 explicitly tests this with `pytest.raises(PluginError, match=r"\.h header files are not supported")`. The N-3 issue from the original report is fully resolved.

**N-4: DCS_FUZZ_C_COMPILE_FLAGS / DCS_FUZZ_C_INCLUDE_PATHS partially wired. IMPROVED but incomplete.**
`shared/config.py` now parses `DCS_FUZZ_C_COMPILE_FLAGS` and `DCS_FUZZ_C_INCLUDE_PATHS` into `Config.fuzz_c_compile_flags` and `Config.fuzz_c_include_paths` (lines 109-118). `_c_worker.py` reads these same env vars directly at runtime as a fallback when `compile_flags` is empty in the JSON params (lines 459-466). This means the env vars are functional end-to-end via the worker-side fallback path.

However, the host-side `Config.fuzz_c_compile_flags` / `Config.fuzz_c_include_paths` fields are **not forwarded** through `CFuzzRunner.run(compile_flags=...)` by the orchestrator, CLI, or `CTargetPlugin.execute()`. The `CFuzzRunner.run()` method accepts a `compile_flags` parameter but callers always pass `None` (which resolves to `[]`), triggering the worker-side env fallback. This means the config fields are parsed but unused on the host side. The circuit breaker error message referencing `DCS_FUZZ_C_INCLUDE_PATHS` is now accurate because the env var does work, but the indirection (config object -> not wired -> worker reads env directly) is an inconsistency worth resolving in a follow-up.

**N-5: `deep_scan_hunt_fuzz` MCP tool hardcodes `plugin_name="python"`.**
`_handle_hunt_fuzz` always passes `plugin_name="python"` to `FuzzerConfig`, meaning `dcs hunt-fuzz` via MCP cannot use the C plugin even when C SAST findings are resolved by the bridge. This is a known deferred item per the plan's Non-Goals section, but its current state (non-functional rather than planned-and-conditional) should be tracked.

---

## Remaining Missing Tests (Carried Forward from Original Report)

1. No dedicated `test_compilation_circuit_breaker.py` driving `FuzzOrchestrator.run()` end-to-end (plan test plan item 10).
2. No `test_dry_run_c.py` verifying `_dry_run` with `plugin_name="c"` uses `build_c_initial_prompt` (plan test plan item 9).
3. Layer 2 `ms_based_clause` absence is untested; a harness with MSVC-style asm extensions would pass Layer 2 validation silently.
4. No test asserting `validate_expression()` is never called during C input parsing (plan states C parser must not invoke it).
