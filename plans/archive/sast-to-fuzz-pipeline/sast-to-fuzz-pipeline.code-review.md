# Code Review: sast-to-fuzz-pipeline

**Reviewer:** code-reviewer agent
**Date:** 2026-03-17
**Plan:** `plans/sast-to-fuzz-pipeline.md` (APPROVED)
**Verdict:** REVISION_NEEDED

---

## Summary

The implementation is architecturally sound and faithfully follows the plan across most components. The bridge models, resolver, CWE guidance map, correlation logic, protocol extensions, and test suites are all well-structured. Two correctness bugs prevent a PASS: a `NameError` that will crash every hunt-fuzz background thread that encounters a crash, and a key mismatch that silently drops SAST context enrichment for class method targets.

---

## Critical Issues (Must Fix)

### C-1: `validate_crash_data` is not imported — guaranteed `NameError` in the fuzz thread

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/mcp/server.py`
**Lines:** 24–28 (imports), 1235 (call site)

The module-level import block from `mcp.input_validator` includes only `InputValidationError`, `validate_function_name`, and `validate_raw_finding`. The name `validate_crash_data` is never imported — not at the module level and not locally within `_run_hunt_fuzz()`. Every hunt-fuzz run that produces at least one crash will hit `NameError: name 'validate_crash_data' is not defined` inside the background thread, causing the thread to transition to `"failed"` state. This defeats the crash-data sanitization requirement and silently drops the correlation report.

The plan (line 641) explicitly requires sanitizing crash signatures through `validate_crash_data()` before storage. The test `test_hunt_fuzz_correlation_crash_data_sanitized` patches `validate_crash_data` at the `mcp.server` namespace, which means the test would pass even without the import (the patch installs the name), masking the production bug.

**Fix:** Add `validate_crash_data` to the existing import block:

```python
from deep_code_security.mcp.input_validator import (
    InputValidationError,
    validate_crash_data,
    validate_function_name,
    validate_raw_finding,
)
```

---

### C-2: `sast_contexts` dict is keyed by `function_name` but `build_sast_enriched_prompt()` looks up by `qualified_name`

**Files:**
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/mcp/server.py` line 1191
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/cli.py` line 835
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/fuzzer/ai/prompts.py` line 214

Both the MCP handler and the CLI build the `sast_contexts` dict keyed by `t.function_name`:

```python
sast_contexts = {t.function_name: t.sast_context for t in _fuzz_targets}
```

However, `build_sast_enriched_prompt()` looks up context by `target.qualified_name` (line 214 in `prompts.py`). For class methods, `FuzzTarget.function_name` is the qualified name (`"MyClass.handle"`) as set by `resolver.py` (`containing.qualified_name`), so they actually agree in this implementation. But the plan section on `FuzzTarget` (and the model definition) describes `function_name` as the qualified name (`"Function name (or Class.method)"`), making this consistent by convention, not by type contract.

The actual bug manifests in `build_sast_enriched_prompt()` where `targets` are `TargetInfo` objects discovered by the fuzzer plugin at runtime. For a class method, the fuzzer plugin's `discover_targets()` uses `include_instance_methods=False` by default and would not discover instance methods at all (they are filtered out). For a standalone function, `qualified_name == function_name`. So in practice the SAST context lookup silently returns `None` for any instance method target (because the fuzzer won't discover those, so there are no `TargetInfo` objects to look up against), but will work correctly for standalone functions.

The deeper issue is that the `FuzzerConfig.target_functions` filter at `orchestrator.py` lines 120–125 matches against both `t.function_name` and `t.qualified_name`, so filtering works. But the `sast_contexts` key used to enrich the prompt must match the key used in the prompt lookup. If a future change renames `FuzzTarget.function_name` to hold only the bare name (not the qualified name), this silently breaks enrichment.

**Fix:** Use `t.function_name` consistently as the key everywhere (which matches `qualified_name` per the model description), or make the type contract explicit in a comment at the dict construction site. Add an assertion or test case that verifies prompt enrichment works for a class method target by qualified name.

---

## Major Issues (Should Fix)

### M-1: Multi-file bridge result uses only the first target's file path for the entire fuzz run

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/mcp/server.py` line 1193

```python
fuzz_target_path = _fuzz_targets[0].file_path
```

The bridge can produce targets from multiple different files (e.g., `utils.py` and `validators.py` both have findings). The `FuzzerConfig.target_path` is set to only the first target's file, so the fuzzer's `discover_targets()` will only look in that one file. Targets from other files will be in `FuzzerConfig.target_functions` but the plugin will never find them during discovery, causing the orchestrator to fall back to fuzzing all targets in the first file (line 127: `targets = all_targets`).

The plan does not address this multi-file scenario explicitly, which is a gap. For the MVP this is likely low-impact since many codebases concentrate tainted code in one module, but it is a silent correctness failure.

**Fix:** Set `target_path` to the common parent directory of all fuzz targets (using `Path(fuzz_target_path).parent` or the original `path` argument), so the plugin discovers all relevant files. The CLI already handles this correctly by using the full `path` argument.

---

### M-2: Missing test: `test_hunt_fuzz_correlation_crash_data_sanitized` does not verify the import fix

**File:** `/Users/imurphy/projects/deep-code-security/tests/test_mcp/test_hunt_fuzz.py` lines 263–328

The test patches `deep_code_security.mcp.server.validate_crash_data`, which installs the name into the module namespace regardless of whether the actual import exists. This means the test passes both with and without the missing import in C-1. The test does not catch the production bug.

**Fix:** After adding the import (C-1), the test remains correct. Additionally, add a test that verifies `validate_crash_data` is callable from `deep_code_security.mcp.server` without patching — e.g., `from deep_code_security.mcp.server import validate_crash_data` or an attribute check on the module.

---

### M-3: `FuzzFormatter` protocol must not be implemented by formatters that also implement `HybridFormatter`, but the plan requires text/json/sarif to implement both — verify no accidental method collision

**Files:**
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/formatters/text.py`
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/formatters/json.py`
- `/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/formatters/sarif.py`

The plan correctly separates `HybridFormatter` from `FuzzFormatter` to avoid breaking `isinstance(formatter, FuzzFormatter)` checks. Confirmed: `html.py` has no `format_hunt_fuzz` method, and the three formatters that implement `format_hunt_fuzz` do so additively. The `FuzzFormatter` protocol is unmodified. This is implemented correctly.

No action needed — this is a confirmation, not a finding.

---

## Minor Issues (Consider)

### N-1: `_run_hunt_fuzz` captures `bridge_summary` from the outer scope but sets `run_state.bridge_result` only after fuzz completes

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/mcp/server.py` line 1262

`run_state.bridge_result = bridge_summary` is set at line 1262, inside the thread, only after the fuzz run and correlation are complete. A client polling during an active run will see `bridge_result=None`. Moving the assignment before the thread starts (since `bridge_summary` is already computed synchronously) would give clients immediate visibility into the bridge result while the fuzz is still running. This is not a correctness bug since the handler already returns `bridge_summary` in its synchronous response, but for the status-polling path it is inconsistent.

---

### N-2: `_find_containing_function` innermost-span tie-breaking has an off-by-one risk

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/bridge/resolver.py` lines 188–191

```python
if best is None or span < best_range:
    best = target
    best_range = span
```

When two functions have identical `lineno..end_lineno` spans (which cannot happen in valid Python AST but could occur if `TargetInfo` is constructed manually in tests), the first one wins. This is safe in production but could cause test flakiness if test fixtures create overlapping spans. Consider using `span <= best_range` with a secondary sort key (e.g., deeper nesting / larger `lineno`) if this becomes an issue.

---

### N-3: `BridgeOrchestrator` is a thin wrapper with no state — could be a module-level function

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/bridge/orchestrator.py`

`BridgeOrchestrator` has no `__init__`, no instance state, and both methods delegate immediately to other functions. This follows the established per-phase `orchestrator.py` pattern from CLAUDE.md, so it is architecturally consistent. However, if state (e.g., caching parsed files across multiple `run_bridge` calls) is never added, the class wrapper adds no value over two module-level functions. No action needed unless the class grows.

---

### N-4: `SASTContext.severity` is not validated against the four canonical values

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/bridge/models.py` line 34

```python
severity: str = Field(default="medium", description="Highest severity among findings")
```

The field accepts any string. If a `RawFinding.severity` contains an unexpected value (e.g., from a future registry change), `_SEVERITY_ORDER.get(s, 0)` silently treats it as lower than "low", and the sorting/cap logic will produce incorrect results without any error. Consider a Pydantic `field_validator` or `Literal["critical", "high", "medium", "low"]` type annotation to enforce the invariant at construction time.

---

### N-5: `os` is imported in `resolver.py` but only used for `os.environ.get()`

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/bridge/resolver.py` line 6

`import os` is present and used only for `os.environ.get("DCS_BRIDGE_MAX_TARGETS", "10")`. This is fine but `os.environ` could be replaced with `os.getenv()` (same module), or the pattern could use `pathlib` conventions. Not a bug; lint will catch any actual unused imports.

---

## What Went Well

**Security posture is strong throughout.** No `shell=True`, no `eval()`, no `yaml.load()`. The `CWE_FUZZ_GUIDANCE` map uses only hardcoded strings, never user-supplied data. The SAST context is placed outside `<target_source_code>` delimiters to prevent prompt injection confusion. The plan's trust boundary analysis correctly identifies that bridge sits between two trusted components.

**Crash data sanitization design is correct.** The intent and placement of `validate_crash_data()` calls in `_run_hunt_fuzz()` are correct — the fix is simply the missing import. The fallback `sig[:2048]` at line 1242 ensures the thread does not fail silently even if sanitization raises.

**`TargetInfo` field additions are clean and backward-compatible.** Adding `lineno: int | None = None`, `end_lineno: int | None = None`, and `is_instance_method: bool = False` with safe defaults means all existing `TargetInfo` construction sites in tests and production code are unaffected.

**`extract_targets_from_source()` parameter addition is non-breaking.** The `include_instance_methods: bool = False` default preserves all existing fuzzer behavior. The bridge is the only caller that passes `True`.

**`FuzzTarget.function_name` stores the qualified name.** The resolver correctly uses `containing.qualified_name` (e.g., `"MyClass.handle"`) as `function_name`, which means the `FuzzerConfig.target_functions` filter at `orchestrator.py` lines 120–125 will correctly match against either `t.function_name` or `t.qualified_name`. This eliminates a potential silent miss.

**`crash_in_finding_scope` field name is correct** — not `fuzz_confirmed`. The docstring disclaimer ("Does NOT imply the SAST vulnerability was exploited") is present and accurate.

**`BridgeResult.not_directly_fuzzable` counter is correctly incremented and surfaced** in both the MCP response (`bridge_summary`) and the CLI output. This is the key user-facing diagnostic for the framework-route-handler limitation.

**`HybridFormatter` is correctly separated from `FuzzFormatter`.** The HTML formatter is correctly left unmodified. The `supports_hybrid()` helper follows the established `supports_fuzz()` pattern. The `@runtime_checkable` decorator is present on `HybridFormatter`.

**`FuzzerConfig.sast_contexts` field uses `exclude=True`**, preventing accidental serialization of internal bridge state.

**Test coverage is comprehensive** for the bridge module. All plan-specified test cases are present in `test_resolver.py`, `test_models.py`, `test_cwe_guidance.py`, `test_orchestrator.py`, `test_correlation.py`, `test_prompts_sast.py`, and `test_hunt_fuzz.py`. Adversarial cases (syntax errors, missing files, non-Python findings, zero-param functions, instance methods, module-level code) are all covered.

**`DCS_BRIDGE_MAX_TARGETS` env var is read with a safe default and error handling** in `resolve_findings_to_targets()` — malformed values fall back to `10` rather than crashing.

**Conditional MCP tool registration** is implemented correctly: `deep_scan_hunt_fuzz` requires both `ContainerBackend.is_available()` and the `anthropic` package to be importable. This is stricter than the existing `deep_scan_fuzz` (which only requires the container backend), which is appropriate since `hunt-fuzz` also initiates API calls.

---

## Verdict: REVISION_NEEDED

Two issues must be addressed before this can ship:

1. **C-1** — Add `validate_crash_data` to the module-level import in `server.py`. One line fix; prevents guaranteed `NameError` in every crash-producing hunt-fuzz run.
2. **M-1** — Fix the single-file-only `target_path` in `_run_hunt_fuzz`: use the original `path` argument (the codebase root) rather than `_fuzz_targets[0].file_path`. This ensures all bridge-identified targets are discoverable by the fuzzer plugin.

C-2 (key mismatch note) is lower priority because the functional impact is narrow (SAST enrichment silently no-ops for instance method targets, which the fuzzer cannot discover anyway with the default plugin), but the inconsistency should be documented or resolved.

After fixing C-1 and M-1, the implementation satisfies all plan requirements and is ready to proceed.
