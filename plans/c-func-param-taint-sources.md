# Plan: C Function Parameter Taint Sources

## Status: APPROVED

## Goals

1. Enable DCS to treat function parameters of externally-visible C functions as taint sources ("library mode"), so that scanning library codebases (libexpat, zlib, libpng, OpenSSL API surfaces) produces meaningful findings instead of near-zero results.
2. Add a new `DCS_C_PARAM_SOURCES` environment variable (default empty/off) that, when set to `on`, `true`, `yes`, or `1`, activates function-parameter taint seeding for C. This is opt-in because it changes the threat model (library boundary vs. application entry point) and would produce noise for application-level scans.
3. Add a corresponding `--c-param-sources` CLI flag and a `c_param_sources` MCP tool parameter so users can activate library mode per invocation without changing environment variables.
4. Implement parameter extraction in the tree-sitter backend by walking each C `function_definition` node's `parameter_list` and synthesizing `Source` objects for each parameter of non-`static` functions.
5. Add parameter-source support to the Semgrep backend by generating additional taint source patterns that match function parameters (using Semgrep's `pattern-sources` with `$PARAM` metavar patterns).
6. Maintain backward compatibility: when `DCS_C_PARAM_SOURCES` is not set or is off (default), all existing behavior is unchanged.
7. Document detection rate improvements: on representative library codebases, measure before/after finding counts.

## Non-Goals

- **Interprocedural taint.** This plan stays within the v1 intraprocedural boundary. A function parameter source only seeds taint within that function.
- **Output-parameter taint summaries.** The deferred `recv`/`fread`/`read` output-parameter sources (Known Limitation #7) are orthogonal and remain deferred.
- **Parameter sources for Python or Go.** Python/Go have rich web framework source registries (request.form, os.Args). Parameter-level source seeding could benefit them too, but the immediate pain point is C library code. Python/Go are deferred.
- **Automatic static/non-static detection in Semgrep.** Semgrep does not distinguish `static` linkage well. The Semgrep backend's parameter sources will match all function parameters, producing potentially more noise than the tree-sitter backend. This is documented, not fixed.
- **Struct member parameters.** `void f(struct ctx *c)` where `c->buf` is the actual tainted field -- tracking member-level taint from struct parameters is a distinct feature requiring field-sensitive analysis.
- **C++ support.** Different grammar, different plan.
- **Applying parameter sources to header-only declarations.** Only `function_definition` nodes (with bodies) generate parameter sources, not `function_declaration` (prototypes in headers).
- **TUI scan config integration.** The `--c-param-sources` CLI flag works when the TUI invokes CLI commands via subprocess, but the TUI scan configuration screen (`src/deep_code_security/tui/screens/`) will not expose a toggle for library mode. Users can set `DCS_C_PARAM_SOURCES=on` in their environment to activate the feature through the TUI. Adding a TUI checkbox is deferred because the TUI wraps CLI via subprocess and the environment variable path works without TUI code changes.

## Assumptions

1. The tree-sitter C grammar represents function parameters as a `parameter_list` child of the `function_declarator`, with each parameter as a `parameter_declaration` containing the type and either an `identifier` or `pointer_declarator` wrapping an `identifier`.
2. `static` functions in C tree-sitter have a `storage_class_specifier` child with text `"static"` in the `function_definition` node (verified empirically by the feasibility review -- it is a direct child of `function_definition`, not nested inside `declaration_specifiers`).
3. The existing `TaintEngine._analyze_function()` processes sources and sinks within each function scope. Injecting synthetic parameter sources into the sources list for each function is sufficient to seed taint from parameters, **with a small modification** to the seeding logic for `func_param` category sources (see Section 4c).
4. The existing `Source` model (Pydantic) is flexible enough to represent parameter sources: `function` field can hold the parameter name, `category` can be `"func_param"`. Note: this overloads the `Source.function` field semantics (for registry sources it holds the source API name like `"argv"`; for `func_param` sources it holds the parameter name like `"buf"`). This overloading is intentional -- the taint engine uses `source.function` as the seed variable name, and for parameter sources the parameter name IS the correct variable.
5. The Semgrep taint mode `pattern-sources` list supports matching function parameter patterns using metavariables.
6. Users scanning library code (the primary use case) are comfortable with opt-in activation and understand the higher noise tradeoff.

## Proposed Design

### 1. New Configuration: `DCS_C_PARAM_SOURCES`

A new environment variable controls whether C function parameters are treated as taint sources.

**Values:**
- Empty or not set (default): Existing behavior. Only registry-defined sources (argv, getenv, gets, fgets) are active.
- `on`, `true`, `yes`, or `1`: All parameters of non-static C function definitions are treated as taint sources.

Any value not in the truthy set (`on`, `true`, `yes`, `1`, case-insensitive) is treated as off.

**Location:** `src/deep_code_security/shared/config.py`

```python
# C function parameter taint sources (library mode)
self.c_param_sources: bool = os.environ.get(
    "DCS_C_PARAM_SOURCES", ""
).lower() in ("1", "true", "yes", "on")
```

### 2. CLI Flag: `--c-param-sources`

Added to the `dcs hunt`, `dcs full-scan`, and `dcs hunt-fuzz` commands. When passed, overrides the environment variable to `True` for that invocation.

```python
@click.option(
    "--c-param-sources", is_flag=True, default=False,
    help="Treat C function parameters as taint sources (library mode). "
         "Enables detection in library code where untrusted data arrives via parameters.",
)
```

The CLI passes this to `HunterOrchestrator.scan()` as a new optional `c_param_sources` kwarg.

### 3. MCP Tool Parameter: `c_param_sources`

Added to the `deep_scan_hunt`, `deep_scan_full`, and `deep_scan_hunt_fuzz` tool schemas.

```json
{
    "c_param_sources": {
        "type": "boolean",
        "default": false,
        "description": "Treat C function parameters as taint sources (library mode)"
    }
}
```

### 4. Tree-Sitter Backend: Parameter Source Extraction

The core implementation. In `TreeSitterBackend.scan_files()`, when `c_param_sources` is enabled and the file language is C, the backend extracts function parameters as additional sources.

#### 4a. New Module: `src/deep_code_security/hunter/param_source_extractor.py`

This module provides a standalone function that walks a tree-sitter C AST and produces `Source` objects for each parameter of non-static function definitions.

```python
"""Extract function parameter taint sources from C ASTs (library mode).

When scanning C library code, function parameters of externally-visible
(non-static) functions are treated as taint sources because any caller
could pass attacker-controlled data.

This module is only invoked when DCS_C_PARAM_SOURCES=on.
"""

from __future__ import annotations

import logging
from typing import Any

from deep_code_security.hunter.models import Source

__all__ = ["extract_param_sources"]

logger = logging.getLogger(__name__)

# Minimum parameter name length to avoid substring-match false positives.
# The taint engine's fallback path in _check_sink_reachability() uses
# `if tainted_var in node_text` substring matching. Single-character
# parameter names (n, s, c, p, i, x) match inside unrelated identifiers
# (e.g., "n" matches in "printf", "internal", "count"). Two-character
# names (fd, op) have a lower but still significant false-match rate.
#
# Parameters with names shorter than this threshold are excluded from
# taint seeding entirely. This trades a small amount of recall for a
# large reduction in false positives.
_MIN_PARAM_NAME_LENGTH = 2


def extract_param_sources(
    tree: Any,
    file_path: str,
) -> list[Source]:
    """Extract taint sources from C function parameters.

    Walks the AST to find all function_definition nodes. For each
    non-static function, extracts all named parameters and creates
    Source objects for them.

    Parameters with names shorter than _MIN_PARAM_NAME_LENGTH are
    excluded to avoid substring-match false positives in the taint
    engine's fallback reachability check.

    Args:
        tree: tree_sitter.Tree for the file.
        file_path: Absolute path to the source file.

    Returns:
        List of Source objects, one per named parameter of non-static functions.
    """
    sources: list[Source] = []
    _visit_for_functions(tree.root_node, file_path, sources)
    return sources


def _visit_for_functions(
    node: Any,
    file_path: str,
    sources: list[Source],
) -> None:
    """Recursively find function_definition nodes and extract parameters."""
    if node.type == "function_definition":
        if not _is_static(node):
            _extract_params_from_function(node, file_path, sources)
        return  # Do not recurse into nested function definitions

    for child in node.children:
        _visit_for_functions(child, file_path, sources)


def _is_static(func_def_node: Any) -> bool:
    """Check if a function_definition has 'static' storage class.

    In tree-sitter-c, a static function has a storage_class_specifier
    child with text "static" as a direct child of the function_definition
    node (verified empirically -- it is NOT nested inside
    declaration_specifiers as originally speculated).

    Args:
        func_def_node: A function_definition AST node.

    Returns:
        True if the function is declared static.
    """
    for child in func_def_node.children:
        if child.type == "storage_class_specifier":
            if child.text.decode("utf-8", errors="replace") == "static":
                return True
        # Also check inside declaration_specifiers for grammar robustness
        if child.type == "declaration_specifiers":
            for spec in child.children:
                if spec.type == "storage_class_specifier":
                    if spec.text.decode("utf-8", errors="replace") == "static":
                        return True
    return False


def _extract_params_from_function(
    func_def_node: Any,
    file_path: str,
    sources: list[Source],
) -> None:
    """Extract parameter names from a function_definition and create Sources.

    The function_definition structure in tree-sitter-c:
        function_definition
            type_specifier
            function_declarator
                identifier (function name)
                parameter_list
                    parameter_declaration
                        type_specifier
                        identifier | pointer_declarator(identifier)
                    parameter_declaration
                        ...
            compound_statement (body)

    Special cases handled:
    - Pointer parameters: char *buf -> pointer_declarator wraps identifier
    - Array parameters: char buf[] -> array_declarator wraps identifier
    - No-name parameters: void foo(int) -> no identifier, skip
    - Variadic: ... -> skip
    - Function pointer parameters: void (*callback)(int) -> no identifier
      at expected level, returns None from _extract_param_name(), skip
      (correct behavior -- function pointer params are not taintable data)

    Parameters with names shorter than _MIN_PARAM_NAME_LENGTH characters
    are excluded to prevent substring-match false positives.

    Args:
        func_def_node: A function_definition AST node.
        file_path: Source file path.
        sources: List to append Source objects to.
    """
    # Find the function_declarator child
    func_declarator = None
    for child in func_def_node.children:
        if child.type == "function_declarator":
            func_declarator = child
            break
        # Handle pointer-returning functions: int *foo(params)
        # The function_declarator may be nested inside a pointer_declarator
        if child.type == "pointer_declarator":
            for inner in child.children:
                if inner.type == "function_declarator":
                    func_declarator = inner
                    break
            if func_declarator:
                break

    if func_declarator is None:
        return

    # Find the parameter_list child
    param_list = None
    for child in func_declarator.children:
        if child.type == "parameter_list":
            param_list = child
            break

    if param_list is None:
        return

    for param in param_list.children:
        if param.type != "parameter_declaration":
            continue

        param_name = _extract_param_name(param)
        if param_name is None:
            continue

        # Skip parameters with very short names to avoid substring-match
        # false positives in the taint engine's fallback reachability check.
        # See _MIN_PARAM_NAME_LENGTH documentation for rationale.
        if len(param_name) < _MIN_PARAM_NAME_LENGTH:
            logger.debug(
                "Skipping short parameter name '%s' at %s:%d "
                "(length %d < minimum %d)",
                param_name, file_path, param.start_point[0] + 1,
                len(param_name), _MIN_PARAM_NAME_LENGTH,
            )
            continue

        # Skip common non-taintable parameter names
        # (argc: always an integer count, not user-controlled data)
        if param_name in ("argc",):
            continue

        source = Source(
            file=file_path,
            line=param.start_point[0] + 1,
            column=param.start_point[1],
            function=param_name,
            category="func_param",
            language="c",
        )
        sources.append(source)
        logger.debug(
            "Parameter source: %s at %s:%d",
            param_name, file_path, source.line,
        )


def _extract_param_name(param_decl: Any) -> str | None:
    """Extract the parameter name from a parameter_declaration node.

    Handles:
    - Direct identifier: int x -> "x"
    - Pointer declarator: char *buf -> "buf"
    - Array declarator: char buf[] -> "buf"
    - Double pointer: char **argv -> "argv"
    - Function pointer: void (*callback)(int) -> None (skipped)

    Args:
        param_decl: A parameter_declaration AST node.

    Returns:
        Parameter name string, or None if unnamed or function pointer.
    """
    for child in param_decl.children:
        if child.type == "identifier":
            return child.text.decode("utf-8", errors="replace")
        if child.type == "pointer_declarator":
            return _unwrap_declarator(child)
        if child.type == "array_declarator":
            return _unwrap_declarator(child)
    return None


def _unwrap_declarator(node: Any) -> str | None:
    """Unwrap pointer_declarator or array_declarator to find the identifier.

    Recursion depth is bounded by the AST structure. In practice, even
    pathological cases like char ********x produce at most ~8 levels of
    nesting, well within Python's recursion limit.

    Args:
        node: A pointer_declarator or array_declarator AST node.

    Returns:
        Identifier name, or None.
    """
    for child in node.children:
        if child.type == "identifier":
            return child.text.decode("utf-8", errors="replace")
        if child.type in ("pointer_declarator", "array_declarator"):
            return _unwrap_declarator(child)
    return None
```

#### 4b. Integration into `TreeSitterBackend.scan_files()`

The `scan_files()` method receives `c_param_sources` as a new parameter (added to the `ScannerBackend` protocol). When enabled and the file language is `Language.C`, it calls `extract_param_sources()` and merges the results with the registry-derived sources before running taint tracking.

The key integration point is in the per-file loop after `find_sources()`:

```python
# After registry-based source finding
sources = find_sources(tree, registry, lang_obj, file_path_str)

# Inject parameter sources if library mode is enabled
if c_param_sources and lang == Language.C:
    from deep_code_security.hunter.param_source_extractor import extract_param_sources
    param_sources = extract_param_sources(tree, file_path_str)
    sources.extend(param_sources)
    total_param_sources += len(param_sources)
```

#### 4c. Taint Seeding for Parameter Sources

The existing `TaintEngine._analyze_function()` method seeds taint from sources by calling `_find_assigned_var_near_line()` to find the LHS variable that receives the source value. **For `func_param` sources, this LHS lookup must be bypassed.** The parameter name IS the variable -- no assignment lookup is needed.

**Why bypassing is required:** `_find_assigned_var_near_line()` searches within a +/- 2 line window of the source line. For parameter sources, the source line is the function signature line. In common C code, the first local variable declaration in the function body is within 1-2 lines of the signature:

```c
int parse_data(const char *buf, int len) {  // L1: parameter source line
    int x = len + 1;                         // L2: within +2 window
    memcpy(internal_buf, buf, len);
}
```

Without the bypass, `_find_assigned_var_near_line()` would find `x = len + 1` and seed `"x"` as tainted in addition to the parameter name. This creates confusing taint paths and potential false positives if `x` flows to a sink through a path that `buf`/`len` do not.

For multi-line parameter lists, the problem is worse: the last parameter's line number may be very close to the first statement in the function body, causing cross-matching with unrelated assignments.

**Required change to `taint_tracker.py`:** In `_analyze_function()`, add a category check before calling `_find_assigned_var_near_line()`:

```python
# In _analyze_function(), replace the unconditional _find_assigned_var_near_line call:
if source.category == "func_param":
    # Parameter name IS the variable; skip LHS assignment lookup.
    # The +/-2 line window would match unrelated local variable
    # declarations near the function signature.
    source_var = None
else:
    source_var = self._find_assigned_var_near_line(
        func_node, source.line, file_path
    )
```

This is a 3-line change. The rest of the seeding logic (`state.add_taint(source.function, initial_step)`) correctly seeds the parameter name as a tainted variable via the existing fallback path.

### 5. Semgrep Backend: Parameter Source Patterns

The Semgrep backend integration is more limited because Semgrep's taint mode `pattern-sources` cannot easily express "all parameters of non-static functions" generically.

**Approach:** Create a new Semgrep rule file `registries/semgrep/c-param-sources/param-sources.yaml` in a **separate directory** from the main C rules. This directory is conditionally included via a second `--config` argument when `c_param_sources` is enabled. Multiple `--config` flags are supported by the Semgrep CLI.

The separate directory approach is necessary because the current Semgrep backend uses a single `--config <rules_dir>` that recursively includes ALL `.yaml` files. Semgrep CLI does not support per-file exclusion within a config directory. Placing the parameter source rules in a separate directory (`registries/semgrep/c-param-sources/`) allows conditional inclusion via an additional `--config` flag without affecting the default rule set.

The new rule file uses Semgrep's `pattern-sources` with parameter patterns:

```yaml
rules:
  - id: dcs.c.param-source.buffer-to-sink
    message: >
      Function parameter flows to a dangerous operation. In library code,
      any function parameter of an externally-visible function could carry
      attacker-controlled data. Validate parameter values and buffer sizes
      before using them in memory operations or command execution.
    severity: WARNING
    languages: [c]
    mode: taint
    metadata:
      cwe:
        - "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer"
      source_category: func_param
      source_function: parameter
      sink_category: memory_corruption
      sink_function: memcpy
      dcs_severity: medium
    pattern-sources:
      # Match pointer parameters (char *buf, void *data, const char *input, etc.)
      - patterns:
          - pattern: |
              $RET_TYPE $FUNC_NAME(..., $TYPE *$PARAM, ...) { ... }
          - focus-metavariable: $PARAM
      # Match size/length integer parameters (int len, size_t n, unsigned count, etc.)
      - patterns:
          - pattern: |
              $RET_TYPE $FUNC_NAME(..., $TYPE $PARAM, ...) { ... }
          - focus-metavariable: $PARAM
          - metavariable-regex:
              metavariable: $TYPE
              regex: ^(int|size_t|ssize_t|unsigned|long|uint32_t|uint64_t|off_t)$
    pattern-sinks:
      - pattern: memcpy(...)
      - pattern: memmove(...)
      - pattern: strcpy(...)
      - pattern: strcat(...)
      - pattern: sprintf(...)
      - pattern: system(...)
      - pattern: popen(...)
      - pattern: malloc(...)
      - pattern: calloc(...)
      - pattern: realloc(...)
      - pattern: printf(...)
      - pattern: fprintf(...)
      - pattern: fopen(...)
```

**Important limitation:** The Semgrep backend's parameter sources are static rule patterns, not a dynamic extraction like the tree-sitter backend. They will produce findings when Semgrep is available, but the tree-sitter backend provides more complete coverage because it dynamically extracts ALL parameters. **For best results with `--c-param-sources`, use `DCS_SCANNER_BACKEND=treesitter`.**

Additionally, the Semgrep rules cannot distinguish `static` functions from non-static ones (see Non-Goals). This means the Semgrep backend will match parameters of static helper functions too, producing additional noise compared to the tree-sitter backend.

**Conditional inclusion:** The `SemgrepBackend.scan_files()` method is modified to conditionally add a second `--config registries/semgrep/c-param-sources/` argument when `c_param_sources` is enabled.

### 6. ScannerBackend Protocol Extension

The `ScannerBackend` protocol's `scan_files()` method gains a new optional parameter:

```python
def scan_files(
    self,
    target_path: Path,
    discovered_files: list[DiscoveredFile],
    severity_threshold: str,
    c_param_sources: bool = False,
) -> BackendResult:
```

Both backends accept this parameter. The `HunterOrchestrator.scan()` method passes it through from its own `c_param_sources` kwarg.

### 7. Source Category: `func_param`

Parameter sources use the category `"func_param"` (not `"cli_input"` or `"env_input"`). This is a new source category that does not appear in `registries/c.yaml` because it is dynamically generated, not statically registered.

The source category allows downstream consumers (auditor, architect, formatters) to distinguish parameter-derived findings from registry-derived findings. This is important because:
- Parameter-derived findings have inherently higher false-positive rates (not all parameters carry untrusted data in practice).
- Future plans could use the category to adjust confidence scoring (e.g., lower raw_confidence for `func_param` sources).

For v1 of this plan, the raw_confidence scoring is unchanged -- parameter sources produce findings with the same confidence as registry sources. This is a deliberate simplicity choice. If noise proves to be a problem, a follow-up plan can add category-based confidence adjustment.

### 8. Confidence Scoring Note

No changes to confidence scoring in this plan. Findings from parameter sources go through the same `_compute_raw_confidence()` logic as registry-source findings. The rationale:

- **For:** Lower confidence for `func_param` sources would reduce noise. Most library functions have some parameters that are NOT attacker-controlled (e.g., opaque handles, configuration flags).
- **Against:** Without context, we cannot know which parameters are attacker-controlled. Lowering confidence uniformly punishes legitimate findings. The opt-in nature of the feature is the noise control mechanism.
- **Decision:** Defer category-based confidence adjustment. The opt-in flag is sufficient for v1.

## Interfaces/Schema Changes

### Config Changes

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `c_param_sources` | `bool` | `False` | Treat C function parameters as taint sources |

### CLI Changes

| Command | New Flag | Description |
|---------|----------|-------------|
| `dcs hunt` | `--c-param-sources` | Activate library mode for C |
| `dcs full-scan` | `--c-param-sources` | Activate library mode for C |
| `dcs hunt-fuzz` | `--c-param-sources` | Activate library mode for C |

### MCP Schema Changes

All three hunt-related tools (`deep_scan_hunt`, `deep_scan_full`, `deep_scan_hunt_fuzz`) gain:

```json
{
    "c_param_sources": {
        "type": "boolean",
        "default": false,
        "description": "Treat C function parameters as taint sources (library mode). "
                       "Enables detection in library code where untrusted data arrives "
                       "through function parameters rather than argv/getenv."
    }
}
```

### ScannerBackend Protocol

`scan_files()` gains `c_param_sources: bool = False` parameter.

### HunterOrchestrator.scan()

Gains `c_param_sources: bool = False` parameter, which is passed through to the backend.

### Environment Variable

| Variable | Default | Accepted Truthy Values | Description |
|----------|---------|------------------------|-------------|
| `DCS_C_PARAM_SOURCES` | (empty/off) | `on`, `true`, `yes`, `1` (case-insensitive) | Treat C function parameters as taint sources |

### Pydantic Model Changes

No changes to `Source`, `Sink`, `TaintStep`, `TaintPath`, `RawFinding`, or `ScanStats`. The `Source.category` field already accepts arbitrary strings; `"func_param"` is a new value used within the existing schema.

## Data Migration

None. This plan adds new behavior behind an opt-in flag. No existing data formats change.

## Rollout Plan

1. **Phase 1: Config + plumbing** -- Add `DCS_C_PARAM_SOURCES` to `Config`, `c_param_sources` parameter to `HunterOrchestrator.scan()`, `ScannerBackend.scan_files()`, and both backend implementations (pass-through only, no logic yet).
2. **Phase 2: Tree-sitter parameter extraction + TaintEngine seeding fix** -- Implement `param_source_extractor.py`, integrate into `TreeSitterBackend.scan_files()`, and add the `func_param` category guard in `TaintEngine._analyze_function()` to bypass `_find_assigned_var_near_line()`.
3. **Phase 3: Semgrep parameter source rules** -- Create `registries/semgrep/c-param-sources/param-sources.yaml` and add conditional `--config` inclusion logic in `SemgrepBackend`.
4. **Phase 4: CLI + MCP integration** -- Add `--c-param-sources` flag to CLI commands and `c_param_sources` to MCP tool schemas.
5. **Phase 5: Test fixtures + test suite** -- Create library-style test fixtures and comprehensive tests.
6. **Phase 6: Documentation** -- Update `CLAUDE.md` with new env var, CLI flag, and Known Limitations update.

All phases merge as a single commit.

## Risks

### 1. Noise from Non-Attacker-Controlled Parameters (High)

**Risk:** Many function parameters carry trusted data (configuration flags, opaque handles, internal buffers). Treating ALL parameters as sources will produce false positives.

**Mitigation:** (a) The feature is opt-in (`DCS_C_PARAM_SOURCES=on`). Application-level scans do not see any new findings by default. (b) Static functions are excluded (internal linkage = not externally callable). (c) `argc` is excluded (always an integer count, not user-controlled data). (d) Parameters with names shorter than 2 characters are excluded to prevent substring-match false positives (see Section 4a, `_MIN_PARAM_NAME_LENGTH`). (e) Future plan can add parameter-name heuristics (e.g., skip `ctx`, `handle`, `flags`, `mode` parameters) or confidence adjustment.

### 2. Short Parameter Names and Substring-Match False Positives (Medium)

**Risk:** The taint engine's fallback path in `_check_sink_reachability()` uses `if tainted_var in node_text` substring matching. C parameters like `n`, `s`, `c`, `p` would match inside unrelated identifiers (e.g., `"n"` matches in `"printf"`, `"internal"`, `"count"`). This would produce massive false positive rates on library code with short parameter names.

**Mitigation:** A minimum parameter name length filter (`_MIN_PARAM_NAME_LENGTH = 2`) is applied in `extract_param_sources()`. Parameters with single-character names are excluded from taint seeding entirely. This is a recall-precision tradeoff: some legitimate single-character parameter vulnerabilities will be missed, but the false positive reduction is substantial. The threshold of 2 was chosen because single-character names have an extremely high substring collision rate, while two-character names (e.g., `fd`, `op`) have a significantly lower but still nonzero collision rate. If two-character false positives prove problematic in practice, the threshold can be raised to 3 in a follow-up.

### 3. Interaction with Existing Registry Sources (Low)

**Risk:** A function like `int main(int argc, char *argv[])` already has `argv` as a registry source. With parameter sources enabled, `argv` would also be a `func_param` source, producing duplicate findings.

**Mitigation:** The existing deduplication in `HunterOrchestrator._deduplicate_findings()` keys on `(file, sink_line, cwe)` and keeps the highest-confidence finding. Since both sources produce the same confidence, one is arbitrarily kept. This is correct behavior -- the vulnerability exists regardless of how the source is classified.

### 4. Performance Impact on Large Codebases (Low)

**Risk:** Extracting parameters from every function definition adds overhead. A codebase with 10,000 functions could produce 30,000+ parameter sources.

**Mitigation:** The extraction is a simple AST walk (O(n) in AST nodes), faster than tree-sitter query execution. The taint engine already processes sources per-function, so parameter sources within a function are processed alongside registry sources with no algorithmic complexity increase. The `DCS_MAX_RESULTS` limit caps output.

### 5. Semgrep Rule Pattern Limitations (Medium)

**Risk:** Semgrep's `pattern-sources` with `focus-metavariable` on parameter positions may not work correctly for all function signatures (variadic functions, K&R-style declarations, function pointers as parameters). Additionally, Semgrep cannot distinguish `static` functions, so it will match all function parameters including internal helpers.

**Mitigation:** The Semgrep parameter source rule is explicitly labeled as "best effort". The tree-sitter backend provides the authoritative implementation. Users who need maximum coverage for library scanning should use `DCS_SCANNER_BACKEND=treesitter` with `--c-param-sources`. This recommendation is documented in CLAUDE.md.

### 6. Tree-Sitter Node Type Assumptions (Medium)

**Risk:** The parameter extraction code assumes specific node types (`parameter_list`, `parameter_declaration`, `storage_class_specifier`). These must be verified against the actual tree-sitter-c grammar.

**Mitigation:** A verification test (similar to `test_c_node_type_verification` in the existing test suite) is required. The test parses representative C code with various function signatures and verifies that the expected node types are present. Additionally, `_extract_param_name()` gracefully returns `None` for unrecognized node structures. The feasibility review has already verified these node types empirically.

### 7. ScannerBackend Protocol Change (Low)

**Risk:** Adding a parameter to the `scan_files()` Protocol method technically breaks existing implementations that do not accept it.

**Mitigation:** The parameter has a default value (`False`), so existing call sites that do not pass it continue to work. Both backends are updated in this plan. No external backends exist.

## Test Plan

### Test Command

```bash
make test-hunter
```

For focused runs:

```bash
pytest tests/test_hunter/test_param_source_extractor.py tests/test_hunter/test_param_sources_integration.py -v
```

For the full suite:

```bash
make test
```

### Test Module: `tests/test_hunter/test_param_source_extractor.py`

Unit tests for the parameter extraction module.

1. **`TestExtractParamSources`:**
   - `test_simple_function_params` -- `void foo(char *buf, int len)` produces 2 sources: `buf` and `len`.
   - `test_static_function_excluded` -- `static void helper(char *buf)` produces 0 sources.
   - `test_no_params_function` -- `void init(void)` produces 0 sources.
   - `test_argc_excluded` -- `int main(int argc, char *argv[])` produces 1 source (`argv`), `argc` is excluded.
   - `test_double_pointer_param` -- `void parse(char **items, int count)` produces 2 sources.
   - `test_array_param` -- `void process(char buf[], int count)` produces 2 sources.
   - `test_multiple_functions` -- file with 3 non-static functions produces sources from all 3.
   - `test_mixed_static_nonstatic` -- file with 2 static + 2 non-static produces sources only from non-static.
   - `test_pointer_return_function` -- `char *get_data(char *input, int len)` (pointer-returning function) produces sources for `input` and `len`.
   - `test_unnamed_params_skipped` -- `void foo(int, char *)` (unnamed params) produces 0 sources.
   - `test_const_params` -- `void foo(const char *buf, const int len)` produces 2 sources.
   - `test_struct_pointer_param` -- `void process(struct ctx *ctx_ptr)` produces 1 source `ctx_ptr`.
   - `test_short_param_names_excluded` -- `void foo(int n, char *s, int c)` produces 0 sources (all names are single-character, below `_MIN_PARAM_NAME_LENGTH`).
   - `test_two_char_param_names_included` -- `void foo(int fd, char *op)` produces 2 sources (`fd` and `op` are 2 characters, meeting the minimum).
   - `test_multi_line_params` -- multi-line parameter list (`void f(\n  char *buf,\n  int len\n)`) produces correct sources with correct line numbers.
   - `test_function_pointer_param_skipped` -- `void register_cb(void (*callback)(int), int count)` produces 1 source (`count`), function pointer param is skipped.

2. **`TestIsStatic`:**
   - `test_static_detected` -- `static void helper(int xx)` returns True.
   - `test_nonstatic_not_detected` -- `void api_func(int xx)` returns False.
   - `test_extern_not_static` -- `extern void exported(int xx)` returns False.
   - `test_inline_static` -- `static inline void fast(int xx)` returns True.

3. **`TestNodeTypeVerification`:**
   - `test_parameter_list_node_type` -- parse C function, verify `parameter_list` node exists.
   - `test_parameter_declaration_node_type` -- parse C function, verify `parameter_declaration` nodes exist.
   - `test_storage_class_specifier_for_static` -- parse `static void f(int xx) {}`, verify `storage_class_specifier` node exists with text `"static"`.

### Test Module: `tests/test_hunter/test_param_sources_integration.py`

Integration tests verifying parameter sources flow through the full pipeline.

1. **`TestTreeSitterBackendParamSources`:**
   - `test_param_sources_disabled_by_default` -- scan a C library file with `c_param_sources=False`, verify parameter sources are not generated.
   - `test_param_sources_enabled_produces_findings` -- scan `lib_parser.c` fixture with `c_param_sources=True`, verify findings are produced for parameter-to-sink paths.
   - `test_param_sources_only_for_c_files` -- scan a Python file with `c_param_sources=True`, verify no parameter sources are generated (only applies to C).
   - `test_param_sources_combined_with_registry` -- scan `buffer_overflow.c` (which has `argv` registry source) with `c_param_sources=True`, verify findings include both registry and parameter sources, deduplicated correctly.
   - `test_static_functions_excluded_integration` -- scan a file with mix of static/non-static, verify only non-static functions produce parameter sources.
   - `test_func_param_bypasses_assigned_var_lookup` -- scan a C function where the first statement is `int x = len + 1;` with `c_param_sources=True`, verify that the taint path shows `len` as the source variable (not `x`), confirming that `_find_assigned_var_near_line` is bypassed for `func_param` sources.

2. **`TestEndToEnd`:**
   - `test_library_parser_findings` -- parse `lib_parser.c` fixture (library function with buffer parameter flowing to memcpy), verify CWE-119 finding.
   - `test_library_format_string` -- parse `lib_logger.c` fixture (library function with format parameter flowing to printf), verify CWE-134 finding.
   - `test_safe_library_no_findings` -- parse `lib_safe.c` fixture (library function using snprintf with parameter), verify zero unsanitized findings.

3. **`TestCLIIntegration`:**
   - `test_hunt_with_c_param_sources_flag` -- invoke `dcs hunt` with `--c-param-sources` on the test fixture, verify findings in output.
   - `test_hunt_without_flag_no_param_findings` -- invoke `dcs hunt` without flag on same fixture, verify no parameter-derived findings.

4. **`TestConfigIntegration`:**
   - `test_env_var_activates_param_sources` -- set `DCS_C_PARAM_SOURCES=on`, create Config, verify `config.c_param_sources is True`.
   - `test_env_var_true_activates` -- set `DCS_C_PARAM_SOURCES=true`, verify `config.c_param_sources is True`.
   - `test_env_var_yes_activates` -- set `DCS_C_PARAM_SOURCES=yes`, verify `config.c_param_sources is True`.
   - `test_env_var_1_activates` -- set `DCS_C_PARAM_SOURCES=1`, verify `config.c_param_sources is True`.
   - `test_env_var_default_off` -- no env var set, verify `config.c_param_sources is False`.
   - `test_cli_flag_overrides_env` -- even with `DCS_C_PARAM_SOURCES=off`, `--c-param-sources` flag activates the feature.

### Test Fixtures

**`tests/fixtures/vulnerable_samples/c/lib_parser.c`** -- A library-style function that receives a buffer and length via parameters, then uses them in `memcpy` without bounds checking. No `main()`, no `argv`. Simulates the `XML_Parse(parser, buf, len, done)` pattern.

```c
/* Library parser function -- intentionally vulnerable for testing.
 * Simulates a library API where buf/len are attacker-controlled.
 */
#include <string.h>

/* Non-static: externally visible. Parameter 'buf' is untrusted. */
int parse_data(const char *buf, int len, int flags) {
    char internal_buf[256];
    /* VULNERABLE: unbounded memcpy from parameter */
    memcpy(internal_buf, buf, len);
    return 0;
}

/* Non-static: parameter 'input' flows to strcpy */
void process_input(char *input) {
    char dest[64];
    /* VULNERABLE: unbounded strcpy from parameter */
    strcpy(dest, input);
}

/* Static function: should NOT be flagged in library mode */
static void internal_helper(char *data) {
    char buf[32];
    memcpy(buf, data, 16);
}
```

**`tests/fixtures/vulnerable_samples/c/lib_logger.c`** -- A library logging function where a format string parameter flows to `printf`.

```c
/* Library logger function -- intentionally vulnerable for testing. */
#include <stdio.h>

/* Non-static: format parameter flows to printf (CWE-134) */
void log_message(const char *format, int level) {
    if (level > 0) {
        /* VULNERABLE: format string from parameter */
        printf(format);
    }
}
```

**`tests/fixtures/safe_samples/c/lib_safe.c`** -- A library function that safely handles parameters using bounded operations.

```c
/* Safe library function -- uses bounded operations. */
#include <string.h>
#include <stdio.h>

/* Non-static but safe: uses snprintf with bounded size */
int format_safely(const char *input, char *output, int output_size) {
    snprintf(output, output_size, "%s", input);
    return 0;
}
```

### Existing Tests

All existing tests must continue to pass. The changes are:
- `scan_files()` protocol gains a defaulted parameter -- existing callers are unaffected.
- `HunterOrchestrator.scan()` gains a defaulted parameter -- existing callers are unaffected.
- `TaintEngine._analyze_function()` gains a 3-line conditional -- existing behavior for non-`func_param` sources is unchanged.
- No registry changes -- existing registry queries and their tests are unchanged.

## Acceptance Criteria

1. `DCS_C_PARAM_SOURCES=on dcs hunt tests/fixtures/vulnerable_samples/c/lib_parser.c` produces findings (CWE-119 for memcpy, CWE-120 for strcpy).
2. `dcs hunt tests/fixtures/vulnerable_samples/c/lib_parser.c` (without the flag) produces zero findings (no registry sources in the file).
3. `dcs hunt --c-param-sources tests/fixtures/vulnerable_samples/c/lib_parser.c` produces findings equivalent to #1.
4. Static functions in test fixtures do not produce parameter-source findings.
5. `argc` parameters are excluded from parameter sources.
6. Single-character parameter names (e.g., `n`, `s`, `c`) are excluded from parameter sources.
7. `dcs hunt --c-param-sources tests/fixtures/vulnerable_samples/c/buffer_overflow.c` produces findings from both registry sources (argv) and parameter sources, deduplicated correctly.
8. The `deep_scan_hunt` MCP tool accepts `c_param_sources: true` and produces parameter-derived findings.
9. `make test-hunter` passes with all new and existing tests green.
10. `make test` passes with 90%+ coverage maintained.
11. All existing Python, Go, and C hunter tests pass unchanged.
12. `CLAUDE.md` documents `DCS_C_PARAM_SOURCES`, the `--c-param-sources` flag, and updated Known Limitations.
13. `func_param` sources bypass `_find_assigned_var_near_line()` in taint seeding, verified by integration test.

## Task Breakdown

### Files to Create

| # | File | Description |
|---|------|-------------|
| 1 | `src/deep_code_security/hunter/param_source_extractor.py` | Parameter extraction from C function definitions (core logic) |
| 2 | `tests/test_hunter/test_param_source_extractor.py` | Unit tests for parameter extraction |
| 3 | `tests/test_hunter/test_param_sources_integration.py` | Integration tests for parameter sources through full pipeline |
| 4 | `tests/fixtures/vulnerable_samples/c/lib_parser.c` | Library-style vulnerable fixture (memcpy + strcpy from params) |
| 5 | `tests/fixtures/vulnerable_samples/c/lib_logger.c` | Library-style format string fixture (printf from param) |
| 6 | `tests/fixtures/safe_samples/c/lib_safe.c` | Safe library fixture (snprintf from param) |
| 7 | `registries/semgrep/c-param-sources/param-sources.yaml` | Semgrep parameter source rules (best-effort, separate directory for conditional inclusion) |

### Files to Modify

| # | File | Changes |
|---|------|---------|
| 8 | `src/deep_code_security/shared/config.py` | Add `c_param_sources` bool field from `DCS_C_PARAM_SOURCES` env var |
| 9 | `src/deep_code_security/hunter/scanner_backend.py` | Add `c_param_sources: bool = False` parameter to `ScannerBackend.scan_files()` protocol |
| 10 | `src/deep_code_security/hunter/treesitter_backend.py` | Accept `c_param_sources` param, call `extract_param_sources()` when enabled + C language, merge into sources list |
| 11 | `src/deep_code_security/hunter/semgrep_backend.py` | Accept `c_param_sources` param, conditionally add `--config registries/semgrep/c-param-sources/` argument when enabled |
| 12 | `src/deep_code_security/hunter/orchestrator.py` | Add `c_param_sources: bool = False` to `scan()`, pass to `_backend.scan_files()`, default from `config.c_param_sources` if not explicitly provided |
| 13 | `src/deep_code_security/hunter/taint_tracker.py` | In `_analyze_function()`, add `source.category == "func_param"` guard to skip `_find_assigned_var_near_line()` for parameter sources (3-line change) |
| 14 | `src/deep_code_security/hunter/__init__.py` | Add `param_source_extractor` to imports and `__all__` |
| 15 | `src/deep_code_security/cli.py` | Add `--c-param-sources` flag to `hunt`, `full_scan`, and `hunt_fuzz` commands; pass to orchestrator |
| 16 | `src/deep_code_security/mcp/server.py` | Add `c_param_sources` to `deep_scan_hunt`, `deep_scan_full`, `deep_scan_hunt_fuzz` tool schemas and handlers |
| 17 | `CLAUDE.md` | Add `DCS_C_PARAM_SOURCES` env var, `--c-param-sources` flag, update Known Limitations |

## Work Groups

### Shared Dependencies

Files that must be implemented first because other work groups depend on them:

| # | File | Rationale |
|---|------|-----------|
| 8 | `src/deep_code_security/shared/config.py` | Config field used by orchestrator, backends, CLI |
| 9 | `src/deep_code_security/hunter/scanner_backend.py` | Protocol change used by both backends and orchestrator |

### WG1: Core Logic (param extractor + tree-sitter backend + taint engine fix)

Independent of WG2, WG3, WG4 after shared dependencies are in place.

| # | File |
|---|------|
| 1 | `src/deep_code_security/hunter/param_source_extractor.py` |
| 10 | `src/deep_code_security/hunter/treesitter_backend.py` |
| 12 | `src/deep_code_security/hunter/orchestrator.py` |
| 13 | `src/deep_code_security/hunter/taint_tracker.py` |
| 14 | `src/deep_code_security/hunter/__init__.py` |

### WG2: Semgrep Backend

Independent of WG1, WG3, WG4 after shared dependencies are in place.

| # | File |
|---|------|
| 7 | `registries/semgrep/c-param-sources/param-sources.yaml` |
| 11 | `src/deep_code_security/hunter/semgrep_backend.py` |

### WG3: CLI + MCP Integration

Depends on WG1 (orchestrator changes).

| # | File |
|---|------|
| 15 | `src/deep_code_security/cli.py` |
| 16 | `src/deep_code_security/mcp/server.py` |

### WG4: Tests + Fixtures + Documentation

Depends on WG1 and WG2 (tests exercise both backends).

| # | File |
|---|------|
| 2 | `tests/test_hunter/test_param_source_extractor.py` |
| 3 | `tests/test_hunter/test_param_sources_integration.py` |
| 4 | `tests/fixtures/vulnerable_samples/c/lib_parser.c` |
| 5 | `tests/fixtures/vulnerable_samples/c/lib_logger.c` |
| 6 | `tests/fixtures/safe_samples/c/lib_safe.c` |
| 17 | `CLAUDE.md` |

## Context Alignment

### CLAUDE.md Patterns Followed

| Pattern | How This Plan Follows It |
|---------|--------------------------|
| `yaml.safe_load()` only | No new YAML loading; registry loading already uses `yaml.safe_load()` |
| Never `eval()`, `exec()`, `shell=True` | No new subprocess or eval usage |
| Pydantic v2 for data models | No model changes; uses existing `Source` model with new `category` value |
| Type hints on public functions | All new functions have type hints |
| `__all__` in `__init__.py` | New module `param_source_extractor.py` has `__all__`; `hunter/__init__.py` updated to include it |
| `pathlib.Path` over `os.path` | All path handling uses `pathlib.Path` |
| No mutable default arguments | All defaults are immutable |
| Registries in YAML files | New Semgrep rule in `registries/semgrep/c-param-sources/param-sources.yaml` |
| `models.py` per phase | No new models; uses existing `Source` |
| 90%+ test coverage | Comprehensive test suite for all new code |
| Intraprocedural taint only | Parameter sources are per-function, consistent with v1 |
| Opt-in via environment variable | `DCS_C_PARAM_SOURCES` follows established pattern (`DCS_SCANNER_BACKEND`, `DCS_FUZZ_CONSENT`) |

### Prior Plans Referenced

| Plan | Relationship |
|------|-------------|
| `plans/c-language-support.md` (APPROVED) | This plan builds directly on c-language-support. It uses the same C registry, taint tracker, and test patterns. It explicitly addresses the limitation noted in that plan: "only `argv`, `getenv`, `gets`, `fgets` (return-value sources) are effective taint sources." |
| `plans/semgrep-scanner-backend.md` (APPROVED) | Follows the same `ScannerBackend` protocol pattern. The Semgrep backend integration uses the same rule-file-based approach. |
| `plans/c-fuzzer-plugin.md` (APPROVED) | The C fuzzer plugin can benefit from parameter sources for generating fuzz targets, but that integration is out of scope for this plan. |

### Deviations from Established Patterns

| Deviation | Justification |
|-----------|---------------|
| New parameter on `ScannerBackend.scan_files()` protocol | The protocol is internal to the project (no external consumers). Adding a defaulted parameter is non-breaking. The alternative (injecting sources via a separate mechanism) would require refactoring the backend contract more extensively. |
| Source category `"func_param"` not in YAML registry | Registry-defined source categories represent static patterns (e.g., `argv`). Parameter sources are dynamically extracted from the AST. Adding them to the registry YAML would require a fundamentally different registry format (per-function rather than per-pattern). Using a synthetic category is the minimal-disruption approach. |
| `Source.function` field holds parameter name instead of source API name | For `func_param` sources, `Source.function` stores the parameter name (e.g., `"buf"`) rather than a source function name (e.g., `"argv"`). This is semantically different but mechanically correct: the taint engine uses `source.function` as the seed variable name, and for parameter sources the parameter name IS the correct variable to taint. Downstream consumers can distinguish via `source.category == "func_param"`. |
| Semgrep parameter sources are "best effort" | Semgrep's pattern DSL cannot express "all parameters of non-static functions" generically without exhaustive enumeration. The tree-sitter backend is the authoritative implementation. This aligns with the existing pattern: tree-sitter provides full intraprocedural taint tracking, while Semgrep provides its own intraprocedural analysis with different strengths. |
| Small change to `TaintEngine._analyze_function()` | A 3-line guard is added to skip `_find_assigned_var_near_line()` for `func_param` sources. This prevents false taint seeding from nearby local variable declarations. The change is minimal and does not alter behavior for any other source category. |

<!-- Context Metadata
discovered_at: 2026-03-20T15:00:00Z
claude_md_exists: true
recent_plans_consulted: c-language-support.md, semgrep-scanner-backend.md, c-fuzzer-plugin.md
archived_plans_consulted: conditional-assignment-sanitizer review, semgrep-scanner-backend review
-->
