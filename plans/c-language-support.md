# Plan: C Language Support for the Hunter Pipeline

## Status: DRAFT

## Goals

1. Make `dcs hunt /path/to/openssl` (or any C codebase) produce useful SAST findings covering the most critical C vulnerability classes.
2. Expand the existing skeletal `registries/c.yaml` into a comprehensive registry covering: buffer overflows (CWE-119/CWE-120), command injection (CWE-78), format string bugs (CWE-134), integer overflow (CWE-190), and dangerous function usage (CWE-676).
3. Extend the taint tracker to handle C-specific idioms: pointer assignments, array indexing, `sizeof`-guarded paths, and string manipulation functions (`strcpy`, `strcat`, `sprintf`, `memcpy`).
4. Add C-specific source categories: `cli_input` (existing `argv`/`gets`, plus `fgets` for stdin), and `env_input` (existing `getenv`). Note: C source functions that deliver tainted data via output parameters (`recv`, `fread`, `read`, `scanf`, `getline`) are deferred because the LHS-seeding taint engine cannot taint the buffer argument -- only `argv`, `getenv`, `gets`, and `fgets` (return-value sources) are effective taint sources in v1. See Known Limitations.
5. Add C-specific sanitizer entries for bounded functions (`strncpy`, `snprintf`, `strncat`, `strlcpy`/`strlcat`).
6. Provide test fixtures and a comprehensive test suite demonstrating end-to-end detection of C vulnerabilities, including false-negative documentation.
7. Update the CWE name mapping in the hunter orchestrator to cover all new CWE identifiers.
8. Ensure the scanner handles real-world C codebases (OpenSSL-scale: ~500k LOC, thousands of `.c`/`.h` files) without performance degradation.

## Non-Goals

- **C fuzzer plugin.** A `CTargetPlugin` for the AI fuzzer is a separate plan requiring compilation, binary instrumentation, and crash analysis. Out of scope.
- **Preprocessor expansion.** We parse the literal source as written. `#ifdef`/`#include` directives are visible in the AST but conditional blocks are not resolved. This is a known limitation consistent with tree-sitter's approach.
- **Cross-file / interprocedural taint.** The v1 architecture is intraprocedural. Function calls like `process(user_buf)` where `process` calls `strcpy` internally are not tracked. This is the same limitation as Python/Go.
- **C++ support.** C++ has a different tree-sitter grammar (`tree-sitter-cpp`). C++ support is a separate plan.
- **Header-only analysis.** `.h` files are already discovered by `file_discovery.py` (via `EXTENSION_MAP`). They will be scanned like `.c` files, but we do not resolve `#include` to inline header contents. Findings in headers are reported at their header file location.
- **Auditor PoC templates for C.** Generating and executing C exploit PoCs requires compilation and binary execution, which is architecturally different from Python/Go PoCs. Deferred.
- **Architect remediation guidance for new CWEs.** The architect already has `(CWE-120, c)` guidance. Adding guidance for CWE-190, CWE-676 is desirable but orthogonal to the hunter pipeline and can be done incrementally.
- **Memory leak detection (CWE-401).** Detecting missing `free()` requires whole-function path analysis beyond source-to-sink taint. This is architecturally different from the current pipeline and is deferred. The existing pipeline can only flag taint-flow vulnerabilities, not the absence of a call.
- **Use-after-free detection (CWE-416).** Detecting use-after-free requires temporal ordering analysis (tracking that `free(ptr)` precedes a subsequent use of `ptr`). This is fundamentally different from the source-to-sink taint model: the vulnerability is not about tainted data flowing to a dangerous function, but about a temporal property (deallocation followed by use). Implementing this correctly requires either a separate temporal ordering pass or a "post-sink tracking" concept that does not exist in the current engine. Deferred to a future plan.

## Assumptions

1. `tree-sitter-c>=0.23.0,<0.23.5` is already a dependency in `pyproject.toml` and the parser already loads it in `parser.py` lines 90-96.
2. `Language.C` is already defined in `shared/language.py` with `.c` and `.h` extensions mapped.
3. The taint tracker already has a `"c"` entry in `_LANGUAGE_NODE_TYPES` (lines 40-49 of `taint_tracker.py`) covering `assignment_expression`, `init_declarator`, `binary_expression`, `call_expression`, `function_definition`, `argument_list`, and `return_statement`.
4. The existing `registries/c.yaml` has 5 sources and 4 sink categories with basic queries that compile and execute. This plan extends it, not replaces it.
5. The existing `tests/fixtures/vulnerable_samples/c/buffer_overflow.c` fixture exercises basic `strcpy`/`sprintf`/`printf`/`system` patterns. Additional fixtures are needed.
6. OpenSSL and similar projects do not use C++ features in `.c` files, so `tree-sitter-c` grammar is sufficient for scanning them.
7. The `_cwe_name()` function in `orchestrator.py` already has entries for CWE-120 ("Buffer Copy without Checking Size") and CWE-676 ("Use of Potentially Dangerous Function"). Only CWE-119 and CWE-190 need to be added.

## Proposed Design

### 1. Registry Expansion (`registries/c.yaml`)

The existing registry has basic sources (`argv`, `gets`, `fgets`, `getenv`) and sinks (`system`, `popen`, `execv*`, `strcpy`/`strcat`/`sprintf`, `printf`/`fprintf`/`syslog`, `fopen`/`open`). The previous `scanf` source is commented out (output-parameter limitation -- see Known Limitations). We expand the registry with:

#### New Source Categories

No new source categories are added in this plan. The existing `cli_input` (`argv`, `gets`, `fgets`) and `env_input` (`getenv`) categories are retained. The previous `scanf` source entry under `cli_input` is commented out (output-parameter limitation).

**Deferred (output-parameter sources):** The following C source functions deliver tainted data via output parameters (buffer arguments) rather than return values. The v1 taint engine seeds taint by finding the LHS variable of the assignment containing the source call (`_find_assigned_var_near_line`). For output-parameter functions, this taints the wrong variable (e.g., the byte count return value of `recv`, not the buffer). These sources are included in the registry YAML as commented-out entries for documentation purposes but are NOT active taint sources:

- `recv` / `recvfrom` / `recvmsg` -- socket read functions (buffer arg tainted, not return value)
- `read` -- file descriptor read (buffer arg tainted, not return value)
- `fread` -- block read from FILE* (buffer arg tainted, not return value)
- `scanf` / `fscanf` / `sscanf` -- formatted input (output args tainted, not return value)
- `getline` / `getdelim` -- line-oriented input (buffer arg tainted via pointer, not return value)

**Sources that work correctly with LHS-seeding:**
- `argv` -- directly tainted identifier (command-line argument access)
- `getenv` -- returns tainted string directly via return value
- `gets(buf)` -- returns `buf` pointer; LHS seeding taints the return value correctly
- `fgets(buf, n, fp)` -- returns `buf` pointer or NULL; when assigned, LHS IS the buffer pointer

#### New Sink Categories

**`memory_corruption` (CWE-119)** -- Generic buffer overflow via memory copy
- `memcpy` / `memmove` / `memset` -- memory operations where tainted data determines the size or source buffer
- `bcopy` (deprecated, still found in legacy code like OpenSSL)

**`integer_overflow` (CWE-190)**
- Arithmetic on values derived from tainted sources used as a size argument to `malloc`/`calloc`/`realloc`
- Pattern: tainted variable used in `malloc(tainted * sizeof(...))` or similar

**`dangerous_function` (CWE-676)**
- `gets` (already a source, but also flagged as a dangerous sink -- always vulnerable regardless of input)
- `mktemp` -- race condition (TOCTOU). **Note:** Because the taint-flow pipeline requires a source-to-sink path, `mktemp()` will only produce a CWE-676 finding if a tainted variable flows to its argument. In practice, `mktemp()` is called with hardcoded templates (e.g., `"/tmp/myXXXXXX"`), so most real-world uses will NOT be detected. See Risk #7 below.
- `tmpnam` -- race condition (TOCTOU). Same detection gap as `mktemp()`. See Risk #7 below.

#### New Sanitizer Entries

- `strlcpy` / `strlcat` -- neutralizes `buffer_overflow` (BSD/OpenSSL, guarantees null-termination)
- `strncat` -- neutralizes `buffer_overflow` (partial, same caveat as `strncpy`)
- `memcpy_s` / `strcpy_s` -- C11 Annex K bounds-checked variants, neutralizes `buffer_overflow` and `memory_corruption`

#### Full Registry YAML

The complete expanded registry:

```yaml
language: c
version: "2.0.0"

# Known Limitations (v1):
# - argv indexing patterns vary (argv[1], *(argv+1), etc.) -- only direct access matched
# - Pointer aliasing (char *p = argv[1]; use(p)) -- tracked within same function only
# - Function pointers for sinks -- NOT matched
# - Struct member injection patterns -- NOT matched
# - Preprocessor conditionals not resolved (#ifdef guards are invisible)
# - read() cannot be distinguished as network vs file I/O at AST level
# - CWE-416 (use-after-free) is NOT detected -- requires temporal ordering pass (future work)
# - mktemp()/tmpnam() (CWE-676) require a taint source in the same function to trigger;
#   standalone calls with hardcoded arguments will NOT be flagged
# - printf("%s", tainted_var) (safe) cannot be distinguished from printf(tainted_var)
#   (vulnerable) -- both are flagged as CWE-134 format string findings (false positive class)
# - C source functions that deliver tainted data via output parameters (recv, fread, read,
#   scanf, getline) are not effective taint sources in v1. Only functions whose return value
#   IS the tainted data (argv, getenv, gets, fgets) work correctly with the LHS-seeding taint
#   engine. Functions that write tainted data to a buffer argument are deferred to a future
#   plan increment that adds output-parameter taint summaries.

sources:
  cli_input:
    - pattern: "argv"
      tree_sitter_query: |
        (identifier) @source
        (#eq? @source "argv")
      severity: medium

    # NOT YET SUPPORTED: output-parameter source (taints buffer arg, not return value). See Known Limitations.
    # - pattern: "scanf"
    #   tree_sitter_query: |
    #     (call_expression
    #       function: (identifier) @fn
    #       (#match? @fn "^(scanf|fscanf|sscanf)$")) @source
    #   severity: high

    - pattern: "gets"
      tree_sitter_query: |
        (call_expression
          function: (identifier) @fn
          (#eq? @fn "gets")) @source
      severity: critical

    - pattern: "fgets"
      tree_sitter_query: |
        (call_expression
          function: (identifier) @fn
          (#eq? @fn "fgets")) @source
      severity: medium

  env_input:
    - pattern: "getenv"
      tree_sitter_query: |
        (call_expression
          function: (identifier) @fn
          (#eq? @fn "getenv")) @source
      severity: low

  # NOT YET SUPPORTED: output-parameter source (taints buffer arg, not return value). See Known Limitations.
  # network_input:
  #   - pattern: "recv"
  #     tree_sitter_query: |
  #       (call_expression
  #         function: (identifier) @fn
  #         (#match? @fn "^(recv|recvfrom|recvmsg)$")) @source
  #     severity: high
  #
  #   - pattern: "read"
  #     tree_sitter_query: |
  #       (call_expression
  #         function: (identifier) @fn
  #         (#eq? @fn "read")) @source
  #     severity: medium

  # NOT YET SUPPORTED: output-parameter source (taints buffer arg, not return value). See Known Limitations.
  # file_input:
  #   - pattern: "fread"
  #     tree_sitter_query: |
  #       (call_expression
  #         function: (identifier) @fn
  #         (#eq? @fn "fread")) @source
  #     severity: medium
  #
  #   - pattern: "getline"
  #     tree_sitter_query: |
  #       (call_expression
  #         function: (identifier) @fn
  #         (#match? @fn "^(getline|getdelim)$")) @source
  #     severity: medium

sinks:
  command_injection:
    cwe: "CWE-78"
    entries:
      - pattern: "system"
        tree_sitter_query: |
          (call_expression
            function: (identifier) @fn
            (#eq? @fn "system")) @sink
        severity: critical

      - pattern: "popen"
        tree_sitter_query: |
          (call_expression
            function: (identifier) @fn
            (#eq? @fn "popen")) @sink
        severity: critical

      - pattern: "execv"
        tree_sitter_query: |
          (call_expression
            function: (identifier) @fn
            (#match? @fn "^(execv|execl|execvp|execlp|execve|execle)$")) @sink
        severity: critical

  buffer_overflow:
    cwe: "CWE-120"
    entries:
      - pattern: "strcpy"
        tree_sitter_query: |
          (call_expression
            function: (identifier) @fn
            (#match? @fn "^(strcpy|strcat|wcscpy|wcscat)$")) @sink
        severity: high

      - pattern: "sprintf"
        tree_sitter_query: |
          (call_expression
            function: (identifier) @fn
            (#match? @fn "^(sprintf|vsprintf)$")) @sink
        severity: high

  memory_corruption:
    cwe: "CWE-119"
    entries:
      - pattern: "memcpy"
        tree_sitter_query: |
          (call_expression
            function: (identifier) @fn
            (#match? @fn "^(memcpy|memmove|memset|bcopy)$")) @sink
        severity: high

  format_string:
    cwe: "CWE-134"
    entries:
      - pattern: "printf"
        tree_sitter_query: |
          (call_expression
            function: (identifier) @fn
            (#match? @fn "^(printf|fprintf|syslog)$")) @sink
        severity: high

  integer_overflow:
    cwe: "CWE-190"
    entries:
      - pattern: "malloc"
        tree_sitter_query: |
          (call_expression
            function: (identifier) @fn
            (#match? @fn "^(malloc|calloc|realloc)$")) @sink
        severity: high

  dangerous_function:
    cwe: "CWE-676"
    entries:
      - pattern: "gets"
        tree_sitter_query: |
          (call_expression
            function: (identifier) @fn
            (#eq? @fn "gets")) @sink
        severity: critical

      - pattern: "mktemp"
        tree_sitter_query: |
          (call_expression
            function: (identifier) @fn
            (#match? @fn "^(mktemp|tmpnam)$")) @sink
        severity: high

  path_traversal:
    cwe: "CWE-22"
    entries:
      - pattern: "fopen"
        tree_sitter_query: |
          (call_expression
            function: (identifier) @fn
            (#match? @fn "^(fopen|open)$")) @sink
        severity: high

sanitizers:
  - pattern: "snprintf"
    neutralizes:
      - buffer_overflow
    description: "Bounded format function -- use instead of sprintf"

  - pattern: "strncpy"
    neutralizes:
      - buffer_overflow
    description: "Bounded string copy -- partial mitigation only (null termination risk)"

  - pattern: "strlcpy"
    neutralizes:
      - buffer_overflow
    description: "Bounded string copy with guaranteed null termination (BSD/OpenSSL)"

  - pattern: "strlcat"
    neutralizes:
      - buffer_overflow
    description: "Bounded string concatenation with guaranteed null termination (BSD/OpenSSL)"

  - pattern: "strncat"
    neutralizes:
      - buffer_overflow
    description: "Bounded string concatenation -- partial mitigation (size semantics differ from strncpy)"

  - pattern: "memcpy_s"
    neutralizes:
      - buffer_overflow
      - memory_corruption
    description: "C11 Annex K bounds-checked memory copy"

  - pattern: "strcpy_s"
    neutralizes:
      - buffer_overflow
    description: "C11 Annex K bounds-checked string copy"
```

### 2. Taint Tracker Enhancements (`hunter/taint_tracker.py`)

#### 2a. C-specific Assignment Handling

The existing `_handle_assignment` method (lines 416-424) already handles C's `assignment_expression` and `init_declarator`. However, it needs refinement for:

**Pointer assignments:** `char *p = buf;` -- in tree-sitter-c, the `init_declarator` node has children that include a `pointer_declarator` wrapping the actual identifier. We need to descend through `pointer_declarator` to extract the variable name.

**Declaration with type:** `int x = tainted_val;` -- the `init_declarator` is a child of `declaration`. The LHS can be an `identifier` or a `pointer_declarator` that wraps an identifier. Both `_extract_lhs_name` and `_node_to_var_name` need to handle these C-specific node types.

**Array subscript on LHS:** `buf[i] = tainted;` -- the LHS is a `subscript_expression`. We extract the base array name and taint it.

Implementation: Extend both `_node_to_var_name` and `_extract_lhs_name` to handle `pointer_declarator` and `subscript_expression` nodes when extracting the LHS name.

#### 2b. `_node_to_var_name` Enhancement

Add handling for C-specific node types:
- `pointer_declarator` -- descend to find the inner `identifier`
- `subscript_expression` -- extract the array name (first child identifier)
- `parenthesized_expression` -- unwrap to inner expression
- `cast_expression` -- the casted value carries taint (descend past the type specifier)

```python
def _node_to_var_name(self, node: Any) -> str | None:
    if node.type == "identifier":
        return node.text.decode("utf-8", errors="replace")
    if node.type in ("qualified_type", "type_identifier"):
        return node.text.decode("utf-8", errors="replace")
    # C-specific: unwrap pointer_declarator to get the actual identifier
    if node.type == "pointer_declarator":
        for child in node.children:
            if child.type == "identifier":
                return child.text.decode("utf-8", errors="replace")
            # Recursive: pointer to pointer (char **pp)
            if child.type == "pointer_declarator":
                return self._node_to_var_name(child)
    # C-specific: array subscript -- extract base array name
    if node.type == "subscript_expression":
        for child in node.children:
            if child.type == "identifier":
                return child.text.decode("utf-8", errors="replace")
    # C-specific: parenthesized expression -- unwrap
    if node.type == "parenthesized_expression":
        for child in node.children:
            result = self._node_to_var_name(child)
            if result:
                return result
    return None
```

#### 2c. `_extract_lhs_name` Enhancement

The `_extract_lhs_name` method (lines 318-338 of `taint_tracker.py`) is called from `_find_assigned_var_near_line` to seed the initial taint from a source. It currently only handles `identifier` and `expression_list` child types. For C pointer declarations like `char *p = recv(...)`, the `init_declarator` node's children include a `pointer_declarator` (not a bare `identifier`), so `_extract_lhs_name` returns `None` and the source variable is never seeded as tainted.

This must be extended to handle `pointer_declarator` nodes by descending to find the inner `identifier`. Without this fix, pointer-assigned source variables -- a very common C pattern -- fail to seed taint, producing false negatives for all downstream findings.

```python
def _extract_lhs_name(self, assignment_node: Any) -> str | None:
    for child in assignment_node.children:
        if child.type in ("identifier", "expression_list"):
            if child.type == "identifier":
                return child.text.decode("utf-8", errors="replace")
            # expression_list: first child
            if child.children:
                first = child.children[0]
                if first.type == "identifier":
                    return first.text.decode("utf-8", errors="replace")
        # C-specific: pointer_declarator wraps the identifier
        # e.g., char *p = recv(...) has init_declarator children
        # [pointer_declarator, "=", call_expression]
        if child.type == "pointer_declarator":
            return self._node_to_var_name(child)
        # C-specific: subscript_expression on LHS
        # e.g., buf[i] = tainted has subscript_expression
        if child.type == "subscript_expression":
            return self._node_to_var_name(child)
    return None
```

#### 2d. `_is_rhs_tainted` Enhancement

Add `field_expression` to the attribute-like node types checked in `_is_rhs_tainted`. In tree-sitter-c, both `struct_ptr->member` and `struct_var.member` are represented as `field_expression` nodes. Update the check on the tuple at line 477:

```python
if node.type in ("attribute", "selector_expression", "member_expression", "field_expression"):
```

#### 2e. `_classify_rhs_transform` Enhancement

Add C-specific transform classifications:
- `cast_expression` -> `"type_cast"` (taint propagates through casts)
- `pointer_expression` -> `"pointer_dereference"` (dereferencing a tainted pointer)
- `subscript_expression` -> `"array_access"` (accessing tainted array)

```python
if rhs_node.type == "cast_expression":
    return "type_cast"
if rhs_node.type == "pointer_expression":
    return "pointer_dereference"
if rhs_node.type == "subscript_expression":
    return "array_access"
```

### 3. CWE Name Mapping (`hunter/orchestrator.py`)

The `_cwe_name()` function at line 394 already has entries for CWE-120 and CWE-676. Add the missing CWE names:

```python
_cwe_names = {
    # ... existing entries (CWE-78, CWE-89, CWE-94, CWE-22, CWE-134, CWE-120, CWE-676, CWE-79) ...
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-190": "Integer Overflow or Wraparound",
}
```

### 4. Test Fixtures

#### Vulnerable Samples (`tests/fixtures/vulnerable_samples/c/`)

Create the following new fixture files. Each file contains intentionally vulnerable C code with clear comments marking the expected detection. Each follows the pattern established by `buffer_overflow.c`: header comment explaining the file is for testing only, `#include` directives, one or more vulnerable functions, and a `main()` that exercises them.

**`command_injection.c`** -- `argv` -> `sprintf` -> `system()` (CWE-78). Distinct from the existing `buffer_overflow.c` which also has a `system()` call, this fixture focuses on command injection as the primary vulnerability.

**`format_string.c`** -- `fgets` -> `printf(user_data)` (CWE-134). User input read via `fgets` is passed directly as the format string to `printf`. Note: the test should exercise the vulnerable pattern `printf(tainted_var)`, not the safe pattern `printf("%s", tainted_var)`. See Risk #4 for the false-positive class.

**`integer_overflow.c`** -- `argv` -> `atoi` -> arithmetic -> `malloc(tainted_size)` (CWE-190). A user-supplied integer is multiplied without overflow check before use as a `malloc` size.

**`dangerous_functions.c`** -- `gets()` (CWE-676). `gets()` is called in a context where a taint source flows to a subsequent `gets()` call, exercising the dual source+sink registration. Note: `mktemp()` and `tmpnam()` fixtures are omitted because they require a taint source flowing to their arguments to produce findings, which does not match their real-world usage pattern (see Risk #7).

**`memory_functions.c`** -- `argv` -> `memcpy` without bounds check (CWE-119). User-supplied input via `argv[1]` is used as the size argument to `memcpy(dst, src, atoi(argv[1]))`, exercising the taint path from CLI input to an unbounded memory copy.

**`network_input.c`** -- `fgets` -> `strcpy` (CWE-120, network input via fgets). Input read via `fgets(buf, sizeof(buf), stdin)` (or `fgets(buf, sizeof(buf), socket_file)`) is assigned to a variable and then copied to a fixed-size buffer via `strcpy(dst, buf)`. Uses `fgets` (a return-value source that works with LHS-seeding) rather than `recv` (an output-parameter source that does not).

The existing `buffer_overflow.c` already covers `strcpy` and `sprintf` with `argv`.

#### Safe Samples (`tests/fixtures/safe_samples/c/`)

**`bounded_copy.c`** -- Uses `strncpy`/`snprintf`/`strlcpy` (sanitized paths -- should produce zero or low-confidence findings). Demonstrates proper bounded string operations with the same taint sources.

**`safe_command.c`** -- Uses `execv` with hardcoded arguments, no user input in command. No taint source is present, so no source-to-sink path exists.

### 5. Performance Considerations for Large Codebases

The existing architecture handles large codebases via:
- `DCS_MAX_FILES` (default 10,000) -- enforced by `FileDiscovery`
- `MAX_PARSE_BYTES` (10MB per file) -- enforced by `TreeSitterParser`
- `DCS_QUERY_TIMEOUT` (5.0s) and `DCS_QUERY_MAX_RESULTS` (1000) -- enforced at query level
- `.gitignore` respect -- skips build artifacts, vendor directories

For C codebases like OpenSSL, additional considerations:
- Header files (`.h`) are included in the scan but typically contain declarations, not function bodies with taint flows. They will have sources/sinks found but few taint paths, adding minimal overhead.
- OpenSSL has ~1,800 `.c` and ~1,200 `.h` files totaling ~500k LOC. At tree-sitter parse speeds (~10ms per file), the full parse phase should complete in under 30 seconds.
- The registry expansion adds ~4 new active sink queries (output-parameter source queries are commented out). Combined with existing queries, the total is ~14 queries per file. With ~3,000 files, this is ~42,000 query executions. At <1ms per query, query execution adds <42 seconds.
- No code changes are needed for performance -- the existing limits are sufficient.

**Recommendation:** Add common C build artifact directories to `FileDiscovery.SKIP_DIRS`:
- `.deps` (autotools dependency tracking)
- `.libs` (libtool build artifacts)

This is a minor quality-of-life improvement, not a correctness requirement.

## Interfaces/Schema Changes

### No Pydantic Model Changes

The existing `Source`, `Sink`, `TaintStep`, `TaintPath`, and `RawFinding` models are language-agnostic. No schema changes are needed.

### No TaintState Changes

The `TaintState` dataclass is unchanged. CWE-416 (use-after-free) tracking, which would have required a `freed_vars` extension, is deferred to a future plan (see Non-Goals).

### Registry Schema

No structural changes. The YAML format is identical to `python.yaml` and `go.yaml`. New sink categories (`memory_corruption`, `integer_overflow`, `dangerous_function`) follow the existing `sinks.<category>.cwe` / `sinks.<category>.entries[]` pattern.

### CLI / MCP

No changes. `dcs hunt /path` already discovers `.c` and `.h` files and routes them through the C parser and registry. The `--languages c` filter already works because `Language.C` is defined.

## Data Migration

None. This plan adds new files and extends existing ones. No data formats change.

## Rollout Plan

1. **Phase 1: Registry + CWE names** -- Expand `registries/c.yaml` and update `_cwe_name()` in `orchestrator.py`. This immediately enables detection of new sink/source patterns via the existing engine. Note: source/sink discovery works with Phase 1 alone, but taint path tracking for C-specific patterns (pointer declarations, field expressions) requires Phase 2.
2. **Phase 2: Taint tracker refinements** -- Enhance `_node_to_var_name`, `_extract_lhs_name`, `_is_rhs_tainted`, and `_classify_rhs_transform` for C-specific node types. This improves taint propagation accuracy for pointer assignments, field expressions, and casts.
3. **Phase 3: Test fixtures + test suite** -- Add all fixture files and the `test_taint_c_paths.py` and `test_c_registry.py` test modules. Verify all existing tests still pass.
4. **Phase 4: FileDiscovery tuning** -- Add `.deps` and `.libs` to `SKIP_DIRS`. Optional but recommended.
5. **Phase 5: CLAUDE.md update** -- Update Known Limitations to document C language support, deferred CWE-416 detection, and the output-parameter source limitation (deferred `recv`/`fread`/`read`/`scanf`/`getline`).

All phases can be merged as a single commit. The phased breakdown is for implementation ordering within the task, not separate deployments.

## Risks

### 1. Tree-sitter C Grammar Node Type Mismatches (Medium)

**Risk:** The C grammar may use different node type names than expected (e.g., `field_expression` vs `member_expression`, `pointer_declarator` vs `pointer_declaration`). Tree-sitter grammar node types are not standardized across languages.

**Mitigation:** During implementation, the engineer MUST write a verification test that parses representative C code (containing pointer declarations, struct field access, cast expressions, array subscripts, function definitions) and walks the AST to print all node types. This test verifies that the node type names used in `_LANGUAGE_NODE_TYPES`, `_node_to_var_name`, `_extract_lhs_name`, `_is_rhs_tainted`, and `_classify_rhs_transform` match the actual tree-sitter-c grammar. If any name is wrong, update the code to match. The `tree-sitter-c` package bundles a `node-types.json` that can also be consulted.

### 2. Query False Positives on Common Functions (Medium)

**Risk:** Functions like `read()`, `memcpy()`, and `printf()` are extremely common in C code. Without context-aware filtering, we may flag thousands of benign uses as sinks.

**Mitigation:** The taint tracker already filters: a sink is only flagged if a tainted variable reaches its arguments. The registry queries find candidate sinks; actual findings require a taint path from a source. Additionally, the `DCS_MAX_RESULTS` limit (default 100) and severity threshold filtering provide output-level control.

### 3. Header File Noise (Low)

**Risk:** Scanning `.h` files may produce findings in system headers or vendored headers that are not interesting to the user.

**Mitigation:** `.gitignore` already excludes most vendored/build directories. Users can add specific paths to `.dcs-suppress.yaml` (from the suppressions-file plan). No code change needed.

### 4. Format String False Positives (`printf("%s", tainted_var)`) (Medium)

**Risk:** The format string sink query matches all `printf`/`fprintf`/`syslog` calls. The taint tracker checks whether any argument to these functions is tainted, but it cannot distinguish which argument position is the format string. `printf("%s", tainted_var)` is safe (tainted data is a data argument, not the format string), but it will be flagged as CWE-134 alongside the genuinely vulnerable `printf(tainted_var)`. This is a known false-positive class.

**Mitigation:** This is a fundamental limitation of the v1 taint tracker, which does not support argument-position-aware analysis. A future improvement could check whether the first argument to `printf` is the tainted one (format string position) versus a subsequent argument (data position), but this is beyond v1 scope. The false-positive class is documented in the registry YAML comments. Users can suppress specific findings via `.dcs-suppress.yaml`.

### 5. `gets()` Double-Counting (Low)

**Risk:** `gets()` is registered as both a source (`cli_input`) and a sink (`dangerous_function`). A call to `gets(buf)` would appear as both a source and a sink, potentially creating a self-referential taint path.

**Mitigation:** The taint tracker requires `sink.line > source.line` (line 256 in `taint_tracker.py`), so a single `gets()` call cannot be both source and sink of the same finding. If `gets()` appears twice (one call's output flows to another call), that is a legitimate finding.

### 6. `read()` Over-Matching (Low -- Deferred)

**Risk:** `read()` was previously registered as a `network_input` source, but most `read()` calls in C code operate on regular files, not sockets. Additionally, `read()` is an output-parameter source (tainted data lands in the buffer argument, not the return value), so it cannot produce correct taint paths with the current LHS-seeding engine.

**Mitigation:** `read()` is now commented out in the registry YAML as part of the output-parameter source deferral. If re-enabled in a future plan increment with output-parameter taint summaries, the over-matching concern should also be addressed (e.g., by checking if the fd argument is likely a socket via `socket()` or `accept()`).

### 7. `mktemp()`/`tmpnam()` Detection Gap (Medium)

**Risk:** `mktemp()` and `tmpnam()` are registered as `dangerous_function` (CWE-676) sinks, but they are dangerous unconditionally -- they do not need tainted input to be vulnerabilities. `mktemp()` is vulnerable because of a TOCTOU race condition on the generated path, not because its template argument is tainted. However, the taint-flow pipeline requires a source-to-sink taint path to produce a finding. In practice, `mktemp(template)` is almost always called with a hardcoded string literal (e.g., `"/tmp/myXXXXXX"`), which is never tainted. Functions containing `mktemp()` may not even have any taint sources. This means most real-world `mktemp()`/`tmpnam()` usage will NOT produce CWE-676 findings.

**Mitigation:** This is a fundamental limitation of the source-to-sink taint architecture, which cannot detect "always dangerous regardless of input" patterns. A lint-style unconditional check would require a different finding pipeline. The detection gap is documented in the registry YAML comments and in the CLAUDE.md Known Limitations update (Phase 5). The `mktemp`/`tmpnam` entries remain in the registry because they will still detect the (rare) case where tainted data flows to these functions, and they serve as a placeholder for future lint-mode support.

## Test Plan

### Test Command

```bash
make test-hunter
```

This runs all tests in `tests/test_hunter/` with coverage reporting for `src/deep_code_security/hunter/`.

For a focused run of just the new C tests:

```bash
pytest tests/test_hunter/test_taint_c_paths.py tests/test_hunter/test_c_registry.py -v
```

For the full suite (must remain at 90%+ coverage):

```bash
make test
```

### Test Module: `tests/test_hunter/test_taint_c_paths.py`

Mirrors the structure of `test_taint_go_paths.py` (existing file at `tests/test_hunter/test_taint_go_paths.py`):

1. **Fixtures:** `c_parser`, `c_registry`, `c_engine` -- load the C tree-sitter parser, C registry, and C taint engine. Pattern:
   ```python
   @pytest.fixture
   def c_parser() -> TreeSitterParser:
       return TreeSitterParser()

   @pytest.fixture
   def c_registry(c_parser):
       lang_obj = c_parser.get_language_object(Language.C)
       return load_registry(Language.C, REGISTRY_DIR, lang_obj)

   @pytest.fixture
   def c_engine(c_registry):
       return TaintEngine(language=Language.C, registry=c_registry)
   ```

2. **`TestCTaintPropagation`:**
   - `test_c_assignment_propagates` -- taint flows through `char *p = argv[1]; strcpy(buf, p);`
   - `test_c_pointer_assignment` -- taint flows through `char *p = tainted; char *q = p;`
   - `test_c_init_declarator` -- taint flows through `int x = atoi(argv[1]); malloc(x);`
   - `test_c_find_assigned_var` -- `_find_assigned_var_near_line` finds C variable names from `init_declarator` and `assignment_expression`
   - `test_c_array_subscript_lhs` -- assignment to `buf[i] = tainted` taints `buf`
   - `test_c_propagate_with_tainted_rhs` -- basic RHS taint check for C identifiers
   - `test_c_field_expression_tainted` -- taint detected in `struct_ptr->member` node

3. **`TestCLhsExtraction`:**
   - `test_c_extract_lhs_pointer_declarator` -- parse `char *p = value;` and verify `_extract_lhs_name` returns `"p"`
   - `test_c_extract_lhs_double_pointer` -- parse `char **pp = value;` and verify `_extract_lhs_name` returns `"pp"`
   - `test_c_extract_lhs_subscript` -- parse `buf[i] = value;` and verify `_extract_lhs_name` returns `"buf"`
   - `test_c_find_assigned_var_pointer_decl` -- `_find_assigned_var_near_line` finds variable name `p` from `char *p = getenv(...);`

4. **`TestCEndToEnd`:**
   - `test_buffer_overflow_detected` -- parse `buffer_overflow.c` fixture, find source-sink-path for `strcpy`
   - `test_command_injection_detected` -- parse `command_injection.c` fixture, find path `argv` -> `sprintf` -> `system`
   - `test_format_string_detected` -- parse `format_string.c` fixture, find path for `printf(user_input)`
   - `test_dangerous_function_gets` -- `gets()` flagged as CWE-676 sink when taint flows to it
   - `test_argv_to_memcpy` -- `argv` -> `atoi` -> `memcpy` size argument flagged as CWE-119
   - `test_fgets_to_strcpy` -- parse `network_input.c` fixture, find path `fgets` -> `strcpy` flagged as CWE-120
   - `test_safe_bounded_copy_no_findings` -- parse `bounded_copy.c`, assert zero findings (sanitizer neutralizes)
   - `test_safe_command_no_findings` -- parse `safe_command.c`, assert zero findings

5. **`TestCNodeTypes`:**
   - `test_c_engine_node_types_configured` -- verify all expected keys exist in `c_engine.node_types`
   - `test_c_function_definition_found` -- parse C code, verify `_find_function_nodes` returns `function_definition` nodes
   - `test_c_node_type_verification` -- parse representative C code and verify key AST node types match expectations. This is the risk mitigation test for Risk #1.

### Test Module: `tests/test_hunter/test_c_registry.py`

1. **`TestCRegistryLoad`:**
   - `test_c_registry_loads` -- `load_registry(Language.C, REGISTRY_DIR, lang_obj)` succeeds
   - `test_c_registry_version` -- version is `"2.0.0"`
   - `test_c_registry_source_categories` -- all expected source categories exist (`cli_input`, `env_input`)
   - `test_c_registry_sink_categories` -- all expected sink categories exist (`command_injection`, `buffer_overflow`, `format_string`, `path_traversal`, `memory_corruption`, `integer_overflow`, `dangerous_function`)
   - `test_c_registry_sanitizers` -- sanitizers list includes `snprintf`, `strncpy`, `strlcpy`, `strlcat`, `strncat`, `memcpy_s`, `strcpy_s`
   - `test_c_all_queries_compile` -- every source and sink entry has a non-None `compiled_query`

2. **`TestCSourceQueries`:**
   - `test_argv_source_found` -- query matches `argv` in `int main(int argc, char *argv[])`
   - `test_gets_source_found` -- query matches `gets(buf)`
   - `test_fgets_source_found` -- query matches `fgets(buf, sizeof(buf), stdin)`
   - `test_getenv_source_found` -- query matches `getenv("PATH")`

3. **`TestCSinkQueries`:**
   - `test_system_sink_found` -- query matches `system(cmd)`
   - `test_strcpy_sink_found` -- query matches `strcpy(dst, src)`
   - `test_printf_sink_found` -- query matches `printf(fmt)`
   - `test_memcpy_sink_found` -- query matches `memcpy(dst, src, n)`
   - `test_malloc_sink_found` -- query matches `malloc(size)`
   - `test_gets_sink_found` -- query matches `gets(buf)`
   - `test_mktemp_sink_found` -- query matches `mktemp(template)`
   - `test_fopen_sink_found` -- query matches `fopen(path, "r")`

### Existing Tests

All existing tests must continue to pass. The changes to `taint_tracker.py` are additive (new node type handling for `Language.C` in `_node_to_var_name` and `_extract_lhs_name`) and should not affect Python or Go behavior.

## Acceptance Criteria

1. `dcs hunt tests/fixtures/vulnerable_samples/c/` produces findings for all fixture files with correct CWE identifiers.
2. `dcs hunt tests/fixtures/safe_samples/c/` produces zero findings (sanitized paths or no taint flow).
3. `registries/c.yaml` loads without errors and all queries compile against tree-sitter-c grammar.
4. The C registry covers at least 7 CWE categories: CWE-78, CWE-119, CWE-120, CWE-134, CWE-190, CWE-22, CWE-676.
5. `make test-hunter` passes with all new tests green.
6. `make test` passes with 90%+ coverage maintained.
7. Scanning a real C project (e.g., a small OpenSSL subset or `curl`) with `dcs hunt` completes without errors and produces at least some findings.
8. The `--languages c` filter works correctly (only `.c`/`.h` files scanned).
9. `gets()` is flagged as both a CWE-676 dangerous function sink and a `cli_input` source. A function containing two `gets()` calls (where the first is the source and the second is the sink at a later line) produces a CWE-676 finding via the existing `sink.line > source.line` constraint.
10. All existing Python and Go hunter tests pass unchanged.
11. CLAUDE.md Known Limitations is updated to document C language support, that CWE-416 detection is deferred, and that C output-parameter source functions (`recv`, `fread`, `read`, `scanf`, `getline`) are not effective taint sources in v1 (deferred to a future plan increment that adds output-parameter taint summaries).

## Task Breakdown

### Files to Create

| # | File | Description |
|---|------|-------------|
| 1 | `tests/fixtures/vulnerable_samples/c/command_injection.c` | CWE-78 fixture: `argv` -> `sprintf` -> `system()` |
| 2 | `tests/fixtures/vulnerable_samples/c/format_string.c` | CWE-134 fixture: user input as printf format |
| 3 | `tests/fixtures/vulnerable_samples/c/integer_overflow.c` | CWE-190 fixture: tainted arithmetic in `malloc` size |
| 4 | `tests/fixtures/vulnerable_samples/c/dangerous_functions.c` | CWE-676 fixture: `gets()` exercising dual source+sink registration |
| 5 | `tests/fixtures/vulnerable_samples/c/memory_functions.c` | CWE-119 fixture: `argv` -> `atoi` -> `memcpy` size argument unbounded |
| 6 | `tests/fixtures/vulnerable_samples/c/network_input.c` | CWE-120 fixture: `fgets` -> `strcpy` (network input via fgets) |
| 7 | `tests/fixtures/safe_samples/c/bounded_copy.c` | Safe fixture: `strncpy`/`snprintf` usage |
| 8 | `tests/fixtures/safe_samples/c/safe_command.c` | Safe fixture: hardcoded command arguments |
| 9 | `tests/test_hunter/test_taint_c_paths.py` | C taint propagation, LHS extraction, and end-to-end tests |
| 10 | `tests/test_hunter/test_c_registry.py` | C registry loading and query compilation tests |

### Files to Modify

| # | File | Changes |
|---|------|---------|
| 11 | `registries/c.yaml` | Expand from 5 sources / 4 sink categories to 4 active sources / 7 sink categories with 7 sanitizers (6 additional sources commented out as deferred -- output-parameter limitation). Bump version to 2.0.0. Full content specified in Section 1 above. |
| 12 | `src/deep_code_security/hunter/taint_tracker.py` | (a) Add `pointer_declarator`, `subscript_expression`, `parenthesized_expression` handling to `_node_to_var_name`. (b) Add `pointer_declarator` and `subscript_expression` handling to `_extract_lhs_name` (critical for source-variable seeding of pointer declarations like `char *p = recv(...)`). (c) Add `"field_expression"` to the attribute-like node type tuple in `_is_rhs_tainted` (line 477). (d) Add `cast_expression`, `pointer_expression`, `subscript_expression` transform classifications to `_classify_rhs_transform`. |
| 13 | `src/deep_code_security/hunter/orchestrator.py` | Add CWE-119 and CWE-190 to the `_cwe_names` dict in `_cwe_name()` function. CWE-120 and CWE-676 are already present. |
| 14 | `src/deep_code_security/shared/file_discovery.py` | Add `".deps"` and `".libs"` to the `SKIP_DIRS` frozenset. |
| 15 | `CLAUDE.md` | Update Known Limitations to add: (a) C language support (intraprocedural taint, no preprocessor resolution, no struct member taint). (b) CWE-416 (use-after-free) detection is deferred -- requires temporal ordering pass. (c) `mktemp()`/`tmpnam()` (CWE-676) detection requires a taint source in the same function, so most real-world uses are missed. (d) C source functions that deliver tainted data via output parameters (`recv`, `fread`, `read`, `scanf`, `getline`) are not effective taint sources in v1. Only functions whose return value IS the tainted data (`argv`, `getenv`, `gets`, `fgets`) work correctly with the LHS-seeding taint engine. Functions that write tainted data to a buffer argument are deferred to a future plan increment that adds output-parameter taint summaries. |

### Implementation Order

1. **Step 1:** Modify `registries/c.yaml` (task 11) -- expand registry with full content from Section 1.
2. **Step 2:** Modify `orchestrator.py` (task 13) -- add 2 new CWE names.
3. **Step 3:** Modify `taint_tracker.py` (task 12) -- all C-specific enhancements (2a through 2e).
4. **Step 4:** Modify `file_discovery.py` (task 14) -- add skip dirs.
5. **Step 5:** Create all test fixtures (tasks 1-8).
6. **Step 6:** Create `test_c_registry.py` (task 10) -- verify registry loads and queries compile.
7. **Step 7:** Create `test_taint_c_paths.py` (task 9) -- verify taint tracking, LHS extraction, and end-to-end detection.
8. **Step 8:** Run `make test-hunter` to verify all hunter tests pass.
9. **Step 9:** Run `make test` to verify full suite at 90%+ coverage.
10. **Step 10:** Run `dcs hunt tests/fixtures/vulnerable_samples/c/` to verify CLI output.
11. **Step 11:** Update `CLAUDE.md` (task 15) -- add C-specific Known Limitations.

### Estimated Effort

- Registry expansion: ~1 hour
- Taint tracker enhancements: ~2 hours
- Orchestrator + file_discovery: ~15 minutes
- Test fixtures: ~1 hour
- Test suite: ~2 hours
- Integration testing against a real C project: ~30 minutes
- CLAUDE.md update: ~15 minutes

**Total: ~7 hours**

## Context Alignment

### CLAUDE.md Patterns Followed

| Pattern | How This Plan Follows It |
|---------|--------------------------|
| `yaml.safe_load()` only | Registry loading uses `yaml.safe_load()` via `registry.py` -- no changes needed |
| Pydantic v2 for data models | No model changes; existing models are language-agnostic |
| Type hints on public functions | All new/modified functions will have type hints |
| `__all__` in `__init__.py` | No new modules added; existing exports unchanged |
| `pathlib.Path` over `os.path` | All path handling uses `pathlib.Path` |
| No mutable default arguments | No new dataclass fields added |
| Registries in YAML files | All source/sink definitions are in `registries/c.yaml` |
| `models.py` per phase | No new models needed |
| `orchestrator.py` per phase | Only adding CWE names to existing orchestrator |
| 90%+ test coverage | New tests cover all new code paths |
| Intraprocedural taint only | Maintained; no cross-function analysis |
| tree-sitter for AST parsing | Uses existing `tree-sitter-c` grammar |
| Never `eval()`, `exec()`, `os.system()` | No new use of prohibited functions |

### Prior Plans Referenced

| Plan | Relationship |
|------|-------------|
| `deep-code-security.md` (original architecture) | States "C as stretch goal" -- this plan delivers on that |
| `suppressions-file.md` | Users can suppress C false positives via `.dcs-suppress.yaml` -- no changes needed |
| `sast-to-fuzz-pipeline.md` | The bridge module could theoretically convert C findings to fuzz targets, but the fuzzer only supports Python. C fuzzer plugin is out of scope. |

### Deviations from Established Patterns

| Deviation | Justification |
|-----------|---------------|
| `gets()` as both source and sink | `gets()` is unconditionally dangerous (CWE-676) regardless of where its input comes from. Having it as a source allows taint to propagate from it; having it as a sink flags any use. The taint tracker's `sink.line > source.line` constraint prevents self-referential findings. |
| Output-parameter sources deferred | `recv`, `fread`, `read`, `scanf`, `getline`, and `getdelim` deliver tainted data via buffer arguments (output parameters), not return values. The v1 LHS-seeding taint engine cannot taint the buffer argument, only the return value (which is metadata like a byte count, not the tainted data). These sources are commented out in the registry YAML and deferred to a future plan increment that adds output-parameter taint summaries. Only return-value sources (`argv`, `getenv`, `gets`, `fgets`) are active in v1. |
| Adding `dangerous_function` sink category | CWE-676 functions like `gets()` and `mktemp()` are dangerous regardless of input source. However, the hunter pipeline requires a source-to-sink taint path to produce a `RawFinding`. For `gets()`, this works because `gets()` is both source and sink (different calls). For `mktemp()`/`tmpnam()`, we rely on them appearing in functions that also have tainted inputs. A separate "lint-style" check that flags these functions unconditionally is architecturally different and deferred to avoid adding a new finding pipeline for v1 C support. See Risk #7 for the detection gap. |

<!-- Context Metadata
discovered_at: 2026-03-18T20:41:00Z
claude_md_exists: true
recent_plans_consulted: suppressions-file.md, sast-to-fuzz-pipeline.md, fuzzer-container-backend.md
archived_plans_consulted: deep-code-security.md, merge-fuzzy-wuzzy.md
-->

## Status: APPROVED
