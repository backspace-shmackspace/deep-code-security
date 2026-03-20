# Plan: C Fuzzer Plugin

## Status: APPROVED

## Goals

1. Add a `CTargetPlugin` that discovers C functions, compiles test harnesses, executes them in a sandbox, and returns `FuzzResult` objects compatible with the existing fuzzer pipeline.
2. Enable the `dcs fuzz --plugin c /path/to/project.c` CLI command to fuzz C targets using AI-generated test harnesses.
3. Build a dedicated container image (`dcs-fuzz-c:latest`) that includes gcc, AddressSanitizer support, and gcov for coverage instrumentation.
4. Generate C test harness source code (not Python expression strings) via a C-specific AI prompt that produces compilable `main()` functions calling the target.
5. Parse crash results from AddressSanitizer reports and signal-based crashes (SIGSEGV, SIGABRT, SIGFPE) into the existing `FuzzResult`/`UniqueCrash` dedup pipeline.
6. Integrate with the SAST-to-Fuzz bridge so `dcs hunt-fuzz` works on C codebases when the C plugin is enabled.
7. Support coverage-guided refinement using gcov line coverage data fed back to the AI engine.

## Non-Goals

- **Go fuzzer plugin.** Go fuzzing is a separate effort with different compilation and coverage semantics.
- **Cross-compilation support.** The C plugin compiles and runs on the same architecture as the host/container (linux/amd64 or linux/aarch64).
- **Build system integration.** v1 of the C fuzzer operates on individual `.c` files with explicit `#include` paths. Full make/cmake project integration is deferred.
- **Custom compiler selection.** v1 uses gcc inside the container. Clang support is deferred.
- **Shared library fuzzing.** v1 compiles single-file targets into standalone binaries. Linking against external `.so`/`.a` is deferred.
- **Interprocedural taint for bridge.** The bridge uses the same intraprocedural SAST findings as Python.
- **Corpus replay for C.** The replay subsystem requires a separate worker that can re-compile harnesses. Deferred.
- **MCP `deep_scan_fuzz` C support.** The MCP fuzz tool currently hardcodes `plugin_name="python"`. Adding a `plugin` parameter to the MCP tool schema is included in this plan, but the C container image must be available for it to work.
- **Static function fuzzing.** `static` functions have internal linkage and cannot be called from an external harness linked at compile time. Fuzzing `static` functions would require `#include`-ing the target `.c` file directly, which changes compilation semantics. Deferred to v2.

## Assumptions

1. The `TargetPlugin` ABC in `fuzzer/plugins/base.py` is stable and does not need modification. The C plugin implements all abstract methods.
2. The `FuzzInput` model's `args` field (tuple of Python expression strings) and `kwargs` field are not suitable for C inputs. The C plugin uses `FuzzInput.metadata` to carry a `"harness_source"` key containing the full C harness source code, while `args` carries a single entry `("'__c_harness__'",)` as a sentinel. The sentinel is a properly quoted Python string literal that passes `ast.literal_eval()` (producing the string `"__c_harness__"`). This avoids modifying the shared `FuzzInput` model while keeping the AI response parser compatible. The C response parser (`c_response_parser.py`) does not invoke `validate_expression()` on args -- expression validation is Python-specific. The `metadata` dict also carries `"plugin": "c"` so downstream code can detect C inputs.
3. The container image uses gcc 13+ with `-fsanitize=address` and gcov for coverage. The base image is `gcc:13-bookworm` (Debian).
4. tree-sitter-c is already a dependency (`pyproject.toml` line 28) and the C parser is functional for both function signature extraction and harness source validation.
5. Podman is required for the container backend (same as Python fuzzer MCP path). CLI mode uses `SubprocessBackend` with rlimits, compiling locally with whatever `gcc` is on PATH.
6. The AI engine (`engine.py`) and prompt system (`prompts.py`) are language-agnostic at the API call level. The C plugin provides C-specific prompts that produce JSON in a compatible format.
7. The `DCS_FUZZ_ALLOWED_PLUGINS` allowlist defaults to `"python"`. Users must set it to `"python,c"` (or just `"c"`) to enable the C plugin.

## Proposed Design

### 1. Architecture Overview

```
CTargetPlugin
    |
    +-- C Signature Extractor (tree-sitter-c)
    |       Parses .c files -> discovers function signatures
    |       Returns TargetInfo[] with C function metadata
    |
    +-- C Harness Worker (_c_worker.py)
    |       Fixed Python script that:
    |       1. Reads input.json (contains harness_source, target_file, compile_flags)
    |       2. Validates harness_source via tree-sitter-c AST analysis
    |       3. Writes harness_source to /build/harness.c
    |       4. Compiles: gcc -fsanitize=address -fprofile-arcs -ftest-coverage ...
    |       5. Executes /build/harness with timeout
    |       6. Parses exit code, ASan stderr, gcov data
    |       7. Writes output.json to /workspace (IPC)
    |
    +-- C Prompt Templates (c_prompts.py)
    |       System prompt + initial/refinement prompts
    |       AI generates compilable C harness source code
    |       Output format: JSON with harness_source field
    |
    +-- C Response Parser (c_response_parser.py)
    |       Validates AI-generated C harness source via tree-sitter-c AST
    |       Rejects harnesses with prohibited AST structures
    |       Returns FuzzInput with metadata["harness_source"]
    |       Does NOT call validate_expression() (Python-specific)
    |
    +-- CContainerBackend (subclass of ContainerBackend)
    |       Hardcodes C-specific mount policy:
    |         /workspace: noexec,nosuid (IPC only, same as Python)
    |         /build tmpfs: rw,nosuid (compilation + binary execution)
    |       Uses dcs-fuzz-c:latest image and seccomp-fuzz-c.json
    |
    +-- C Container Image (Containerfile.fuzz-c)
    |       gcc 13, ASan runtime, gcov, tree-sitter-c
    |       ENTRYPOINT: python3 _c_worker.py
    |
    +-- C Seccomp Profile (seccomp-fuzz-c.json)
            Same base as Python + empirically validated for ASan/gcc
```

### 2. C Signature Extractor (`fuzzer/analyzer/c_signature_extractor.py`)

Uses tree-sitter-c to parse `.c` files and extract function definitions. Produces `TargetInfo` objects with:

- `module_path`: Path to the `.c` file
- `function_name`: The C function name
- `qualified_name`: Same as function_name (no classes in C)
- `signature`: Full C signature string (e.g., `int process_input(const char *data, size_t len)`)
- `parameters`: List of `{"name": "data", "type_hint": "const char *", "default": "", "kind": "POSITIONAL_OR_KEYWORD"}`
- `source_code`: Full function source text
- `lineno` / `end_lineno`: Line range

Excluded targets:
- `static` functions (internal linkage, cannot be called from external harness without modification -- see Non-Goals)
- Functions with no parameters (nothing to fuzz)
- `main()` (entry point, not a fuzzing target)
- `inline` functions are included (they have external linkage by default and are callable from a harness)

The extractor uses tree-sitter queries rather than Python `ast` (which is Python-specific). The query pattern:

```scheme
(function_definition
  declarator: (function_declarator
    declarator: (identifier) @func_name
    parameters: (parameter_list) @params)
  body: (compound_statement) @body) @func_def
```

Storage class specifiers (`static`, `extern`, `inline`) are checked by examining the `storage_class_specifier` child nodes of the `function_definition` node.

### 3. C Harness Worker (`fuzzer/execution/_c_worker.py`)

A fixed Python script executed as a subprocess (same pattern as `_worker.py`). It does NOT use `eval()`. Instead:

1. Reads `input.json` from `/workspace` containing:
   - `harness_source`: Complete C harness source code (generated by AI)
   - `target_file`: Path to the original `.c` file (mounted read-only in container)
   - `compile_flags`: List of additional compiler flags
   - `collect_coverage`: Boolean

2. **Validates `harness_source` via tree-sitter-c AST analysis** (Layer 2 -- see Section 3a).

3. Writes `harness_source` to `/build/harness.c` (on the `/build` tmpfs, which allows execution).

4. Compiles with a **separate timeout** (30 seconds, enforced via `subprocess.run(timeout=30)`):
   ```
   gcc -fsanitize=address -fprofile-arcs -ftest-coverage \
       -g -O0 -Wall -Wextra \
       -o /build/harness /build/harness.c <target_file> \
       <compile_flags>
   ```

5. Executes `/build/harness` with a per-binary timeout (from `DCS_FUZZ_TIMEOUT_MS`), capturing stdout, stderr, and exit code.

6. Parses results:
   - Exit code 0: success
   - Exit code non-zero without ASan: runtime error (crash)
   - ASan output in stderr: parse the ASan report for error type and location
   - Signal-based termination: map signal number to name (SIGSEGV, SIGABRT, etc.)

7. If `collect_coverage` is true, runs `gcov harness.c <target_file>` and parses the `.gcov` output into the same coverage dict format used by coverage.py. gcov is invoked in a fresh subdirectory (`/build/gcov_out/`) to prevent TOCTOU manipulation of `.gcov` files by a malicious harness binary.

8. Writes `output.json` to `/workspace` in the same schema as the Python worker.

**Security: No `eval()`.** The C worker never evaluates any expression. It writes C source to a file and invokes gcc as a subprocess with list-form arguments. The compiled binary runs inside the container sandbox.

**Security: Harness validation is defense-in-depth, not the security boundary.** The container security policy (seccomp, network isolation, capabilities, read-only root) is the actual security boundary. Harness validation is a best-effort quality control filter that rejects obviously problematic AI-generated code before compilation. A determined adversary can bypass harness validation; the container security policy prevents meaningful exploitation even if validation is bypassed entirely.

### 3a. Tree-sitter-c AST Harness Validation

Both `c_response_parser.py` (Layer 1, host-side) and `_c_worker.py` (Layer 2, container-side) validate harness source using tree-sitter-c AST analysis rather than regex. The container image includes tree-sitter-c for Layer 2 validation.

Validation procedure:

1. **Parse with tree-sitter-c.** If parsing fails, reject the harness.

2. **Size check.** Source must be under 64 KB.

3. **Exactly one `main()` function.** Walk all `function_definition` nodes; exactly one must have declarator name `main`.

4. **Reject `asm_statement` nodes.** Walk the AST for any `asm_statement`, `__asm__`, or `gnu_asm_expression` nodes. Reject if found. This blocks inline assembly-based syscall invocation.

5. **Reject `#define` and `#undef` preprocessor directives.** Walk the AST for `preproc_def`, `preproc_function_def`, and `preproc_undef` nodes. Reject if found. This prevents macro-based obfuscation of prohibited function calls (e.g., `#define S system` then `S("/bin/sh")`). Allowed preprocessor directives: `#include` (validated separately in step 6).

6. **Validate `#include` directives.** Walk all `preproc_include` nodes. Only the following headers are allowed: `<stdlib.h>`, `<string.h>`, `<stdint.h>`, `<limits.h>`, `<stdio.h>`, `<math.h>`, `<stdbool.h>`, `<stddef.h>`, `<errno.h>`, `<float.h>`, `<assert.h>`. Reject any other include (especially `<sys/socket.h>`, `<netinet/in.h>`, `<sys/ptrace.h>`, `<dlfcn.h>`, `<unistd.h>`, `<signal.h>`).

7. **Reject prohibited function calls.** Walk all `call_expression` nodes. If the function field is an `identifier` node, check against the prohibited set: `system`, `popen`, `execl`, `execle`, `execlp`, `execv`, `execve`, `execvp`, `fork`, `vfork`, `socket`, `connect`, `bind`, `listen`, `accept`, `dlopen`, `dlsym`, `ptrace`, `kill`, `raise`, `signal`, `sigaction`. This catches direct calls but NOT function pointer aliasing (e.g., `void (*fn)(const char*) = system; fn("cmd");`). Function pointer aliasing is handled by the container security policy (the `system()` libc function itself invokes `/bin/sh`, which is not present in the container, and `--network=none` prevents exfiltration).

**Limitations of AST validation (documented, accepted):**
- **Function pointer aliasing is not caught.** A harness can assign `system` to a function pointer variable and call through the pointer. The AST validator sees a `call_expression` with an `identifier` that is the pointer variable name, not `system`. Container security policy is the defense.
- **Extern forward declarations bypass include checks.** A harness can declare `extern void *dlsym(void*, const char*);` without `#include <dlfcn.h>`. The prohibited function call check (step 7) catches the `dlsym` call itself.
- **Computed includes are not possible.** Step 5 rejects `#define`, preventing `#define HEADER "evil.h"` followed by `#include HEADER`.

### 4. C Prompt Templates (`fuzzer/ai/c_prompts.py`)

The C system prompt instructs Claude to generate compilable C test harness source code. Key differences from Python prompts:

- Output format includes `harness_source` instead of `args`/`kwargs` expression strings
- The harness must declare the target function `extern` (it is linked at compile time)
- The harness must define `main()` that calls the target function with adversarial inputs
- Focus areas: buffer overflows, integer overflows, format strings, null pointer dereference, off-by-one errors
- Inputs are C literal values, not Python expressions

Expected AI output format:
```json
{
  "inputs": [
    {
      "target_function": "process_input",
      "harness_source": "#include <stdlib.h>\n#include <string.h>\nextern int process_input(const char *data, size_t len);\nint main(void) {\n    char buf[4096];\n    memset(buf, 'A', sizeof(buf));\n    process_input(buf, sizeof(buf));\n    return 0;\n}\n",
      "rationale": "Buffer overflow: pass buffer larger than expected internal buffer size"
    }
  ]
}
```

The system prompt emphasizes:
- All harnesses must be self-contained and compilable
- Use `extern` declarations for target functions (the target `.c` file is compiled separately and linked)
- Do NOT include the target `.c` file via `#include` (it is linked at compile time)
- Only the allowed standard headers are permitted (see Section 3a step 6)
- No network, filesystem, or process-spawning code in harnesses
- No inline assembly
- No `#define` or `#undef` preprocessor directives

### 5. C Response Parser (`fuzzer/ai/c_response_parser.py`)

Parses AI responses into `FuzzInput` objects with `metadata["harness_source"]`. Validates:

1. JSON structure matches expected format (same `{"inputs": [...]}` wrapper)
2. Each input has `target_function`, `harness_source`, `rationale`
3. `target_function` matches a discovered target (same strict validation as Python)
4. `harness_source` passes tree-sitter-c AST validation (Section 3a)
5. Returns `FuzzInput` with:
   - `target_function`: The C function name
   - `args`: `("'__c_harness__'",)` -- sentinel value, a properly quoted Python string literal that passes `ast.literal_eval()`. NOT evaluated as a function argument.
   - `kwargs`: `{}` -- empty
   - `metadata`: `{"harness_source": "<validated source>", "rationale": "<AI rationale>", "source": "ai", "plugin": "c"}`

**Expression validation is skipped for C inputs.** The C response parser does NOT call `validate_expression()` from `expression_validator.py`. The sentinel value in `args` is a valid Python string literal (passes `ast.literal_eval()`) so it would survive expression validation if encountered, but the C response parser simply does not invoke it because expression validation is a Python-specific defense for `eval()` safety. C inputs are never `eval()`-ed.

The `metadata["plugin"] = "c"` tag allows downstream code (corpus serialization, replay) to detect C inputs and skip Python-specific processing.

The existing `response_parser.py` (Python) and `c_response_parser.py` (C) are separate modules. The `AIEngine` delegates to the correct parser based on configuration.

### 6. Container Image (`sandbox/Containerfile.fuzz-c`)

```dockerfile
FROM gcc:13-bookworm

# Install Python 3 and tree-sitter-c for worker-side harness validation
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-minimal \
    python3-pip \
    && pip3 install --no-cache-dir tree-sitter tree-sitter-c \
    && apt-get purge -y python3-pip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Create package structure for the worker
RUN mkdir -p /app/deep_code_security/fuzzer/execution \
             /app/deep_code_security/fuzzer/ai \
             /app/deep_code_security/fuzzer

COPY src/deep_code_security/fuzzer/execution/_c_worker.py \
     /app/deep_code_security/fuzzer/execution/_c_worker.py

# __init__.py files for package discovery
RUN touch /app/deep_code_security/__init__.py \
          /app/deep_code_security/fuzzer/__init__.py \
          /app/deep_code_security/fuzzer/execution/__init__.py \
          /app/deep_code_security/fuzzer/ai/__init__.py

ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONSAFEPATH=1

WORKDIR /workspace
USER 65534

ENTRYPOINT ["python3", "-m", "deep_code_security.fuzzer.execution._c_worker"]
```

Build command: `podman build -t dcs-fuzz-c:latest -f sandbox/Containerfile.fuzz-c .`

Note: tree-sitter and tree-sitter-c are installed in the container image for Layer 2 harness validation inside `_c_worker.py`. pip is removed after installation to reduce attack surface.

### 7. C Seccomp Profile (`sandbox/seccomp-fuzz-c.json`)

Based on the Python seccomp profile. The plan does NOT assume "no additional syscalls needed." Instead, the implementation task includes empirical validation:

1. Start with the Python seccomp profile as a baseline.
2. Run a test harness with ASan inside the container under `strace`.
3. Identify any `EPERM`/`ENOSYS` errors from syscalls blocked by the profile.
4. Add only the minimally required additional syscalls (candidates: `personality` for ASan ASLR control, `prctl` with `PR_SET_VMA` for shadow memory naming).
5. Document each addition with rationale.

The same explicit deny list is retained (ptrace, kernel modules, namespace ops, etc.).

### 8. CContainerBackend (`fuzzer/execution/sandbox.py`)

Instead of adding a `workspace_noexec` parameter to `ContainerBackend._build_podman_cmd` (which would make `noexec` removal a caller responsibility and weaken the Python security invariant), a `CContainerBackend` subclass is introduced that hardcodes the C-specific mount policy.

```python
class CContainerBackend(ContainerBackend):
    """Container backend for C fuzzer with separate IPC and build mounts.

    Security policy differences from Python ContainerBackend:
    - /workspace: rw,noexec,nosuid (IPC only -- identical to Python)
    - /build: tmpfs, rw,nosuid,nodev,size=128m (NO noexec -- compilation and
      binary execution occur here)
    - /tmp: rw,noexec,nosuid,size=64m (scratch -- identical to Python)

    The IPC mount at /workspace retains noexec,nosuid, preserving the
    invariant established in the approved fuzzer-container-backend plan.
    The /build tmpfs is a SEPARATE mount dedicated to compilation artifacts
    and binary execution. This isolates the binary execution surface from
    the IPC channel.
    """

    def __init__(
        self,
        runtime_cmd: list[str] | None = None,
        image: str | None = None,
        seccomp_profile: str | None = None,
    ) -> None:
        from deep_code_security.shared.config import get_config
        config = get_config()

        super().__init__(
            runtime_cmd=runtime_cmd,
            image=image or config.fuzz_c_container_image,
            seccomp_profile=seccomp_profile or str(
                Path(__file__).resolve().parents[4] / "sandbox" / "seccomp-fuzz-c.json"
            ),
            memory_limit="1g",      # Larger for compilation artifacts
            tmpfs_size="64m",       # /tmp scratch (noexec retained)
        )

    def _build_podman_cmd(
        self,
        target_file: str,
        ipc_dir: str | None,
        timeout_seconds: float,
        run_id: str,
    ) -> list[str]:
        """Build podman command with separate IPC and build mounts.

        Overrides the parent to add the /build tmpfs mount (without noexec)
        while keeping /workspace with noexec,nosuid for IPC.
        """
        # Get the base command from parent (includes /workspace with noexec)
        podman_cmd = super()._build_podman_cmd(
            target_file=target_file,
            ipc_dir=ipc_dir,
            timeout_seconds=timeout_seconds,
            run_id=run_id,
        )

        # Insert the /build tmpfs mount (rw,nosuid -- NO noexec) before the
        # image name (last element). This is where gcc writes compiled
        # binaries and where the harness binary executes.
        podman_cmd.insert(-1, "--tmpfs=/build:rw,nosuid,nodev,size=128m")

        return podman_cmd
```

**Design rationale (addressing F-01, C-1):**
- The parent `ContainerBackend._build_podman_cmd` is NOT modified. Its `/workspace:rw,noexec,nosuid` mount is structurally guaranteed and cannot be accidentally weakened by callers.
- The C subclass adds a SEPARATE `/build` tmpfs mount (without `noexec`) for compilation and binary execution. This mount is distinct from the IPC channel at `/workspace`.
- The IPC directory (`/workspace`) remains `noexec,nosuid` for both Python and C, preserving the security invariant from the approved `fuzzer-container-backend` plan.
- The `_c_worker.py` reads `input.json` from `/workspace`, compiles to `/build/harness`, executes `/build/harness`, and writes `output.json` back to `/workspace`.
- The `/build` tmpfs includes `nodev` to prevent device node creation.

**Per-language `is_available()` (addressing F-05, M-3):**

`ContainerBackend.is_available()` is modified to accept an optional `image` parameter:

```python
@classmethod
def is_available(cls, image: str | None = None) -> bool:
    """Return True if Podman is installed and the specified worker image exists.

    Args:
        image: Container image to check. If None, checks the default
            Python fuzzer image (backward compatible).
    """
    from deep_code_security.shared.config import get_config
    config = get_config()
    check_image = image or config.fuzz_container_image
    # ... existing podman version + image inspect checks using check_image ...
```

The MCP server registration logic changes:
1. `deep_scan_fuzz` is registered if Podman is available AND at least one fuzz container image exists (Python or C).
2. At request time, when the handler receives `"plugin": "c"`, it checks `ContainerBackend.is_available(image=config.fuzz_c_container_image)`. If the C image is not available, it returns a structured error: `{"error": "C fuzzer container image not found. Run: make build-fuzz-c-sandbox"}`.
3. Similarly for Python: if `"plugin": "python"` (or default) and the Python image is missing, return a structured error.

### 9. CTargetPlugin (`fuzzer/plugins/c_target.py`)

```python
class CTargetPlugin(TargetPlugin):

    @property
    def name(self) -> str:
        return "c"

    @property
    def file_extensions(self) -> tuple[str, ...]:
        return (".c",)

    def discover_targets(self, path, allow_side_effects=False):
        # Uses c_signature_extractor to find C functions
        ...

    def execute(self, fuzz_input, timeout_ms, collect_coverage=True):
        # Extracts harness_source from fuzz_input.metadata
        # Invokes _c_worker.py via CFuzzRunner
        ...

    def validate_target(self, path):
        # Checks for .c files
        # In SubprocessBackend mode, also checks gcc availability
        ...

    def set_backend(self, backend):
        # Sets backend on internal CFuzzRunner
        ...
```

**Addressing review finding on `@property` (Librarian):** The plugin uses `@property` methods for `name` and `file_extensions`, matching the `TargetPlugin` ABC contract and the existing `PythonTargetPlugin` pattern. The `file_extensions` property returns a `tuple` (immutable) instead of a `list` to comply with the "no mutable default arguments" rule. Note: the ABC declares `-> list[str]` as the return type; the `tuple` return is compatible at runtime (both are sequences). If strict type checking requires it, the property can return `list((".c",))` on each call.

The plugin uses a `CFuzzRunner` (see Section 8a) which encapsulates the C-specific `input.json` format and worker invocation.

### 8a. CFuzzRunner

`CFuzzRunner` is a **separate class** (not a subclass of `FuzzRunner`). The Python `FuzzRunner` is deeply coupled to Python worker semantics (`module_path`, `qualified_name`, `args`, `kwargs`, `PYTHONPATH` environment, `_worker.py` invocation). A subclass would need to override nearly every method, providing no benefit over a separate implementation.

`CFuzzRunner` encapsulates:
1. Writing `input.json` with `harness_source`, `target_file`, and `compile_flags` (not Python module path / qualified name / args).
2. Invoking `_c_worker.py` instead of `_worker.py`.
3. Reading `output.json` in the same format as the Python worker.
4. Constructing a `SandboxManager` that uses `CContainerBackend` when container execution is required.

The `CTargetPlugin.set_backend()` method replaces the backend on the `CFuzzRunner`'s internal `SandboxManager`, same pattern as `PythonTargetPlugin`.

**Security: `CFuzzRunner` does NOT override security flags.** The `CContainerBackend._build_podman_cmd` method hardcodes all security flags (network=none, cap-drop=ALL, seccomp, etc.). `CFuzzRunner` passes only the target file path, IPC directory, and timeout. It cannot weaken the security policy.

### 10. Coverage Integration

gcov output is parsed by the C worker into the same dictionary format used by coverage.py:
```json
{
  "files": {
    "/target/vulnerable.c": {
      "executed_lines": [1, 2, 5, 8, 10],
      "missing_lines": [3, 4, 6, 7, 9]
    }
  },
  "totals": {
    "covered_lines": 5,
    "num_statements": 10,
    "percent_covered": 50.0
  }
}
```

This allows the existing `DeltaTracker` and `CoverageReport` models to work without modification.

**Coverage inside the C container:** Unlike the Python container (where coverage.py writes to host-side `.coverage` paths that are inaccessible from within the container), the C worker runs `gcov` inside the container and includes coverage data in `output.json`. The C container CAN collect coverage data even when using `ContainerBackend`. The orchestrator's `collect_coverage = not isinstance(self._backend, ContainerBackend)` check is overridden for C: the C plugin always passes `collect_coverage=True` regardless of backend type, because gcov data is collected and returned within the container via the JSON IPC protocol.

### 11. Crash Analysis

C crashes are mapped to the existing `FuzzResult` model:

| C Signal/ASan Error | FuzzResult.exception | FuzzResult.traceback |
|---|---|---|
| SIGSEGV | `"SignalError: SIGSEGV (segmentation fault)"` | ASan report or empty |
| SIGABRT | `"SignalError: SIGABRT (abort)"` | ASan report or empty |
| SIGFPE | `"SignalError: SIGFPE (floating point exception)"` | ASan report or empty |
| ASan heap-buffer-overflow | `"AddressSanitizer: heap-buffer-overflow"` | Full ASan report |
| ASan stack-buffer-overflow | `"AddressSanitizer: stack-buffer-overflow"` | Full ASan report |
| ASan use-after-free | `"AddressSanitizer: heap-use-after-free"` | Full ASan report |
| ASan null-deref | `"AddressSanitizer: SEGV on unknown address"` | Full ASan report |
| Compilation failure | `"CompilationError: <gcc stderr>"` | gcc error output |
| Non-zero exit (no ASan) | `"RuntimeError: exit code N"` | stderr output |

**Crash dedup correctness (addressing M-6):** The `crash_signature()` function in `corpus/manager.py` hashes `exc_type` and the last traceback file+line location. It does NOT include `FuzzInput.metadata` in the hash. Therefore, the same vulnerability triggered by two different harnesses (with different `harness_source` in metadata) will produce the same crash signature, and dedup will correctly group them.

For ASan crashes, `parse_traceback_location()` uses the regex `File "([^"]+)", line (\d+)` which matches Python tracebacks. The C worker formats ASan locations into this same format in the `traceback` field of `output.json` (e.g., `File "/target/vulnerable.c", line 42`), ensuring the existing regex extracts the crash location correctly.

### 12. Bridge Integration

The existing bridge `resolver.py` filters `finding.language.lower() != "python"` and skips non-Python findings. To support C:

1. The language filter is changed to check file extension of `sink_file`: `.py` dispatches to the Python extractor, `.c` dispatches to the C extractor. This avoids coupling the bridge to the fuzzer plugin registry.
2. If C findings exist but the C plugin is not in `DCS_FUZZ_ALLOWED_PLUGINS`, the bridge logs a warning and skips the finding (not silently dropped).
3. The `extract_targets_from_file` call is dispatched to `c_signature_extractor` for `.c` files.
4. The `FuzzTarget.file_path` and `function_name` are populated from C signature extraction results.

The bridge already uses `TargetInfo` which is language-agnostic. The `signature_extractor.py` import is replaced with a dispatcher that selects the correct extractor based on file extension.

**Note:** This expands the v1 scope boundary of the `sast-to-fuzz-pipeline` plan, which explicitly limited the bridge to Python-only. The prior plan's "v1" qualifier anticipated future expansion; this plan is that expansion.

### 13. AI Engine Changes

The `AIEngine` class is modified to support pluggable prompts and response parsing. The existing methods that hardcode Python-specific imports are changed to use instance-level callables.

**Concrete modifications to `AIEngine` (addressing F-03):**

1. `AIEngine.__init__` gains four optional parameters with defaults pointing to existing Python implementations:
   ```python
   def __init__(
       self,
       ...,
       system_prompt: str | None = None,
       initial_prompt_builder: Callable | None = None,
       refinement_prompt_builder: Callable | None = None,
       response_parser_fn: Callable | None = None,
   ):
       self._system_prompt = system_prompt or SYSTEM_PROMPT
       self._initial_prompt_builder = initial_prompt_builder or build_initial_prompt
       self._refinement_prompt_builder = refinement_prompt_builder or build_refinement_prompt
       self._response_parser_fn = response_parser_fn or parse_ai_response
   ```

2. `_call_api()` uses `self._system_prompt` instead of the module-level `SYSTEM_PROMPT`:
   ```python
   message = self._client.messages.create(
       model=self.model,
       max_tokens=4096,
       system=self._system_prompt,  # was: SYSTEM_PROMPT
       messages=[{"role": "user", "content": prompt}],
   )
   ```

3. `generate_initial_inputs()` uses `self._initial_prompt_builder()` instead of the imported `build_initial_prompt`:
   ```python
   prompt = self._initial_prompt_builder(targets, count, redact_strings=self.redact_strings)
   ```

4. `generate_sast_guided_inputs()` uses a `self._sast_prompt_builder` (also injectable, defaults to `build_sast_enriched_prompt`).

5. `refine_inputs()` uses `self._refinement_prompt_builder()` instead of `build_refinement_prompt`.

6. `_parse_with_validation()` uses `self._response_parser_fn()` instead of `parse_ai_response`.

**Orchestrator dispatch (addressing F-03, M-2):**

The `FuzzOrchestrator` constructs `AIEngine` with the correct prompt/parser based on `config.plugin_name`:

```python
# In orchestrator.py, before constructing AIEngine
if config.plugin_name == "c":
    from deep_code_security.fuzzer.ai.c_prompts import (
        C_SYSTEM_PROMPT,
        build_c_initial_prompt,
        build_c_refinement_prompt,
        build_c_sast_enriched_prompt,
    )
    from deep_code_security.fuzzer.ai.c_response_parser import parse_c_ai_response

    ai_engine = AIEngine(
        ...,
        system_prompt=C_SYSTEM_PROMPT,
        initial_prompt_builder=build_c_initial_prompt,
        refinement_prompt_builder=build_c_refinement_prompt,
        sast_prompt_builder=build_c_sast_enriched_prompt,
        response_parser_fn=parse_c_ai_response,
    )
else:
    # existing Python defaults -- no additional parameters needed
    ai_engine = AIEngine(...)
```

**`_dry_run()` dispatch (addressing M-2):**

The `_dry_run()` method is updated to dispatch by `config.plugin_name`:

```python
def _dry_run(self, targets: list) -> FuzzReport:
    if self.config.plugin_name == "c":
        from deep_code_security.fuzzer.ai.c_prompts import build_c_initial_prompt
        prompt = build_c_initial_prompt(targets, count=5, redact_strings=self.config.redact_strings)
    else:
        from deep_code_security.fuzzer.ai.prompts import build_initial_prompt
        prompt = build_initial_prompt(targets, count=5, redact_strings=self.config.redact_strings)
    # ... rest of dry_run display logic unchanged ...
```

### 14. MCP Integration

The `deep_scan_fuzz` MCP tool's `input_schema` gains an optional `plugin` field (default: `"python"`, enum: `["python", "c"]`). The handler passes `plugin_name=params.get("plugin", "python")` to `FuzzerConfig`.

The `deep_scan_fuzz_status` tool already returns plugin-agnostic results. No changes needed.

**MCP tool registration (addressing F-05):**

The MCP server registers `deep_scan_fuzz` if Podman is available AND at least one fuzz container image exists. At startup:

```python
# Register if ANY fuzz image is available
python_available = ContainerBackend.is_available(image=config.fuzz_container_image)
c_available = ContainerBackend.is_available(image=config.fuzz_c_container_image)
if python_available or c_available:
    self._register_tool(deep_scan_fuzz_schema, self._handle_fuzz)
```

At request time, the handler checks the specific plugin's image:

```python
async def _handle_fuzz(self, params):
    plugin = params.get("plugin", "python")
    if plugin == "c":
        if not ContainerBackend.is_available(image=config.fuzz_c_container_image):
            return {"error": "C fuzzer container image not found. Run: make build-fuzz-c-sandbox"}
        backend = CContainerBackend()
    else:
        if not ContainerBackend.is_available():
            return {"error": "Python fuzzer container image not found. Run: make build-fuzz-sandbox"}
        backend = ContainerBackend()
    ...
```

### 15. Compilation Circuit Breaker (addressing M-5)

The C plugin tracks compilation failures and stops early when compilation consistently fails, avoiding wasted API calls.

**Design:**

- A `_compile_failure_count` counter is maintained in the `FuzzOrchestrator` (or `CTargetPlugin`), reset at the start of each iteration.
- Each `FuzzResult` returned by `CTargetPlugin.execute()` is checked: if `result.exception` starts with `"CompilationError:"`, increment the counter.
- At the end of each iteration, compute the compilation failure rate: `compile_failures / total_inputs_in_iteration`.
- If the failure rate exceeds 80% for an iteration, increment a `_compile_fail_iterations` counter.
- After 3 consecutive iterations with >80% compilation failure rate, raise a `CircuitBreakerError` with a message indicating compilation failures.
- A successful iteration (failure rate <= 80%) resets `_compile_fail_iterations` to 0.
- Compilation error messages (gcc stderr) are included in the refinement prompt sent to the AI, so it can learn from and correct compilation failures.

**Feedback format in refinement prompt:**

```
## Recent Compilation Errors
The following harnesses failed to compile. Avoid these patterns:
1. Error: implicit declaration of function 'foo' (harness for process_input)
2. Error: expected ';' before '}' token (harness for parse_buffer)
```

### 16. Configuration Changes

New environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DCS_FUZZ_C_CONTAINER_IMAGE` | `dcs-fuzz-c:latest` | Podman image for C fuzzer |
| `DCS_FUZZ_C_COMPILE_FLAGS` | `""` | Additional gcc flags (comma-separated) |
| `DCS_FUZZ_C_INCLUDE_PATHS` | `""` | Additional include paths (comma-separated) |

`DCS_FUZZ_ALLOWED_PLUGINS` must include `"c"` for the C plugin to be loadable.

**SubprocessBackend on macOS:** SubprocessBackend mode for C is documented as "best effort" on macOS. On macOS, `gcc` is typically a symlink to Apple Clang, which has different ASan runtime behavior and gcov output format. The primary supported path is the container backend (Podman). The `validate_target()` method checks `gcc --version` output; if it reports Apple Clang, a warning is logged advising the user to use the container backend for reliable results.

## Interfaces / Schema Changes

### Modified Models

**No changes to `FuzzInput`** -- the C harness source is carried in `metadata["harness_source"]`. The `args` field uses a sentinel value `("'__c_harness__'",)`. The `metadata` dict includes `"plugin": "c"`.

**No changes to `FuzzResult`** -- C crashes map into existing `exception`/`traceback`/`success` fields.

**No changes to `TargetInfo`** -- the `parameters` list uses the same dict format with `type_hint` carrying C type strings.

### Modified Interfaces

**`AIEngine.__init__`** -- gains optional `system_prompt`, `initial_prompt_builder`, `refinement_prompt_builder`, `sast_prompt_builder`, `response_parser_fn` parameters. All default to existing Python implementations for backward compatibility.

**`AIEngine._call_api()`** -- uses `self._system_prompt` instead of module-level `SYSTEM_PROMPT`.

**`AIEngine.generate_initial_inputs()`** -- uses `self._initial_prompt_builder()` instead of imported `build_initial_prompt`.

**`AIEngine.refine_inputs()`** -- uses `self._refinement_prompt_builder()` instead of imported `build_refinement_prompt`.

**`AIEngine._parse_with_validation()`** -- uses `self._response_parser_fn()` instead of imported `parse_ai_response`.

**`FuzzOrchestrator.run()`** -- dispatches to C-specific prompt/parser based on `config.plugin_name`.

**`FuzzOrchestrator._dry_run()`** -- dispatches to C-specific prompt builder based on `config.plugin_name`.

**`ContainerBackend.is_available()`** -- gains optional `image` parameter (defaults to config, backward compatible).

**`bridge/resolver.py`** -- language filter expanded from Python-only to Python+C, dispatched by file extension.

**MCP `deep_scan_fuzz` schema** -- adds optional `plugin` string field.

**`pyproject.toml`** -- adds C plugin entry point.

**`Makefile`** -- adds `build-fuzz-c-sandbox` target.

### New Interfaces

**`c_signature_extractor.py`** -- `extract_c_targets_from_file(path) -> list[TargetInfo]`

**`_c_worker.py`** -- Fixed worker script. Same JSON IPC protocol as `_worker.py`. Reads from `/workspace`, compiles to `/build`, writes output to `/workspace`.

**`c_prompts.py`** -- `C_SYSTEM_PROMPT`, `build_c_initial_prompt()`, `build_c_refinement_prompt()`, `build_c_sast_enriched_prompt()`

**`c_response_parser.py`** -- `parse_c_ai_response(response_text, valid_targets) -> list[FuzzInput]`

**`c_target.py`** -- `CTargetPlugin(TargetPlugin)` implementation.

**`CContainerBackend`** -- Subclass of `ContainerBackend` with C-specific mount policy.

**`CFuzzRunner`** -- Separate class (not FuzzRunner subclass) for C worker invocation.

## Data Migration

None. No existing data formats change. New data flows through existing models.

## Rollout Plan

### Phase 1: Core Plugin (CLI-only, SubprocessBackend)
1. Implement `c_signature_extractor.py`
2. Implement `c_prompts.py` and `c_response_parser.py` (with tree-sitter-c AST validation)
3. Implement `_c_worker.py` (with tree-sitter-c AST validation, Layer 2)
4. Implement `CTargetPlugin` with `@property` methods and `CFuzzRunner`
5. Register plugin in `pyproject.toml`
6. Add `AIEngine` prompt/parser extensibility (constructor params + instance method delegation)
7. Add orchestrator dispatch for C plugin (including `_dry_run` dispatch)
8. Unit tests for all new modules
9. Manual smoke test: `DCS_FUZZ_ALLOWED_PLUGINS=c dcs fuzz --plugin c tests/fixtures/vulnerable_samples/c/buffer_overflow.c --consent --dry-run`

### Phase 2: Container Backend
1. Implement `CContainerBackend` subclass with separate `/workspace` (noexec) and `/build` (exec) mounts
2. Create `Containerfile.fuzz-c` (including tree-sitter-c for Layer 2 validation)
3. Create `seccomp-fuzz-c.json` (empirically validated with strace)
4. Add `build-fuzz-c-sandbox` Makefile target
5. Add `DCS_FUZZ_C_CONTAINER_IMAGE` config
6. Modify `ContainerBackend.is_available()` to accept optional `image` parameter
7. Integration test with Podman
8. Update MCP tool schema and registration logic

### Phase 3: Bridge Integration
1. Expand bridge resolver language filter (file extension dispatch)
2. Add C signature extraction dispatch
3. Test `dcs hunt-fuzz` on C targets
4. Update MCP `deep_scan_hunt_fuzz` for C

### Phase 4: Documentation and CLAUDE.md Updates
1. Update CLAUDE.md with C fuzzer plugin details
2. Update Known Limitations
3. Update environment variable table

## Risks

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| AI generates malicious C harnesses (sandbox escape attempts) | Critical | Medium | Tree-sitter-c AST validation rejects prohibited function calls, inline assembly, and macro definitions. Container runs with --network=none, --cap-drop=ALL, --read-only, seccomp, separate IPC/build mounts. **Container security policy is the actual defense boundary; AST validation is defense-in-depth quality control.** |
| Compilation failures dominate fuzzing iterations (wasted API calls) | High | High | The system prompt emphasizes compilable harnesses with extern declarations. Compilation errors are fed back to the AI in refinement prompts. Compilation circuit breaker: after 3 consecutive iterations with >80% compilation failure rate, iteration stops early. |
| gcov coverage data format varies across gcc versions | Medium | Low | Pin gcc:13 in the container image. Parse gcov output defensively with fallback to empty coverage data. |
| ASan report format changes across gcc versions | Medium | Low | Pin gcc:13. Parse ASan output with regex patterns that handle common variations. Unrecognized ASan output is reported as raw stderr. |
| C harness includes may not resolve in container | Medium | Medium | The harness uses `extern` declarations for target functions. The target `.c` file is linked (not included). Standard library headers are available in the container. Project-specific headers require `DCS_FUZZ_C_INCLUDE_PATHS`. |
| SubprocessBackend mode may not have gcc on PATH (macOS) | Medium | Medium | Document as "best effort." `validate_target()` checks gcc availability and warns if Apple Clang is detected. Users directed to use container backend for reliable results. |
| Large C files slow down tree-sitter parsing | Low | Low | Tree-sitter is designed for large files. The existing `DCS_QUERY_TIMEOUT` limit applies. |

## Trust Boundary Analysis

### New Trust Boundaries

1. **AI-generated C harness source -> _c_worker.py**: The harness source is untrusted user-influenced data (AI-generated from untrusted source code analysis). It is validated by `c_response_parser.py` (Layer 1: tree-sitter-c AST analysis on the host) and by `_c_worker.py` (Layer 2: tree-sitter-c AST analysis inside the container). Validation is defense-in-depth quality control; the container security policy is the actual defense boundary. The harness is compiled and executed inside a container with full security policy.

2. **Compiled binary execution**: The compiled binary is fully untrusted. It runs inside the Podman container with --network=none, --cap-drop=ALL, --security-opt=no-new-privileges, seccomp profile, read-only root filesystem, as nobody. The binary executes on the `/build` tmpfs (separate from the `/workspace` IPC mount). Even a complete sandbox escape from the binary would still be contained by the container security policy.

3. **gcov output**: gcov writes `.gcov` files to a fresh subdirectory (`/build/gcov_out/`), parsed by the worker. The parsing is defensive (regex-based, fallback to empty). gcov output is not executable. A malicious harness binary could pre-create `.gcov` files, but the worker creates a fresh subdirectory and the worst case is polluted coverage data (data quality issue, not security issue).

4. **gcc compiler**: gcc runs inside the container. It processes the harness source (untrusted) and the target `.c` file (untrusted). gcc is a well-tested compiler; adversarial source triggering gcc bugs is possible but extremely unlikely. The container security policy limits the blast radius. gcc compilation has a separate 30-second timeout.

### Unchanged Trust Boundaries

- AI API calls (same as Python fuzzer)
- JSON IPC between runner and worker (same protocol)
- MCP path validation (same validation)

## Container Security Policy

The C container enforces the same base policy as the Python container, with one structural addition (the `/build` tmpfs):

| Flag | Value | Rationale |
|------|-------|-----------|
| `--network` | `none` | No outbound network from compiled binary or gcc |
| `--read-only` | yes | Immutable root filesystem |
| `--tmpfs` | `/tmp:rw,noexec,nosuid,size=64m` | Writable scratch (noexec retained) |
| `--tmpfs` | `/build:rw,nosuid,nodev,size=128m` | **Compilation and execution mount (NO noexec).** Separate from IPC. Harness binary compiles and executes here. |
| `--volume` | `/workspace:rw,noexec,nosuid` | **IPC mount (noexec retained, identical to Python).** `input.json` and `output.json` only. |
| `--cap-drop` | `ALL` | No Linux capabilities |
| `--security-opt` | `no-new-privileges` | No setuid/setgid escalation |
| `--security-opt` | `seccomp=seccomp-fuzz-c.json` | Syscall allowlist (empirically validated) |
| `--pids-limit` | `64` | Fork bomb prevention |
| `--memory` | `1g` | Cgroup memory cap (larger than Python for compilation) |
| `--cpus` | `1.0` | CPU quota |
| `--user` | `65534:65534` | Run as nobody |
| `--rm` | yes | Ephemeral container |

**Key invariant preserved:** The IPC mount at `/workspace` retains `noexec,nosuid`, identical to the Python container. This prevents a compromised binary from planting executables in the IPC directory. The compiled binary executes on the separate `/build` tmpfs, which is ephemeral and destroyed with the container.

**Container timeout:** The `--timeout` flag is set to `compilation_timeout (30s) + execution_timeout (from DCS_FUZZ_TIMEOUT_MS) + 10s buffer`. For the default `DCS_FUZZ_TIMEOUT_MS=5000`, this is `30 + 5 + 10 = 45 seconds`.

## Supply Chain Assessment

### New Dependencies

**Python (host-side):** None. The C plugin uses only stdlib + existing project dependencies (tree-sitter, Pydantic).

**Python (container-side):** `tree-sitter` and `tree-sitter-c` are installed in the container image for Layer 2 harness validation.

### New Container Image Dependencies

| Dependency | Source | Risk Assessment |
|------------|--------|-----------------|
| `gcc:13-bookworm` | Docker Hub official | Low risk. Official gcc image maintained by Docker. Pinned to gcc 13 for reproducibility. |
| `python3-minimal` (Debian) | Debian APT | Low risk. Standard Python 3 runtime for the worker script. |
| `tree-sitter` (PyPI, container) | PyPI | Low risk. Already a project dependency on the host side. Pinned version in container build. |
| `tree-sitter-c` (PyPI, container) | PyPI | Low risk. Already a project dependency on the host side. Pinned version in container build. |

pip is removed from the container image after installation to reduce attack surface.

## Test Plan

### Unit Tests

All new modules require 90%+ coverage per CLAUDE.md.

1. **`test_c_signature_extractor.py`**: Test function discovery from C source. Test exclusion of static functions, main(), parameterless functions. Test inclusion of inline functions. Test extraction of parameter types. Test handling of variadic functions, function pointers as parameters. Test storage class specifier handling.

2. **`test_c_response_parser.py`**: Test parsing valid AI responses. Test tree-sitter-c AST rejection of prohibited function calls (system, exec, socket, dlsym, dlopen). Test rejection of inline assembly (`asm`, `__asm__`). Test rejection of `#define`/`#undef` macros. Test rejection of prohibited includes. Test rejection of oversized harnesses. Test sentinel value `"'__c_harness__'"` in FuzzInput.args. Test that `validate_expression()` is NOT invoked. Test `metadata["plugin"] == "c"` is set. Test target function validation.

3. **`test_c_prompts.py`**: Test prompt generation with C function signatures. Test SAST-enriched prompt. Test refinement prompt with coverage data and compilation errors. Test prompt injection mitigation (source code delimiters).

4. **`test_c_worker_validation.py`**: Test tree-sitter-c AST harness validation (prohibited functions, inline asm, macros, includes, main() check, size limits). Test output.json format. Test ASan output parsing. Test signal-to-exception mapping. Test gcov output parsing. Test gcc compilation timeout (30s separate timeout). Test ASan location formatting for dedup compatibility.

5. **`test_c_target_plugin.py`**: Test `@property` name returns `"c"`. Test `@property` file_extensions returns tuple `(".c",)`. Test validate_target for .c files and directories. Test discover_targets. Test execute flow (mocked runner). Test gcc-not-found error handling. Test Apple Clang detection warning.

6. **`test_c_bridge_resolver.py`**: Test that C findings are resolved to fuzz targets. Test language filter accepts C via file extension dispatch. Test C signature extraction dispatch. Test warning when C plugin is not in allowlist.

7. **`test_c_container_backend.py`**: Test `CContainerBackend._build_podman_cmd` produces correct mount flags: `/workspace` with `noexec,nosuid`, `/build` tmpfs without `noexec` but with `nosuid,nodev`. Test that parent `ContainerBackend._build_podman_cmd` is unchanged (no regression). Test container timeout calculation.

8. **`test_ai_engine_extensibility.py`**: Test `AIEngine` with injected system_prompt, prompt builders, and response parser. Test that `_call_api` uses `self._system_prompt`. Test that defaults are backward compatible (Python implementations used when no overrides).

9. **`test_dry_run_c.py`**: Test `_dry_run` with `config.plugin_name == "c"` shows C-specific prompt.

10. **`test_compilation_circuit_breaker.py`**: Test circuit breaker trips after 3 iterations with >80% compilation failure. Test reset on successful iteration.

### Integration Tests

11. **`test_integration/test_c_fuzz_container.py`** (requires Podman + image): Build and run a C harness in the container. Verify ASan detection of a known buffer overflow. Verify coverage data collection. Verify container security flags (no network, read-only root, etc.). Verify `/workspace` has noexec. Verify `/build` is used for compilation and execution.

### Adversarial Tests

12. **`test_c_harness_validation_adversarial.py`**: Test that the AST validator rejects known evasion patterns: function pointer aliasing to `system` (note: this is NOT caught by AST validation -- test documents the limitation and verifies container policy is the defense), macro-defined aliases (caught by `#define` rejection), inline assembly (caught by asm node rejection), extern-declared `dlsym` (caught by function call check), `#include` of prohibited headers (caught by include validation).

### Test Command

```bash
# Unit tests only
make test-fuzzer

# Integration tests (requires Podman + dcs-fuzz-c:latest image)
make build-fuzz-c-sandbox && make test-integration
```

### Test Fixtures

New fixture files in `tests/fixtures/vulnerable_samples/c/`:
- `fuzz_target_buffer.c` -- function with buffer overflow (for harness generation testing)
- `fuzz_target_format.c` -- function with format string vulnerability
- `fuzz_target_integer.c` -- function with integer overflow

## Acceptance Criteria

1. `DCS_FUZZ_ALLOWED_PLUGINS=c dcs fuzz --plugin c tests/fixtures/vulnerable_samples/c/buffer_overflow.c --consent --dry-run` shows the C-specific prompt with function signatures extracted from the C file.
2. The C fuzzer discovers at least one fuzzable target in the buffer_overflow.c fixture.
3. AI-generated harnesses compile successfully in at least 60% of iterations (measured over 5 runs with consent).
4. AddressSanitizer detects the known buffer overflow in the fixture when the AI generates an appropriate harness.
5. Coverage data from gcov is fed back to the AI in refinement prompts and shows monotonically non-decreasing line coverage.
6. The crash dedup pipeline correctly groups ASan crashes by error type and location.
7. `make test-fuzzer` passes with 90%+ coverage on all new modules.
8. The container image builds successfully: `make build-fuzz-c-sandbox`.
9. Integration test passes: harness compilation, execution, and ASan detection inside the container.
10. `dcs hunt-fuzz` on a C project with known SAST findings produces correlated fuzz results when the C plugin is enabled.
11. MCP `deep_scan_fuzz` with `"plugin": "c"` launches a C fuzz run when the C container image is available.
12. The `/workspace` mount inside the C container has `noexec` (verified by integration test).
13. The compilation circuit breaker stops iteration after 3 consecutive high-failure iterations.

## Context Alignment

### CLAUDE.md Patterns Followed

- **Pydantic v2** for all data-crossing models (TargetInfo reused, no new models needed)
- **`__all__` in `__init__.py`** for all new modules
- **pathlib.Path** over os.path in all new code
- **No `eval()`** in the C worker (deliberate divergence from Python worker pattern)
- **No `shell=True`** in subprocess calls (gcc invoked via list-form arguments)
- **No `yaml.load()`** (no YAML usage in C fuzzer)
- **Container security policy**: seccomp + no-new-privileges + cap-drop=ALL (non-negotiable)
- **Plugin allowlist**: `DCS_FUZZ_ALLOWED_PLUGINS` must include "c"
- **90%+ test coverage** for all new modules
- **Fixed worker script**: `_c_worker.py` is a fixed module, not dynamically generated
- **No mutable default arguments**: `CTargetPlugin.file_extensions` returns tuple, not list

### Prior Plans This Builds Upon

- **`plans/merge-fuzzy-wuzzy.md`** (APPROVED): Established the plugin architecture, TargetPlugin ABC, FuzzRunner/SandboxManager, ContainerBackend, expression validator, and JSON IPC protocol. This plan extends all of these for C.
- **`plans/c-language-support.md`** (APPROVED): Established C hunter SAST pipeline with tree-sitter-c. Explicitly listed "C fuzzer plugin" as a Non-Goal, stating it is "a separate plan requiring compilation, binary instrumentation, and crash analysis." This plan is that separate plan.
- **`plans/sast-to-fuzz-pipeline.md`** (APPROVED): Established the bridge architecture. This plan extends the bridge resolver to handle C findings, expanding the prior plan's v1 scope boundary (which limited the bridge to Python-only).
- **`plans/fuzzer-container-backend.md`** (APPROVED): Established the container security baseline including `noexec,nosuid` on the `/workspace` mount. This plan preserves that invariant for the IPC mount and adds a separate `/build` tmpfs for compilation/execution.

### Deviations from Established Patterns

1. **No `eval()` in C worker**: The Python worker uses `eval()` with restricted globals (SD-02). The C worker does not use `eval()` at all. C inputs are compiled source code, not expression strings. This is not a deviation but an improvement -- no justified security deviation is needed.

2. **`FuzzInput.args` sentinel value**: Using `("'__c_harness__'",)` as a sentinel in args is a pragmatic compromise to avoid modifying the shared FuzzInput model. The sentinel is a properly quoted Python string literal (passes `ast.literal_eval()`, producing the string `"__c_harness__"`). The C response parser does not invoke `validate_expression()` -- expression validation is Python-specific. The `metadata["plugin"] = "c"` tag allows downstream code to detect and handle C inputs.

3. **Separate `/build` tmpfs mount**: The C container adds a `/build` tmpfs mount without `noexec` for compilation and binary execution. The IPC mount at `/workspace` retains `noexec,nosuid`, preserving the security invariant from the approved `fuzzer-container-backend` plan. The `/build` tmpfs includes `nosuid,nodev` and is ephemeral (destroyed with the container). This is a necessary trade-off for C compilation; the security impact is mitigated by the full container security policy (seccomp, network=none, cap-drop=ALL, no-new-privileges, read-only root).

4. **`CContainerBackend` subclass**: Rather than parameterizing the existing `ContainerBackend` with `workspace_noexec`, a subclass hardcodes the C-specific mount policy. This keeps the Python security invariant structural (not caller-dependent) and makes the C-specific differences explicit and auditable.

5. **`CFuzzRunner` as separate class**: Rather than subclassing `FuzzRunner`, a separate `CFuzzRunner` class is used because the Python `FuzzRunner` is deeply coupled to Python worker semantics. The C runner shares the same `SandboxManager` pattern but has different `input.json` format and worker invocation.

6. **Orchestrator dispatch by plugin_name**: Rather than a fully pluggable prompt/parser system, the orchestrator uses a two-branch dispatch (`"c"` vs default). This is simpler and appropriate for v1 with only two languages. A fully extensible prompt plugin system is deferred.

7. **Tree-sitter-c AST validation instead of regex**: The harness validation uses tree-sitter-c AST analysis instead of regex pattern matching. This is more robust against obfuscation (macro definitions, whitespace/comment insertion) and catches structural violations (asm nodes, preproc_def nodes, call_expression nodes with prohibited function names). The validation is documented as defense-in-depth quality control, not the security boundary.

## Task Breakdown

### Files to Create

| # | File | Description |
|---|------|-------------|
| 1 | `src/deep_code_security/fuzzer/analyzer/c_signature_extractor.py` | C function discovery via tree-sitter |
| 2 | `src/deep_code_security/fuzzer/ai/c_prompts.py` | C-specific system/initial/refinement prompts |
| 3 | `src/deep_code_security/fuzzer/ai/c_response_parser.py` | Parse AI C harness responses into FuzzInput (tree-sitter-c AST validation, no expression validator) |
| 4 | `src/deep_code_security/fuzzer/execution/_c_worker.py` | Fixed C harness compile+execute worker (tree-sitter-c AST validation Layer 2) |
| 5 | `src/deep_code_security/fuzzer/execution/c_runner.py` | CFuzzRunner: C-specific worker invocation |
| 6 | `src/deep_code_security/fuzzer/plugins/c_target.py` | CTargetPlugin implementation (@property, tuple file_extensions) |
| 7 | `sandbox/Containerfile.fuzz-c` | Container image for C fuzzer (includes tree-sitter-c) |
| 8 | `sandbox/seccomp-fuzz-c.json` | Seccomp profile for C container (empirically validated) |
| 9 | `tests/test_fuzzer/test_analyzer/test_c_signature_extractor.py` | Unit tests for C extractor |
| 10 | `tests/test_fuzzer/test_ai/test_c_prompts.py` | Unit tests for C prompts |
| 11 | `tests/test_fuzzer/test_ai/test_c_response_parser.py` | Unit tests for C response parser (AST validation, no expression validator) |
| 12 | `tests/test_fuzzer/test_execution/test_c_worker_validation.py` | Unit tests for C worker AST validation |
| 13 | `tests/test_fuzzer/test_execution/test_c_container_backend.py` | Unit tests for CContainerBackend mount policy |
| 14 | `tests/test_fuzzer/test_plugins/test_c_target.py` | Unit tests for CTargetPlugin |
| 15 | `tests/fixtures/vulnerable_samples/c/fuzz_target_buffer.c` | Fixture: fuzzable buffer overflow |
| 16 | `tests/fixtures/vulnerable_samples/c/fuzz_target_format.c` | Fixture: fuzzable format string |
| 17 | `tests/fixtures/vulnerable_samples/c/fuzz_target_integer.c` | Fixture: fuzzable integer overflow |
| 18 | `tests/test_integration/test_c_fuzz_container.py` | Integration test for C container |
| 19 | `tests/test_bridge/test_c_resolver.py` | Unit tests for C bridge resolver |
| 20 | `tests/test_fuzzer/test_ai/test_ai_engine_extensibility.py` | Unit tests for AIEngine prompt/parser injection |
| 21 | `tests/test_fuzzer/test_c_harness_validation_adversarial.py` | Adversarial validation tests |

### Files to Modify

| # | File | Change |
|---|------|--------|
| 22 | `src/deep_code_security/fuzzer/ai/engine.py` | Add prompt/parser extensibility: constructor params, `_call_api` uses `self._system_prompt`, methods use `self._*_builder` and `self._response_parser_fn` |
| 23 | `src/deep_code_security/fuzzer/orchestrator.py` | Add C plugin dispatch for prompts/parser; update `_dry_run` for C; add compilation circuit breaker |
| 24 | `src/deep_code_security/fuzzer/execution/sandbox.py` | Add `CContainerBackend` subclass; modify `is_available()` to accept optional `image` parameter |
| 25 | `src/deep_code_security/bridge/resolver.py` | Expand language filter to support C via file extension dispatch; add extractor dispatch |
| 26 | `src/deep_code_security/mcp/server.py` | Add `plugin` field to `deep_scan_fuzz` schema; per-plugin image availability check at registration and request time |
| 27 | `src/deep_code_security/shared/config.py` | Add `fuzz_c_container_image` config field |
| 28 | `pyproject.toml` | Add C plugin entry point; add `_c_worker.py` to package-data |
| 29 | `Makefile` | Add `build-fuzz-c-sandbox` target |

## Work Groups

### Shared Dependencies
- `src/deep_code_security/fuzzer/analyzer/c_signature_extractor.py` (implement first -- CTargetPlugin, bridge, and tests depend on this)
- `tests/fixtures/vulnerable_samples/c/fuzz_target_buffer.c` (implement first -- used by multiple test groups)
- `tests/fixtures/vulnerable_samples/c/fuzz_target_format.c` (implement first)
- `tests/fixtures/vulnerable_samples/c/fuzz_target_integer.c` (implement first)

### Work Group 1: AI Prompt and Response Layer
- `src/deep_code_security/fuzzer/ai/c_prompts.py`
- `src/deep_code_security/fuzzer/ai/c_response_parser.py` (tree-sitter-c AST validation)
- `src/deep_code_security/fuzzer/ai/engine.py` (modification: prompt/parser extensibility)
- `tests/test_fuzzer/test_ai/test_c_prompts.py`
- `tests/test_fuzzer/test_ai/test_c_response_parser.py`
- `tests/test_fuzzer/test_ai/test_ai_engine_extensibility.py`

### Work Group 2: Execution Layer
- `src/deep_code_security/fuzzer/execution/_c_worker.py` (tree-sitter-c AST validation Layer 2)
- `src/deep_code_security/fuzzer/execution/c_runner.py` (CFuzzRunner)
- `src/deep_code_security/fuzzer/execution/sandbox.py` (modification: CContainerBackend, is_available)
- `sandbox/Containerfile.fuzz-c` (includes tree-sitter-c)
- `sandbox/seccomp-fuzz-c.json`
- `tests/test_fuzzer/test_execution/test_c_worker_validation.py`
- `tests/test_fuzzer/test_execution/test_c_container_backend.py`
- `tests/test_integration/test_c_fuzz_container.py`
- `tests/test_fuzzer/test_c_harness_validation_adversarial.py`

### Work Group 3: Plugin and Orchestrator
- `src/deep_code_security/fuzzer/plugins/c_target.py`
- `src/deep_code_security/fuzzer/orchestrator.py` (modification: C dispatch, dry_run, compilation circuit breaker)
- `tests/test_fuzzer/test_plugins/test_c_target.py`

### Work Group 4: Bridge and MCP Integration
- `src/deep_code_security/bridge/resolver.py` (modification: C support)
- `src/deep_code_security/mcp/server.py` (modification: plugin field, per-plugin availability)
- `src/deep_code_security/shared/config.py` (modification: fuzz_c_container_image)
- `tests/test_bridge/test_c_resolver.py`

### Work Group 5: Build and Registration
- `pyproject.toml` (modification: entry point + package-data)
- `Makefile` (modification: build-fuzz-c-sandbox)

---

<!-- Context Metadata
discovered_at: 2026-03-20T00:00:00Z
claude_md_exists: true
recent_plans_consulted: plans/c-language-support.md, plans/scanner-tui.md, plans/semgrep-scanner-backend.md
archived_plans_consulted: plans/merge-fuzzy-wuzzy.md, plans/sast-to-fuzz-pipeline.md, plans/fuzzer-container-backend.md
-->
