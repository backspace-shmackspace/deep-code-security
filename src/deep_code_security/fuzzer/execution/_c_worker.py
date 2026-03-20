"""Fixed C harness compile-and-execute worker.

This module is executed as a subprocess inside the C fuzzer container.
It reads parameters from a JSON file (sys.argv[1]), validates the harness
source via tree-sitter-c AST analysis (Layer 2 defense), compiles the
harness with gcc, executes the compiled binary, and writes results to the
output JSON file (sys.argv[2]).

SECURITY:
- No eval(). The harness is a C source file compiled by gcc.
- Layer 2 AST validation mirrors c_response_parser.py (Layer 1, host-side).
- The compiled binary runs in the /build tmpfs (exec allowed, nosuid, nodev).
- All subprocess calls use list-form arguments (no shell=True).
- gcov is run in a fresh /build/gcov_out/ subdirectory to prevent TOCTOU.
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import subprocess
import sys
import traceback
from pathlib import Path

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# AST validation constants (mirror of c_response_parser.py Layer 1)
# ──────────────────────────────────────────────────────────────────────────────

MAX_HARNESS_SIZE_BYTES = 64 * 1024  # 64 KB

ALLOWED_INCLUDES: frozenset[str] = frozenset(
    [
        "stdlib.h",
        "string.h",
        "stdint.h",
        "limits.h",
        "stdio.h",
        "math.h",
        "stdbool.h",
        "stddef.h",
        "errno.h",
        "float.h",
        "assert.h",
    ]
)

PROHIBITED_FUNCTION_CALLS: frozenset[str] = frozenset(
    [
        "system",
        "popen",
        "execl",
        "execle",
        "execlp",
        "execv",
        "execve",
        "execvp",
        "fork",
        "vfork",
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "dlopen",
        "dlsym",
        "ptrace",
        "kill",
        "raise",
        "signal",
        "sigaction",
    ]
)

# Compilation timeout (separate from binary execution timeout)
COMPILE_TIMEOUT_SECONDS = 30

# Build directory where gcc writes compiled binaries (exec allowed)
BUILD_DIR = Path("/build")
GCOV_OUT_DIR = BUILD_DIR / "gcov_out"

# Signal number to name mapping for crash reporting
SIGNAL_NAMES: dict[int, str] = {
    signal.SIGSEGV: "SIGSEGV",
    signal.SIGABRT: "SIGABRT",
    signal.SIGFPE: "SIGFPE",
    signal.SIGBUS: "SIGBUS",
    signal.SIGILL: "SIGILL",
    signal.SIGTRAP: "SIGTRAP",
}


# ──────────────────────────────────────────────────────────────────────────────
# Tree-sitter-c AST validation (Layer 2)
# ──────────────────────────────────────────────────────────────────────────────


class HarnessValidationError(ValueError):
    """Raised when harness source fails AST validation."""


def _validate_harness_source(harness_source: str) -> None:
    """Validate harness source via tree-sitter-c AST analysis.

    This is the same 7-step procedure documented in the plan Section 3a.
    It mirrors c_response_parser.py (Layer 1) for defense-in-depth.

    Validation is a best-effort quality control filter; the container
    security policy is the actual defense boundary.

    Args:
        harness_source: C source code string to validate.

    Raises:
        HarnessValidationError: If the harness fails any validation step.
    """
    # Step 2: Size check (before parsing to avoid parsing huge inputs)
    if len(harness_source.encode("utf-8")) > MAX_HARNESS_SIZE_BYTES:
        raise HarnessValidationError(
            f"Harness source exceeds {MAX_HARNESS_SIZE_BYTES // 1024} KB size limit"
        )

    # Step 1: Parse with tree-sitter-c
    try:
        import tree_sitter_c
        from tree_sitter import Language, Parser

        C_LANGUAGE = Language(tree_sitter_c.language())
        parser = Parser(C_LANGUAGE)
    except Exception as exc:
        raise HarnessValidationError(f"tree-sitter-c unavailable: {exc}") from exc

    try:
        source_bytes = harness_source.encode("utf-8")
        tree = parser.parse(source_bytes)
    except Exception as exc:
        raise HarnessValidationError(f"tree-sitter parsing failed: {exc}") from exc

    if tree.root_node.has_error:
        raise HarnessValidationError("Harness source has parse errors (tree-sitter)")

    # Collect all nodes for walking
    def _walk(node):  # type: ignore[no-untyped-def]
        yield node
        for child in node.children:
            yield from _walk(child)

    all_nodes = list(_walk(tree.root_node))

    # Step 3: Exactly one main() function
    main_count = 0
    for node in all_nodes:
        if node.type == "function_definition":
            # Find the function_declarator's declarator (the function name)
            for child in node.children:
                if child.type == "function_declarator":
                    for sub in child.children:
                        if sub.type == "identifier":
                            if sub.text == b"main":
                                main_count += 1
    if main_count != 1:
        raise HarnessValidationError(
            f"Harness must define exactly one main() function, found {main_count}"
        )

    # Step 4: Reject asm_statement nodes
    for node in all_nodes:
        if node.type in (
            "asm_statement",
            "gnu_asm_expression",
        ):
            raise HarnessValidationError(
                f"Harness contains prohibited inline assembly node: {node.type}"
            )
        # Also check for __asm__ identifiers
        if node.type == "identifier" and node.text in (b"__asm__", b"asm"):
            # Only reject if it's used as a statement keyword, not a variable
            # The parent context disambiguates this; a conservative approach
            # is to reject any identifier named __asm__ or asm at top scope
            if node.parent and node.parent.type in (
                "expression_statement",
                "compound_statement",
            ):
                raise HarnessValidationError(
                    "Harness contains prohibited inline assembly (__asm__/asm)"
                )

    # Step 5: Reject #define and #undef preprocessor directives
    for node in all_nodes:
        if node.type in ("preproc_def", "preproc_function_def"):
            raise HarnessValidationError(
                f"Harness contains prohibited preprocessor directive: {node.type}"
            )
        # tree-sitter-c emits #undef (both top-level and inside function bodies)
        # as a preproc_call node with a preproc_directive child.
        if node.type == "preproc_call":
            for child in node.children:
                if child.type == "preproc_directive":
                    directive = (child.text or b"").decode("utf-8", errors="replace").strip()
                    if directive in ("#undef",):
                        raise HarnessValidationError(
                            f"Harness contains prohibited preprocessor directive: {directive}"
                        )

    # Step 6: Validate #include directives
    for node in all_nodes:
        if node.type == "preproc_include":
            # Get the path node (string_literal or system_lib_string)
            path_text = None
            for child in node.children:
                if child.type in ("string_literal", "system_lib_string"):
                    path_text = child.text.decode("utf-8", errors="replace")
                    break
            if path_text is None:
                raise HarnessValidationError(
                    "Harness has a #include with non-literal path"
                )
            # Strip angle brackets or quotes
            header_name = path_text.strip("<>\"'")
            if header_name not in ALLOWED_INCLUDES:
                raise HarnessValidationError(
                    f"Harness includes prohibited header: {path_text!r}. "
                    f"Only standard headers are allowed: {sorted(ALLOWED_INCLUDES)}"
                )

    # Step 7: Reject prohibited function calls
    for node in all_nodes:
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node is not None and func_node.type == "identifier":
                func_name = func_node.text.decode("utf-8", errors="replace")
                if func_name in PROHIBITED_FUNCTION_CALLS:
                    raise HarnessValidationError(
                        f"Harness calls prohibited function: {func_name!r}"
                    )


# ──────────────────────────────────────────────────────────────────────────────
# ASan output parser
# ──────────────────────────────────────────────────────────────────────────────

# ASan error type patterns (ordered: check specific patterns first)
_ASAN_ERROR_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"heap-buffer-overflow"), "AddressSanitizer: heap-buffer-overflow"),
    (re.compile(r"stack-buffer-overflow"), "AddressSanitizer: stack-buffer-overflow"),
    (re.compile(r"heap-use-after-free"), "AddressSanitizer: heap-use-after-free"),
    (re.compile(r"use-after-poison"), "AddressSanitizer: use-after-poison"),
    (re.compile(r"stack-use-after-scope"), "AddressSanitizer: stack-use-after-scope"),
    (re.compile(r"global-buffer-overflow"), "AddressSanitizer: global-buffer-overflow"),
    (re.compile(r"SEGV on unknown address"), "AddressSanitizer: SEGV on unknown address"),
    (re.compile(r"AddressSanitizer:"), "AddressSanitizer: unknown error"),
]

# ASan location pattern -- emits as Python-compatible "File X, line Y" for dedup
_ASAN_LOCATION_RE = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+\S+\s+(\S+):(\d+)")


def _parse_asan_output(stderr: str) -> tuple[str | None, str | None]:
    """Parse ASan output to extract exception type and formatted traceback.

    Formats ASan locations as 'File "/target/foo.c", line N' to be
    compatible with the existing crash_signature() dedup regex.

    Returns:
        (exception_type, traceback_string) or (None, None) if not ASan output.
    """
    if "AddressSanitizer" not in stderr and "ASan" not in stderr:
        return None, None

    exc_type = None
    for pattern, label in _ASAN_ERROR_PATTERNS:
        if pattern.search(stderr):
            exc_type = label
            break
    if exc_type is None:
        exc_type = "AddressSanitizer: unknown error"

    # Format ASan stack frames as Python-style File/line entries for dedup
    formatted_lines: list[str] = [exc_type, ""]
    for match in _ASAN_LOCATION_RE.finditer(stderr):
        file_path = match.group(1)
        line_num = match.group(2)
        formatted_lines.append(f'  File "{file_path}", line {line_num}')

    traceback_str = "\n".join(formatted_lines) if len(formatted_lines) > 2 else stderr

    return exc_type, traceback_str


def _signal_name(signum: int) -> str:
    """Return the signal name string for a signal number."""
    descriptions = {
        signal.SIGSEGV: "SIGSEGV (segmentation fault)",
        signal.SIGABRT: "SIGABRT (abort)",
        signal.SIGFPE: "SIGFPE (floating point exception)",
        signal.SIGBUS: "SIGBUS (bus error)",
        signal.SIGILL: "SIGILL (illegal instruction)",
        signal.SIGTRAP: "SIGTRAP (trace/breakpoint trap)",
    }
    return descriptions.get(signum, f"signal {signum}")


# ──────────────────────────────────────────────────────────────────────────────
# gcov coverage parsing
# ──────────────────────────────────────────────────────────────────────────────


def _parse_gcov_output(gcov_dir: Path, source_files: list[str]) -> dict:
    """Parse gcov output files into the coverage_data dict format.

    Returns a dict compatible with coverage.py JSON output format:
    {
        "files": {
            "/target/foo.c": {
                "executed_lines": [...],
                "missing_lines": [...]
            }
        },
        "totals": {
            "covered_lines": N,
            "num_statements": M,
            "percent_covered": P
        }
    }
    """
    files: dict = {}
    total_covered = 0
    total_statements = 0

    for gcov_file in gcov_dir.glob("*.gcov"):
        try:
            content = gcov_file.read_text(errors="replace")
        except OSError:
            continue

        executed: list[int] = []
        missing: list[int] = []

        for line in content.splitlines():
            # gcov format: <count>:<line_no>:<source>
            parts = line.split(":", 2)
            if len(parts) < 2:
                continue
            count_str = parts[0].strip()
            try:
                line_no = int(parts[1].strip())
            except ValueError:
                continue
            if line_no <= 0:
                continue  # Skip file headers

            if count_str == "-":
                continue  # Non-executable line
            elif count_str == "#####":
                missing.append(line_no)
            else:
                try:
                    if int(count_str) > 0:
                        executed.append(line_no)
                    else:
                        missing.append(line_no)
                except ValueError:
                    continue

        # Determine the source file name from the gcov file header
        source_name = None
        for hdr_line in content.splitlines()[:5]:
            if hdr_line.startswith("        -:    0:Source:"):
                source_name = hdr_line.split("Source:", 1)[1].strip()
                break
        if source_name is None:
            # Fall back to using the gcov filename minus ".gcov"
            source_name = gcov_file.stem

        files[source_name] = {
            "executed_lines": sorted(executed),
            "missing_lines": sorted(missing),
        }
        total_covered += len(executed)
        total_statements += len(executed) + len(missing)

    percent = (total_covered / total_statements * 100.0) if total_statements > 0 else 0.0

    return {
        "files": files,
        "totals": {
            "covered_lines": total_covered,
            "num_statements": total_statements,
            "percent_covered": round(percent, 2),
        },
    }


# ──────────────────────────────────────────────────────────────────────────────
# Worker main logic
# ──────────────────────────────────────────────────────────────────────────────


def _write_output(output_path: str, result: dict) -> None:
    """Write result dict to output JSON file."""
    with open(output_path, "w") as f:
        json.dump(result, f)


def _error_result(exc_type: str, tb: str = "") -> dict:
    """Build a standard failure result dict."""
    return {
        "success": False,
        "exception": exc_type,
        "traceback": tb or None,
        "stdout": "",
        "stderr": "",
        "coverage_data": {},
        "returncode": -1,
    }


def main() -> None:
    """Main entry point for the C harness worker."""
    if len(sys.argv) != 3:
        print(
            "Usage: python -m deep_code_security.fuzzer.execution._c_worker"
            " <input_json> <output_json>",
            file=sys.stderr,
        )
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    # ── Read parameters ──────────────────────────────────────────────────────
    try:
        with open(input_path) as f:
            params = json.load(f)
    except Exception as exc:
        result = _error_result(
            f"WorkerSetupError: Cannot read input file: {exc}",
            traceback.format_exc(),
        )
        _write_output(output_path, result)
        return

    harness_source: str = params.get("harness_source", "")
    target_file: str = params.get("target_file", "")
    compile_flags: list[str] = params.get("compile_flags", [])
    collect_coverage: bool = params.get("collect_coverage", True)
    timeout_ms: int = params.get("timeout_ms", 5000)
    execution_timeout = max(1.0, timeout_ms / 1000.0)

    # When the caller passes an empty compile_flags list, fall back to the
    # environment variables DCS_FUZZ_C_COMPILE_FLAGS and DCS_FUZZ_C_INCLUDE_PATHS.
    # This lets users configure extra flags and include paths inside the container
    # even when the host-side runner does not forward them explicitly.
    if not compile_flags:
        extra_flags_env = os.environ.get("DCS_FUZZ_C_COMPILE_FLAGS", "")
        compile_flags = [f.strip() for f in extra_flags_env.split(",") if f.strip()]
        extra_includes_env = os.environ.get("DCS_FUZZ_C_INCLUDE_PATHS", "")
        for inc in extra_includes_env.split(","):
            inc = inc.strip()
            if inc:
                compile_flags.append(f"-I{inc}")

    # Basic input validation
    if not harness_source:
        result = _error_result("WorkerSetupError: harness_source is empty")
        _write_output(output_path, result)
        return
    if not target_file:
        result = _error_result("WorkerSetupError: target_file is empty")
        _write_output(output_path, result)
        return

    # Validate compile_flags: must be a list of strings
    if not isinstance(compile_flags, list) or not all(
        isinstance(f, str) for f in compile_flags
    ):
        result = _error_result("WorkerSetupError: compile_flags must be a list of strings")
        _write_output(output_path, result)
        return

    # ── Layer 2: AST validation ──────────────────────────────────────────────
    try:
        _validate_harness_source(harness_source)
    except HarnessValidationError as exc:
        result = _error_result(f"HarnessValidationError: {exc}")
        _write_output(output_path, result)
        return

    # ── Write harness to /build tmpfs ────────────────────────────────────────
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    harness_c = BUILD_DIR / "harness.c"
    harness_bin = BUILD_DIR / "harness"

    try:
        harness_c.write_text(harness_source, encoding="utf-8")
    except OSError as exc:
        result = _error_result(f"WorkerSetupError: Cannot write harness.c: {exc}")
        _write_output(output_path, result)
        return

    # ── Compile ──────────────────────────────────────────────────────────────
    compile_cmd: list[str] = [
        "gcc",
        "-fsanitize=address",
        "-fprofile-arcs",
        "-ftest-coverage",
        "-g",
        "-O0",
        "-Wall",
        "-Wextra",
        "-o",
        str(harness_bin),
        str(harness_c),
        target_file,
    ]
    # Append caller-supplied compile flags (already validated as list[str])
    compile_cmd.extend(compile_flags)

    try:
        compile_proc = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        result = _error_result(
            f"CompilationError: gcc timed out after {COMPILE_TIMEOUT_SECONDS}s"
        )
        _write_output(output_path, result)
        return
    except Exception as exc:
        result = _error_result(f"CompilationError: gcc failed to start: {exc}")
        _write_output(output_path, result)
        return

    if compile_proc.returncode != 0:
        gcc_stderr = compile_proc.stderr[:4096]  # Truncate to avoid huge payloads
        result = _error_result(
            f"CompilationError: {gcc_stderr}",
            compile_proc.stderr,
        )
        result["returncode"] = compile_proc.returncode
        _write_output(output_path, result)
        return

    # ── Execute compiled binary ───────────────────────────────────────────────
    try:
        run_proc = subprocess.run(
            [str(harness_bin)],
            capture_output=True,
            text=True,
            timeout=execution_timeout,
            cwd=str(BUILD_DIR),
        )
        run_returncode = run_proc.returncode
        run_stdout = run_proc.stdout
        run_stderr = run_proc.stderr
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        run_returncode = -1
        run_stdout = ""
        run_stderr = "TIMEOUT"
        timed_out = True
        run_proc = None  # type: ignore[assignment]
    except Exception as exc:
        run_returncode = -1
        run_stdout = ""
        run_stderr = str(exc)
        timed_out = False
        run_proc = None  # type: ignore[assignment]

    # ── Parse exit code and crash type ───────────────────────────────────────
    exception_str: str | None = None
    traceback_str: str | None = None
    success = False

    if timed_out:
        exception_str = "TimeoutError: Execution exceeded timeout"
    elif run_returncode == 0:
        success = True
    else:
        # Check if ASan killed the process
        asan_exc, asan_tb = _parse_asan_output(run_stderr)
        if asan_exc:
            exception_str = asan_exc
            traceback_str = asan_tb
        elif run_returncode < 0:
            # Killed by a signal
            signum = -run_returncode
            sig_name = _signal_name(signum)
            exception_str = f"SignalError: {sig_name}"
            traceback_str = run_stderr if run_stderr else None
        else:
            exception_str = f"RuntimeError: exit code {run_returncode}"
            traceback_str = run_stderr if run_stderr else None

    # ── Collect gcov coverage ─────────────────────────────────────────────────
    coverage_data: dict = {}
    if collect_coverage and success and run_proc is not None:
        try:
            GCOV_OUT_DIR.mkdir(parents=True, exist_ok=True)
            gcov_cmd = [
                "gcov",
                "-o",
                str(BUILD_DIR),
                str(harness_c),
                target_file,
            ]
            subprocess.run(
                gcov_cmd,
                capture_output=True,
                text=True,
                timeout=15,
                cwd=str(GCOV_OUT_DIR),
            )
            coverage_data = _parse_gcov_output(GCOV_OUT_DIR, [target_file])
        except Exception as cov_exc:
            coverage_data = {"error": str(cov_exc)}

    # ── Write output ──────────────────────────────────────────────────────────
    result = {
        "success": success,
        "exception": exception_str,
        "traceback": traceback_str,
        "stdout": run_stdout,
        "stderr": run_stderr,
        "coverage_data": coverage_data,
        "returncode": run_returncode,
    }
    _write_output(output_path, result)


if __name__ == "__main__":
    main()
