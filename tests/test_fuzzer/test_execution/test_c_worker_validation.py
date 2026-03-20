"""Unit tests for _c_worker.py AST validation (Layer 2, security-critical).

Tests cover:
- Valid harness acceptance
- Prohibited function call rejection
- Inline assembly rejection
- #define/#undef macro rejection
- Prohibited include rejection
- main() count validation
- Size limit rejection
- ASan output parsing
- Signal-to-exception mapping
- gcov output parsing
- ASan location formatting for dedup compatibility
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.fuzzer.execution._c_worker import (
    HarnessValidationError,
    _parse_asan_output,
    _parse_gcov_output,
    _signal_name,
    _validate_harness_source,
)


# ──────────────────────────────────────────────────────────────────────────────
# Valid harness acceptance
# ──────────────────────────────────────────────────────────────────────────────

MINIMAL_VALID_HARNESS = """\
#include <stdlib.h>
#include <string.h>
extern int process_input(const char *data, size_t len);
int main(void) {
    char buf[64];
    memset(buf, 'A', sizeof(buf));
    process_input(buf, sizeof(buf));
    return 0;
}
"""


class TestValidHarness:
    def test_minimal_valid_harness_passes(self) -> None:
        """A well-formed harness with allowed includes and no prohibited calls passes."""
        _validate_harness_source(MINIMAL_VALID_HARNESS)  # Should not raise

    def test_all_allowed_includes_pass(self) -> None:
        """All allowed headers can be included simultaneously."""
        harness = """\
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <float.h>
#include <assert.h>
extern int f(int x);
int main(void) {
    f(0);
    return 0;
}
"""
        _validate_harness_source(harness)  # Should not raise

    def test_extern_declaration_passes(self) -> None:
        """extern function declarations are allowed."""
        harness = """\
#include <stdlib.h>
extern void process(const char *s, int n);
int main(void) {
    process("test", 4);
    return 0;
}
"""
        _validate_harness_source(harness)


# ──────────────────────────────────────────────────────────────────────────────
# Size limit
# ──────────────────────────────────────────────────────────────────────────────


class TestSizeLimit:
    def test_rejects_oversized_harness(self) -> None:
        """Harness exceeding 64 KB is rejected before parsing."""
        huge_source = "// " + "A" * (65 * 1024)
        with pytest.raises(HarnessValidationError, match="size limit"):
            _validate_harness_source(huge_source)

    def test_accepts_harness_just_under_limit(self) -> None:
        """Harness just under 64 KB passes the size check."""
        # Build a harness that is valid and under the size limit
        padding = "// " + "x" * 100 + "\n"
        # We need a valid harness with padding; repeat comment lines
        body = "".join(padding for _ in range(400))  # ~40 KB of comments
        harness = body + MINIMAL_VALID_HARNESS
        assert len(harness.encode("utf-8")) < 64 * 1024
        _validate_harness_source(harness)  # Should not raise


# ──────────────────────────────────────────────────────────────────────────────
# main() count validation
# ──────────────────────────────────────────────────────────────────────────────


class TestMainCount:
    def test_rejects_no_main(self) -> None:
        """Harness with no main() is rejected."""
        harness = """\
#include <stdlib.h>
extern int f(int x);
void helper(void) {
    f(0);
}
"""
        with pytest.raises(HarnessValidationError, match="main()"):
            _validate_harness_source(harness)

    def test_rejects_two_main_functions(self) -> None:
        """Harness with two main() definitions is rejected."""
        harness = """\
#include <stdlib.h>
extern int f(int x);
int main(void) { f(1); return 0; }
int main(int argc, char **argv) { f(2); return 0; }
"""
        with pytest.raises(HarnessValidationError, match="main()"):
            _validate_harness_source(harness)


# ──────────────────────────────────────────────────────────────────────────────
# Inline assembly rejection
# ──────────────────────────────────────────────────────────────────────────────


class TestAsmRejection:
    def test_rejects_asm_statement(self) -> None:
        """asm() statements are rejected."""
        harness = """\
#include <stdlib.h>
extern int f(int x);
int main(void) {
    asm("nop");
    f(0);
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Aa]sm|assembly|asm_statement"):
            _validate_harness_source(harness)


# ──────────────────────────────────────────────────────────────────────────────
# #define / #undef rejection
# ──────────────────────────────────────────────────────────────────────────────


class TestMacroRejection:
    def test_rejects_define(self) -> None:
        """#define directives are rejected."""
        harness = """\
#include <stdlib.h>
#define BUF_SIZE 256
extern int f(const char *s);
int main(void) {
    char buf[BUF_SIZE];
    f(buf);
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]reprocessor|define|#define"):
            _validate_harness_source(harness)

    def test_rejects_undef(self) -> None:
        """#undef directives are rejected."""
        harness = """\
#include <stdlib.h>
extern int f(int x);
int main(void) {
#undef NULL
    f(0);
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]reprocessor|undef|#undef"):
            _validate_harness_source(harness)

    def test_rejects_function_macro(self) -> None:
        """Function-like #define macros are rejected."""
        harness = """\
#include <stdlib.h>
#define CALL_F(x) f(x)
extern int f(int x);
int main(void) {
    CALL_F(0);
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]reprocessor|define"):
            _validate_harness_source(harness)


# ──────────────────────────────────────────────────────────────────────────────
# Prohibited include rejection
# ──────────────────────────────────────────────────────────────────────────────


class TestIncludeRejection:
    @pytest.mark.parametrize(
        "header",
        [
            "<unistd.h>",
            "<sys/socket.h>",
            "<netinet/in.h>",
            "<sys/ptrace.h>",
            "<dlfcn.h>",
            "<signal.h>",
        ],
    )
    def test_rejects_prohibited_include(self, header: str) -> None:
        """Prohibited headers are rejected."""
        harness = f"""\
#include {header}
extern int f(int x);
int main(void) {{
    f(0);
    return 0;
}}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]rohibited|not allowed|header"):
            _validate_harness_source(harness)


# ──────────────────────────────────────────────────────────────────────────────
# Prohibited function call rejection
# ──────────────────────────────────────────────────────────────────────────────


class TestProhibitedFunctionCalls:
    @pytest.mark.parametrize(
        "func_call",
        [
            "system",
            "popen",
            "execl",
            "execve",
            "fork",
            "vfork",
            "socket",
            "connect",
            "dlopen",
            "dlsym",
            "ptrace",
        ],
    )
    def test_rejects_prohibited_function(self, func_call: str) -> None:
        """Calls to prohibited functions are rejected."""
        harness = f"""\
#include <stdlib.h>
extern int f(int x);
int main(void) {{
    {func_call}(0);
    return 0;
}}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]rohibited"):
            _validate_harness_source(harness)


# ──────────────────────────────────────────────────────────────────────────────
# ASan output parsing
# ──────────────────────────────────────────────────────────────────────────────


class TestAsanParsing:
    def test_parses_heap_buffer_overflow(self) -> None:
        asan_stderr = """\
=================================================================
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
READ of size 1 at 0x... thread T0
    #0 0x401234 in process_input /target/vulnerable.c:42
    #1 0x401345 in main /build/harness.c:10
"""
        exc, tb = _parse_asan_output(asan_stderr)
        assert exc == "AddressSanitizer: heap-buffer-overflow"
        assert tb is not None
        assert 'File "/target/vulnerable.c", line 42' in tb

    def test_parses_stack_buffer_overflow(self) -> None:
        asan_stderr = "AddressSanitizer: stack-buffer-overflow\n#0 0x1234 in foo /src/foo.c:5\n"
        exc, tb = _parse_asan_output(asan_stderr)
        assert exc == "AddressSanitizer: stack-buffer-overflow"

    def test_parses_use_after_free(self) -> None:
        asan_stderr = "ERROR: AddressSanitizer: heap-use-after-free\n"
        exc, tb = _parse_asan_output(asan_stderr)
        assert exc == "AddressSanitizer: heap-use-after-free"

    def test_parses_null_deref(self) -> None:
        asan_stderr = "AddressSanitizer: SEGV on unknown address 0x0\n"
        exc, tb = _parse_asan_output(asan_stderr)
        assert exc == "AddressSanitizer: SEGV on unknown address"

    def test_returns_none_for_non_asan_output(self) -> None:
        exc, tb = _parse_asan_output("normal program output")
        assert exc is None
        assert tb is None

    def test_formats_location_as_python_style(self) -> None:
        """ASan locations must be formatted as 'File X, line N' for dedup."""
        asan_stderr = (
            "AddressSanitizer: heap-buffer-overflow\n"
            "#0 0xdeadbeef in process_input /target/vulnerable.c:42\n"
        )
        exc, tb = _parse_asan_output(asan_stderr)
        assert tb is not None
        # Must match the dedup regex: File "path", line N
        assert 'File "/target/vulnerable.c", line 42' in tb


# ──────────────────────────────────────────────────────────────────────────────
# Signal-to-exception mapping
# ──────────────────────────────────────────────────────────────────────────────


class TestSignalMapping:
    def test_sigsegv_name(self) -> None:
        import signal
        name = _signal_name(signal.SIGSEGV)
        assert "SIGSEGV" in name
        assert "segmentation" in name.lower()

    def test_sigabrt_name(self) -> None:
        import signal
        name = _signal_name(signal.SIGABRT)
        assert "SIGABRT" in name
        assert "abort" in name.lower()

    def test_sigfpe_name(self) -> None:
        import signal
        name = _signal_name(signal.SIGFPE)
        assert "SIGFPE" in name

    def test_unknown_signal(self) -> None:
        name = _signal_name(99)
        assert "99" in name


# ──────────────────────────────────────────────────────────────────────────────
# gcov output parsing
# ──────────────────────────────────────────────────────────────────────────────


class TestGcovParsing:
    def test_parses_gcov_output(self, tmp_path: Path) -> None:
        """Parse a synthetic .gcov file into coverage data dict."""
        gcov_content = """\
        -:    0:Source:/target/foo.c
        -:    0:Graph:/build/harness.gcno
        -:    0:Data:/build/harness.gcda
        -:    0:Runs:1
        -:    1:#include <stdio.h>
        -:    2:
        1:    3:int process_input(const char *s) {
        1:    4:    if (s == 0) {
    #####:    5:        return -1;
        1:    6:    }
        1:    7:    return 0;
        -:    8:}
"""
        gcov_file = tmp_path / "harness.c.gcov"
        gcov_file.write_text(gcov_content)

        result = _parse_gcov_output(tmp_path, ["/target/foo.c"])
        assert "files" in result
        assert "totals" in result
        assert "/target/foo.c" in result["files"]
        file_data = result["files"]["/target/foo.c"]
        assert 3 in file_data["executed_lines"]
        assert 5 in file_data["missing_lines"]
        assert result["totals"]["covered_lines"] > 0

    def test_empty_gcov_dir_returns_empty(self, tmp_path: Path) -> None:
        """Empty gcov directory returns empty coverage data."""
        result = _parse_gcov_output(tmp_path, [])
        assert result["files"] == {}
        assert result["totals"]["covered_lines"] == 0

    def test_percent_calculation(self, tmp_path: Path) -> None:
        """Coverage percentage is computed correctly."""
        gcov_content = """\
        -:    0:Source:/target/calc.c
        1:    1:int f(void) {
        1:    2:    return 1;
    #####:    3:    return 0;
        -:    4:}
"""
        gcov_file = tmp_path / "calc.c.gcov"
        gcov_file.write_text(gcov_content)

        result = _parse_gcov_output(tmp_path, ["/target/calc.c"])
        totals = result["totals"]
        assert totals["covered_lines"] == 2
        assert totals["num_statements"] == 3
        assert abs(totals["percent_covered"] - 66.67) < 0.1


# ──────────────────────────────────────────────────────────────────────────────
# Worker main() integration (mocked subprocess calls)
# ──────────────────────────────────────────────────────────────────────────────


class TestWorkerMain:
    def _run_worker_with_input(self, tmp_path: Path, params: dict) -> dict:
        """Helper: write input.json, run main(), read output.json."""
        input_json = tmp_path / "input.json"
        output_json = tmp_path / "output.json"
        input_json.write_text(json.dumps(params))

        import sys
        original_argv = sys.argv[:]
        try:
            sys.argv = [
                "deep_code_security.fuzzer.execution._c_worker",
                str(input_json),
                str(output_json),
            ]
            from deep_code_security.fuzzer.execution._c_worker import main
            main()
        finally:
            sys.argv = original_argv

        assert output_json.exists(), "output.json was not written"
        with open(output_json) as f:
            return json.load(f)

    def test_empty_harness_source_returns_error(self, tmp_path: Path) -> None:
        """Empty harness_source produces a WorkerSetupError."""
        params = {
            "harness_source": "",
            "target_file": "/target/foo.c",
            "compile_flags": [],
            "collect_coverage": False,
            "timeout_ms": 1000,
        }
        result = self._run_worker_with_input(tmp_path, params)
        assert result["success"] is False
        assert "harness_source" in result["exception"]

    def test_empty_target_file_returns_error(self, tmp_path: Path) -> None:
        """Empty target_file produces a WorkerSetupError."""
        params = {
            "harness_source": MINIMAL_VALID_HARNESS,
            "target_file": "",
            "compile_flags": [],
            "collect_coverage": False,
            "timeout_ms": 1000,
        }
        result = self._run_worker_with_input(tmp_path, params)
        assert result["success"] is False
        assert "target_file" in result["exception"]

    def test_invalid_harness_returns_validation_error(self, tmp_path: Path) -> None:
        """Harness with system() call returns HarnessValidationError."""
        bad_harness = """\
#include <stdlib.h>
extern int f(int x);
int main(void) {
    system("cat /etc/passwd");
    return 0;
}
"""
        params = {
            "harness_source": bad_harness,
            "target_file": "/target/foo.c",
            "compile_flags": [],
            "collect_coverage": False,
            "timeout_ms": 1000,
        }
        result = self._run_worker_with_input(tmp_path, params)
        assert result["success"] is False
        assert "HarnessValidationError" in result["exception"]

    def test_compilation_failure_returns_compilation_error(self, tmp_path: Path) -> None:
        """When gcc exits non-zero, result has CompilationError."""
        params = {
            "harness_source": MINIMAL_VALID_HARNESS,
            "target_file": "/target/foo.c",
            "compile_flags": [],
            "collect_coverage": False,
            "timeout_ms": 1000,
        }
        input_json = tmp_path / "input.json"
        output_json = tmp_path / "output.json"
        input_json.write_text(json.dumps(params))

        def fake_gcc(*args, **kwargs):
            m = MagicMock()
            m.returncode = 1
            m.stdout = ""
            m.stderr = "harness.c:5:3: error: implicit declaration of function 'foo'"
            return m

        # Patch BUILD_DIR to use a writable temp path (macOS /build doesn't exist)
        fake_build_dir = tmp_path / "build"
        fake_build_dir.mkdir()

        import sys
        import deep_code_security.fuzzer.execution._c_worker as cw_module
        original_argv = sys.argv[:]
        original_build_dir = cw_module.BUILD_DIR
        try:
            sys.argv = ["_c_worker", str(input_json), str(output_json)]
            cw_module.BUILD_DIR = fake_build_dir
            with patch("subprocess.run", side_effect=fake_gcc):
                from deep_code_security.fuzzer.execution._c_worker import main
                main()
        finally:
            sys.argv = original_argv
            cw_module.BUILD_DIR = original_build_dir

        with open(output_json) as f:
            result = json.load(f)

        assert result["success"] is False
        assert "CompilationError" in result["exception"]

    def test_compile_timeout_returns_compilation_error(self, tmp_path: Path) -> None:
        """gcc timeout produces CompilationError."""
        import subprocess

        params = {
            "harness_source": MINIMAL_VALID_HARNESS,
            "target_file": "/target/foo.c",
            "compile_flags": [],
            "collect_coverage": False,
            "timeout_ms": 1000,
        }
        input_json = tmp_path / "input.json"
        output_json = tmp_path / "output.json"
        input_json.write_text(json.dumps(params))

        def fake_timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="gcc", timeout=30)

        # Patch BUILD_DIR to use a writable temp path (macOS /build doesn't exist)
        fake_build_dir = tmp_path / "build"
        fake_build_dir.mkdir()

        import sys
        import deep_code_security.fuzzer.execution._c_worker as cw_module
        original_argv = sys.argv[:]
        original_build_dir = cw_module.BUILD_DIR
        try:
            sys.argv = ["_c_worker", str(input_json), str(output_json)]
            cw_module.BUILD_DIR = fake_build_dir
            with patch("subprocess.run", side_effect=fake_timeout):
                from deep_code_security.fuzzer.execution._c_worker import main
                main()
        finally:
            sys.argv = original_argv
            cw_module.BUILD_DIR = original_build_dir

        with open(output_json) as f:
            result = json.load(f)

        assert result["success"] is False
        assert "CompilationError" in result["exception"]
        assert "timed out" in result["exception"]
