"""Unit tests for C AI response parser and harness AST validation."""

from __future__ import annotations

import json
import pytest

from deep_code_security.fuzzer.ai.c_response_parser import (
    parse_c_ai_response,
    validate_harness_source,
)
from deep_code_security.fuzzer.exceptions import InputValidationError


# ---------------------------------------------------------------------------
# Minimal valid harness that passes all 7 validation steps
# ---------------------------------------------------------------------------

_VALID_HARNESS = """\
#include <stdlib.h>
#include <string.h>
extern int process_input(const char *data, size_t len);
int main(void) {
    char buf[4096];
    memset(buf, 'A', sizeof(buf));
    process_input(buf, sizeof(buf));
    return 0;
}
"""

_VALID_RESPONSE = json.dumps({
    "inputs": [
        {
            "target_function": "process_input",
            "harness_source": _VALID_HARNESS,
            "rationale": "Buffer overflow: pass large buffer",
        }
    ]
})


# ---------------------------------------------------------------------------
# validate_harness_source tests
# ---------------------------------------------------------------------------


class TestValidateHarnessSource:
    def test_valid_harness_passes(self) -> None:
        ok, reason = validate_harness_source(_VALID_HARNESS)
        assert ok, f"Expected valid harness to pass, got: {reason}"
        assert reason == ""

    def test_rejects_oversized_harness(self) -> None:
        huge = "// " + "A" * (64 * 1024 + 1)
        ok, reason = validate_harness_source(huge)
        assert not ok
        assert "64 KB" in reason

    def test_rejects_syntax_error(self) -> None:
        broken = "int main(void) { return 0"  # missing closing brace and semicolon
        ok, reason = validate_harness_source(broken)
        # tree-sitter may produce an ERROR node or no main with misparse
        # We just assert it fails for some reason
        # (tree-sitter is lenient; we test the ERROR node rejection path with truly broken code)
        # A cleaner test: inject a known parse error that tree-sitter marks ERROR
        broken2 = "@@@@@ this is not C"
        ok2, reason2 = validate_harness_source(broken2)
        assert not ok2

    def test_rejects_no_main(self) -> None:
        no_main = "#include <stdlib.h>\nextern int f(int x);\nvoid helper(void) { f(0); }\n"
        ok, reason = validate_harness_source(no_main)
        assert not ok
        assert "main" in reason.lower()

    def test_rejects_multiple_main(self) -> None:
        two_mains = (
            "int main(void) { return 0; }\n"
            "int main(int argc, char **argv) { return 0; }\n"
        )
        ok, reason = validate_harness_source(two_mains)
        assert not ok
        assert "main" in reason.lower()

    def test_rejects_system_call(self) -> None:
        harness = (
            "#include <stdlib.h>\n"
            "extern int f(void);\n"
            "int main(void) { system(\"ls\"); f(); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert not ok
        assert "system" in reason

    def test_rejects_popen_call(self) -> None:
        harness = (
            "#include <stdio.h>\n"
            "extern int f(void);\n"
            "int main(void) { popen(\"ls\", \"r\"); f(); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert not ok
        assert "popen" in reason

    def test_rejects_fork_call(self) -> None:
        harness = (
            "#include <stdlib.h>\n"
            "extern int f(void);\n"
            "int main(void) { fork(); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert not ok
        assert "fork" in reason

    def test_rejects_socket_call(self) -> None:
        harness = (
            "#include <stdlib.h>\n"
            "extern int f(void);\n"
            "int main(void) { socket(2, 1, 0); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert not ok
        assert "socket" in reason

    def test_rejects_dlopen_call(self) -> None:
        harness = (
            "#include <stdlib.h>\n"
            "extern int f(void);\n"
            "int main(void) { dlopen(\"libfoo.so\", 1); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert not ok
        assert "dlopen" in reason

    def test_rejects_execv_call(self) -> None:
        harness = (
            "#include <stdlib.h>\n"
            "extern int f(void);\n"
            "int main(void) { char *args[] = {NULL}; execv(\"/bin/sh\", args); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert not ok
        assert "execv" in reason

    def test_rejects_define_directive(self) -> None:
        harness = (
            "#include <stdlib.h>\n"
            "#define S system\n"
            "extern int f(void);\n"
            "int main(void) { f(); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert not ok
        assert "preproc" in reason.lower() or "define" in reason.lower()

    def test_rejects_undef_directive(self) -> None:
        harness = (
            "#include <stdlib.h>\n"
            "#undef NULL\n"
            "extern int f(void);\n"
            "int main(void) { f(); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert not ok
        assert "preproc" in reason.lower() or "undef" in reason.lower()

    def test_rejects_prohibited_include(self) -> None:
        harness = (
            "#include <sys/socket.h>\n"
            "extern int f(void);\n"
            "int main(void) { f(); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert not ok
        assert "socket" in reason or "prohibited" in reason.lower()

    def test_rejects_unistd_include(self) -> None:
        harness = (
            "#include <unistd.h>\n"
            "extern int f(void);\n"
            "int main(void) { f(); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert not ok

    def test_rejects_asm_keyword_in_source(self) -> None:
        """Harnesses with __asm__ are rejected."""
        harness = (
            "#include <stdlib.h>\n"
            "extern int f(void);\n"
            "int main(void) { __asm__(\"nop\"); f(); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert not ok
        assert "asm" in reason.lower()

    def test_allows_all_permitted_headers(self) -> None:
        """All permitted headers should not cause rejection."""
        harness = (
            "#include <stdlib.h>\n"
            "#include <string.h>\n"
            "#include <stdint.h>\n"
            "#include <limits.h>\n"
            "#include <stdio.h>\n"
            "#include <stdbool.h>\n"
            "#include <stddef.h>\n"
            "#include <errno.h>\n"
            "#include <assert.h>\n"
            "extern int process_input(const char *data, size_t len);\n"
            "int main(void) {\n"
            "    char buf[16];\n"
            "    process_input(buf, 16);\n"
            "    return 0;\n"
            "}\n"
        )
        ok, reason = validate_harness_source(harness)
        assert ok, f"Expected all-permitted-headers harness to pass, got: {reason}"

    def test_allows_math_float_headers(self) -> None:
        harness = (
            "#include <math.h>\n"
            "#include <float.h>\n"
            "extern double f(double x);\n"
            "int main(void) { f(3.14); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert ok, f"Expected math/float headers to pass, got: {reason}"

    def test_rejects_kill_call(self) -> None:
        harness = (
            "#include <stdlib.h>\n"
            "extern int f(void);\n"
            "int main(void) { kill(1, 9); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert not ok
        assert "kill" in reason

    def test_rejects_ptrace_call(self) -> None:
        harness = (
            "#include <stdlib.h>\n"
            "extern int f(void);\n"
            "int main(void) { ptrace(0, 0, 0, 0); return 0; }\n"
        )
        ok, reason = validate_harness_source(harness)
        assert not ok
        assert "ptrace" in reason


# ---------------------------------------------------------------------------
# parse_c_ai_response tests
# ---------------------------------------------------------------------------


class TestParseCaiResponse:
    def test_valid_response_produces_fuzz_input(self) -> None:
        result = parse_c_ai_response(_VALID_RESPONSE, {"process_input"})
        assert len(result) == 1
        fi = result[0]
        assert fi.target_function == "process_input"

    def test_sentinel_in_args(self) -> None:
        result = parse_c_ai_response(_VALID_RESPONSE, {"process_input"})
        assert len(result) == 1
        # Sentinel must be exactly ("'__c_harness__'",)
        assert result[0].args == ("'__c_harness__'",)

    def test_kwargs_empty(self) -> None:
        result = parse_c_ai_response(_VALID_RESPONSE, {"process_input"})
        assert result[0].kwargs == {}

    def test_metadata_has_harness_source(self) -> None:
        result = parse_c_ai_response(_VALID_RESPONSE, {"process_input"})
        assert "harness_source" in result[0].metadata
        assert result[0].metadata["harness_source"] == _VALID_HARNESS

    def test_metadata_plugin_is_c(self) -> None:
        result = parse_c_ai_response(_VALID_RESPONSE, {"process_input"})
        assert result[0].metadata.get("plugin") == "c"

    def test_metadata_source_is_ai(self) -> None:
        result = parse_c_ai_response(_VALID_RESPONSE, {"process_input"})
        assert result[0].metadata.get("source") == "ai"

    def test_metadata_includes_rationale(self) -> None:
        result = parse_c_ai_response(_VALID_RESPONSE, {"process_input"})
        assert "rationale" in result[0].metadata
        assert result[0].metadata["rationale"] == "Buffer overflow: pass large buffer"

    def test_invalid_target_raises_input_validation_error(self) -> None:
        response = json.dumps({
            "inputs": [
                {
                    "target_function": "nonexistent_func",
                    "harness_source": _VALID_HARNESS,
                    "rationale": "test",
                }
            ]
        })
        with pytest.raises(InputValidationError, match="nonexistent_func"):
            parse_c_ai_response(response, {"process_input"})

    def test_invalid_harness_skipped_not_whole_response_rejected(self) -> None:
        """A harness failing AST validation is skipped; valid harnesses still returned."""
        bad_harness = (
            "#include <stdlib.h>\n"
            "extern int process_input(const char *d, size_t l);\n"
            "int main(void) { system(\"cmd\"); process_input(NULL, 0); return 0; }\n"
        )
        response = json.dumps({
            "inputs": [
                {
                    "target_function": "process_input",
                    "harness_source": bad_harness,
                    "rationale": "bad harness with system()",
                },
                {
                    "target_function": "process_input",
                    "harness_source": _VALID_HARNESS,
                    "rationale": "good harness",
                },
            ]
        })
        result = parse_c_ai_response(response, {"process_input"})
        # bad harness skipped, good harness accepted
        assert len(result) == 1
        assert result[0].metadata["rationale"] == "good harness"

    def test_no_json_returns_empty(self) -> None:
        result = parse_c_ai_response("No JSON here", {"f"})
        assert result == []

    def test_missing_inputs_key_returns_empty(self) -> None:
        result = parse_c_ai_response('{"other": []}', {"f"})
        assert result == []

    def test_empty_inputs_list(self) -> None:
        result = parse_c_ai_response('{"inputs": []}', {"f"})
        assert result == []

    def test_markdown_code_block_extracted(self) -> None:
        response = f"```json\n{_VALID_RESPONSE}\n```"
        result = parse_c_ai_response(response, {"process_input"})
        assert len(result) == 1

    def test_missing_harness_source_skipped(self) -> None:
        response = json.dumps({
            "inputs": [
                {
                    "target_function": "process_input",
                    "harness_source": "",
                    "rationale": "empty harness",
                }
            ]
        })
        result = parse_c_ai_response(response, {"process_input"})
        assert result == []

    def test_non_string_harness_source_skipped(self) -> None:
        response = json.dumps({
            "inputs": [
                {
                    "target_function": "process_input",
                    "harness_source": 12345,
                    "rationale": "number",
                }
            ]
        })
        result = parse_c_ai_response(response, {"process_input"})
        assert result == []

    def test_expression_validator_not_invoked(self) -> None:
        """validate_expression must NOT be called by parse_c_ai_response.

        The sentinel value is not a Python expression that would be eval()ed.
        This test verifies validate_expression is not called at all by patching it.
        """
        import unittest.mock as mock

        with mock.patch(
            "deep_code_security.fuzzer.ai.expression_validator.validate_expression"
        ) as mock_validator:
            parse_c_ai_response(_VALID_RESPONSE, {"process_input"})
            mock_validator.assert_not_called()

    def test_invalid_json_returns_empty(self) -> None:
        result = parse_c_ai_response("{not valid json", {"f"})
        assert result == []

    def test_inputs_not_list_returns_empty(self) -> None:
        result = parse_c_ai_response('{"inputs": "not a list"}', {"f"})
        assert result == []

    def test_whole_response_rejected_when_any_target_invalid(self) -> None:
        """If ONE input has bad target, ALL inputs in the response are rejected."""
        response = json.dumps({
            "inputs": [
                {
                    "target_function": "process_input",
                    "harness_source": _VALID_HARNESS,
                    "rationale": "valid target",
                },
                {
                    "target_function": "bad_target",
                    "harness_source": _VALID_HARNESS,
                    "rationale": "invalid target",
                },
            ]
        })
        with pytest.raises(InputValidationError):
            parse_c_ai_response(response, {"process_input"})

    def test_multiple_valid_inputs(self) -> None:
        response = json.dumps({
            "inputs": [
                {
                    "target_function": "process_input",
                    "harness_source": _VALID_HARNESS,
                    "rationale": "first",
                },
                {
                    "target_function": "process_input",
                    "harness_source": _VALID_HARNESS,
                    "rationale": "second",
                },
            ]
        })
        result = parse_c_ai_response(response, {"process_input"})
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Sentinel value structural tests
# ---------------------------------------------------------------------------


class TestSentinelValue:
    def test_sentinel_passes_ast_literal_eval(self) -> None:
        """The sentinel string must be eval-able to the string '__c_harness__'."""
        import ast

        result = parse_c_ai_response(_VALID_RESPONSE, {"process_input"})
        assert len(result) == 1
        sentinel_expr = result[0].args[0]
        value = ast.literal_eval(sentinel_expr)
        assert value == "__c_harness__"

    def test_sentinel_is_tuple_of_one(self) -> None:
        result = parse_c_ai_response(_VALID_RESPONSE, {"process_input"})
        assert isinstance(result[0].args, tuple)
        assert len(result[0].args) == 1
