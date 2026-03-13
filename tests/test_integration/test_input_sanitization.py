"""Integration tests for input sanitization."""

from __future__ import annotations

import pytest

from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath
from deep_code_security.mcp.input_validator import (
    InputValidationError,
    validate_file_path,
    validate_function_name,
    validate_raw_finding,
    validate_variable_name,
)


def make_finding(source_function: str, sink_function: str = "cursor.execute") -> RawFinding:
    """Helper to create a finding with the given function names."""
    return RawFinding(
        source=Source(
            file="/test.py", line=1, column=0,
            function=source_function, category="web_input", language="python"
        ),
        sink=Sink(
            file="/test.py", line=5, column=0,
            function=sink_function, category="sql_injection",
            cwe="CWE-89", language="python"
        ),
        taint_path=TaintPath(steps=[]),
        vulnerability_class="CWE-89: SQL Injection",
        severity="critical",
        language="python",
        raw_confidence=0.5,
    )


class TestInputSanitizationIntegration:
    """End-to-end tests for input sanitization."""

    def test_valid_finding_passes(self) -> None:
        """Valid finding passes all validations."""
        finding = make_finding("request.form")
        result = validate_raw_finding(finding)
        assert result is finding

    def test_shell_metachar_in_source_rejected(self) -> None:
        """Shell metacharacters in source function are rejected."""
        finding = make_finding("request.form; rm -rf /")
        with pytest.raises(InputValidationError):
            validate_raw_finding(finding)

    def test_pipe_in_sink_rejected(self) -> None:
        """Pipe character in sink function is rejected."""
        finding = make_finding("request.form", "cursor.execute | cat /etc/passwd")
        with pytest.raises(InputValidationError):
            validate_raw_finding(finding)

    def test_ampersand_in_function_rejected(self) -> None:
        """Ampersand in function name is rejected."""
        with pytest.raises(InputValidationError):
            validate_function_name("os.system && id")

    def test_null_byte_in_path_rejected(self) -> None:
        """Null bytes in file paths are rejected."""
        with pytest.raises(InputValidationError):
            validate_file_path("/tmp/test\x00.py")

    def test_newline_in_function_rejected(self) -> None:
        """Newlines in function names are rejected."""
        with pytest.raises(InputValidationError):
            validate_function_name("request.form\nos.system")

    def test_tab_in_function_rejected(self) -> None:
        """Tabs in function names are rejected."""
        with pytest.raises(InputValidationError):
            validate_function_name("request\tform")

    def test_dollar_sign_rejected(self) -> None:
        """Dollar signs (shell variable expansion) are rejected."""
        with pytest.raises(InputValidationError):
            validate_function_name("$HOME")

    def test_parentheses_rejected(self) -> None:
        """Parentheses in function names are rejected (except valid calls)."""
        # Valid: function.name (no parens)
        validate_function_name("os.system")
        # Invalid: shell expansion
        with pytest.raises(InputValidationError):
            validate_function_name("$(id)")

    def test_long_function_name_rejected(self) -> None:
        """Excessively long function names are rejected."""
        with pytest.raises(InputValidationError, match="too long"):
            validate_function_name("a" * 300)

    def test_long_file_path_rejected(self) -> None:
        """Excessively long file paths are rejected."""
        with pytest.raises(InputValidationError, match="too long"):
            validate_file_path("/tmp/" + "a" * 5000 + ".py")

    def test_valid_variable_names(self) -> None:
        """Valid variable names pass validation."""
        validate_variable_name("user_input")
        validate_variable_name("_private")
        validate_variable_name("CamelCase")
        validate_variable_name("x")

    def test_variable_name_with_dot_rejected(self) -> None:
        """Variable names with dots are rejected (use function_name for attribute access)."""
        with pytest.raises(InputValidationError):
            validate_variable_name("self.value")

    def test_variable_name_with_hyphen_rejected(self) -> None:
        """Variable names with hyphens are rejected."""
        with pytest.raises(InputValidationError):
            validate_variable_name("my-var")
