"""Additional tests for input_validator.py to increase coverage."""

from __future__ import annotations

import pytest

from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath, TaintStep
from deep_code_security.mcp.input_validator import (
    InputValidationError,
    validate_file_path,
    validate_function_name,
    validate_raw_finding,
    validate_variable_name,
)


class TestValidateFunctionName:
    """Edge-case tests for validate_function_name."""

    def test_empty_string_raises(self) -> None:
        with pytest.raises(InputValidationError, match="empty"):
            validate_function_name("")

    def test_too_long_raises(self) -> None:
        name = "a" * 257
        with pytest.raises(InputValidationError, match="too long"):
            validate_function_name(name)

    def test_valid_dotted_name(self) -> None:
        assert validate_function_name("request.form.get") == "request.form.get"

    def test_valid_underscore_name(self) -> None:
        assert validate_function_name("_private_func") == "_private_func"

    def test_starts_with_digit_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            validate_function_name("1bad_name")

    def test_dollar_sign_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            validate_function_name("func$name")

    def test_newline_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            validate_function_name("func\nname")

    def test_max_length_accepted(self) -> None:
        name = "a" * 256
        assert validate_function_name(name) == name


class TestValidateVariableName:
    """Edge-case tests for validate_variable_name."""

    def test_empty_raises(self) -> None:
        with pytest.raises(InputValidationError, match="empty"):
            validate_variable_name("")

    def test_too_long_raises(self) -> None:
        name = "x" * 129
        with pytest.raises(InputValidationError, match="too long"):
            validate_variable_name(name)

    def test_dot_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            validate_variable_name("my.var")

    def test_valid_underscore(self) -> None:
        assert validate_variable_name("my_var_123") == "my_var_123"

    def test_hyphen_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            validate_variable_name("my-var")


class TestValidateFilePath:
    """Edge-case tests for validate_file_path."""

    def test_empty_raises(self) -> None:
        with pytest.raises(InputValidationError, match="empty"):
            validate_file_path("")

    def test_too_long_raises(self) -> None:
        path = "/" + "a" * 4096
        with pytest.raises(InputValidationError, match="too long"):
            validate_file_path(path)

    def test_null_byte_raises(self) -> None:
        with pytest.raises(InputValidationError, match="Null byte"):
            validate_file_path("/tmp/test\x00.py")

    def test_space_raises(self) -> None:
        with pytest.raises(InputValidationError):
            validate_file_path("/tmp/my file.py")

    def test_valid_path_with_dots(self) -> None:
        assert validate_file_path("/tmp/test.py") == "/tmp/test.py"

    def test_valid_path_with_hyphens(self) -> None:
        assert validate_file_path("/home/user/my-project/main.py") == "/home/user/my-project/main.py"

    def test_special_char_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            validate_file_path("/tmp/test;rm.py")


class TestValidateRawFindingEdgeCases:
    """Tests for validate_raw_finding coverage of all branches."""

    def _make_finding(self, **overrides) -> RawFinding:
        defaults = dict(
            source=Source(
                file="/tmp/test.py", line=1, column=0,
                function="request.form", category="web_input", language="python"
            ),
            sink=Sink(
                file="/tmp/test.py", line=5, column=0,
                function="cursor.execute", category="sql_injection",
                cwe="CWE-89", language="python"
            ),
            taint_path=TaintPath(steps=[]),
            vulnerability_class="CWE-89: SQL Injection",
            severity="critical",
            language="python",
            raw_confidence=0.5,
        )
        defaults.update(overrides)
        return RawFinding(**defaults)

    def test_invalid_language_raises(self) -> None:
        finding = self._make_finding(language="PYTHON")
        with pytest.raises(InputValidationError, match="language"):
            validate_raw_finding(finding)

    def test_invalid_severity_raises(self) -> None:
        # Pydantic validates severity as a Literal before we can call validate_raw_finding,
        # so we test the validator directly with a mock that bypasses Pydantic
        from unittest.mock import MagicMock
        finding = self._make_finding()
        bad = MagicMock(spec=finding)
        bad.source = finding.source
        bad.sink = finding.sink
        bad.taint_path = finding.taint_path
        bad.language = finding.language
        bad.severity = "extreme"
        bad.vulnerability_class = finding.vulnerability_class
        with pytest.raises(InputValidationError, match="severity"):
            validate_raw_finding(bad)

    def test_invalid_vulnerability_class_raises(self) -> None:
        finding = self._make_finding(vulnerability_class="SQLi")
        with pytest.raises(InputValidationError, match="vulnerability_class"):
            validate_raw_finding(finding)

    def test_invalid_cwe_in_sink_raises(self) -> None:
        finding = self._make_finding(
            sink=Sink(
                file="/tmp/test.py", line=5, column=0,
                function="cursor.execute", category="sql_injection",
                cwe="BAD-89", language="python"
            )
        )
        with pytest.raises(InputValidationError, match="CWE"):
            validate_raw_finding(finding)

    def test_invalid_sink_language_raises(self) -> None:
        finding = self._make_finding(
            sink=Sink(
                file="/tmp/test.py", line=5, column=0,
                function="cursor.execute", category="sql_injection",
                cwe="CWE-89", language="Python3"
            )
        )
        with pytest.raises(InputValidationError, match="language"):
            validate_raw_finding(finding)

    def test_invalid_source_language_raises(self) -> None:
        finding = self._make_finding(
            source=Source(
                file="/tmp/test.py", line=1, column=0,
                function="request.form", category="web_input", language="Python3"
            )
        )
        with pytest.raises(InputValidationError, match="language"):
            validate_raw_finding(finding)

    def test_taint_step_long_variable_raises(self) -> None:
        long_var = "x" * 129
        finding = self._make_finding(
            taint_path=TaintPath(steps=[
                TaintStep(file="/tmp/test.py", line=1, column=0,
                          variable=long_var, transform="source")
            ])
        )
        with pytest.raises(InputValidationError, match="too long"):
            validate_raw_finding(finding)

    def test_valid_finding_all_severities(self) -> None:
        for sev in ("critical", "high", "medium", "low"):
            finding = self._make_finding(severity=sev)
            result = validate_raw_finding(finding)
            assert result is finding

    def test_taint_step_empty_variable_passes(self) -> None:
        """Taint steps with empty-string variable pass the length check (no regex)."""
        finding = self._make_finding(
            taint_path=TaintPath(steps=[
                TaintStep(file="/tmp/test.py", line=1, column=0,
                          variable="", transform="source")
            ])
        )
        result = validate_raw_finding(finding)
        assert result is finding
