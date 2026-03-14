"""Tests for the shared expression validator (security-critical)."""

from __future__ import annotations

from deep_code_security.fuzzer.ai.expression_validator import SAFE_NAMES, validate_expression


class TestValidateExpression:
    """Tests for AST-based expression validation."""

    def test_literal_int(self) -> None:
        assert validate_expression("42") is True

    def test_literal_string(self) -> None:
        assert validate_expression("'hello'") is True

    def test_literal_none(self) -> None:
        assert validate_expression("None") is True

    def test_literal_list(self) -> None:
        assert validate_expression("[1, 2, 3]") is True

    def test_literal_dict(self) -> None:
        assert validate_expression("{'a': 1}") is True

    def test_float_nan(self) -> None:
        assert validate_expression("float('nan')") is True

    def test_float_inf(self) -> None:
        assert validate_expression("float('inf')") is True

    def test_range(self) -> None:
        assert validate_expression("range(10)") is True

    def test_bytes(self) -> None:
        assert validate_expression("bytes(5)") is True

    def test_negative_number(self) -> None:
        assert validate_expression("-1") is True

    def test_binary_op(self) -> None:
        assert validate_expression("2**31 - 1") is True

    def test_tuple(self) -> None:
        assert validate_expression("(1, 2, 3)") is True

    def test_set(self) -> None:
        assert validate_expression("{1, 2, 3}") is True

    # Rejection tests

    def test_rejects_import(self) -> None:
        assert validate_expression("__import__('os')") is False

    def test_rejects_attribute_access(self) -> None:
        assert validate_expression("().__class__") is False

    def test_rejects_subclass_attack(self) -> None:
        assert validate_expression("().__class__.__bases__[0].__subclasses__()") is False

    def test_rejects_lambda(self) -> None:
        assert validate_expression("lambda: 1") is False

    def test_rejects_exec(self) -> None:
        assert validate_expression("exec('import os')") is False

    def test_rejects_eval(self) -> None:
        assert validate_expression("eval('1+1')") is False

    def test_rejects_fstring(self) -> None:
        assert validate_expression("f'{1+1}'") is False

    def test_rejects_os_system(self) -> None:
        assert validate_expression("os.system('ls')") is False

    def test_rejects_open(self) -> None:
        assert validate_expression("open('/etc/passwd')") is False

    def test_rejects_non_string(self) -> None:
        assert validate_expression(42) is False  # type: ignore[arg-type]

    def test_rejects_syntax_error(self) -> None:
        assert validate_expression("def foo():") is False

    def test_rejects_assignment(self) -> None:
        assert validate_expression("x = 1") is False

    def test_memoryview_not_in_safe_names(self) -> None:
        """memoryview should be excluded from SAFE_NAMES per plan."""
        assert "memoryview" not in SAFE_NAMES

    def test_rejects_memoryview_call(self) -> None:
        assert validate_expression("memoryview(b'hello')") is False
