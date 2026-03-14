"""Tests for _worker.py AST validation before eval() (security-critical)."""

from __future__ import annotations

import pytest

from deep_code_security.fuzzer.execution._worker import eval_expression


class TestWorkerValidation:
    def test_valid_literal(self) -> None:
        assert eval_expression("42") == 42

    def test_valid_float_nan(self) -> None:
        import math

        result = eval_expression("float('nan')")
        assert math.isnan(result)

    def test_valid_float_inf(self) -> None:
        assert eval_expression("float('inf')") == float("inf")

    def test_valid_list(self) -> None:
        assert eval_expression("[1, 2, 3]") == [1, 2, 3]

    def test_valid_none(self) -> None:
        assert eval_expression("None") is None

    def test_valid_range(self) -> None:
        result = eval_expression("range(5)")
        assert list(result) == [0, 1, 2, 3, 4]

    def test_rejects_subclass_attack(self) -> None:
        with pytest.raises(ValueError, match="AST validation"):
            eval_expression("().__class__.__bases__[0].__subclasses__()")

    def test_rejects_import_expression(self) -> None:
        with pytest.raises(ValueError, match="AST validation"):
            eval_expression("__import__('os')")

    def test_rejects_attribute_access(self) -> None:
        with pytest.raises(ValueError, match="AST validation"):
            eval_expression("''.__class__")

    def test_rejects_eval_call(self) -> None:
        with pytest.raises(ValueError, match="AST validation"):
            eval_expression("eval('1+1')")

    def test_rejects_exec_call(self) -> None:
        with pytest.raises(ValueError, match="AST validation"):
            eval_expression("exec('import os')")

    def test_rejects_open_call(self) -> None:
        with pytest.raises(ValueError, match="AST validation"):
            eval_expression("open('/etc/passwd')")

    def test_rejects_memoryview(self) -> None:
        with pytest.raises(ValueError, match="AST validation"):
            eval_expression("memoryview(b'hello')")
