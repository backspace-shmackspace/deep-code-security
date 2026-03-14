"""Tests for replay runner with expression re-validation."""

from __future__ import annotations

import pytest

from deep_code_security.fuzzer.exceptions import CorpusError
from deep_code_security.fuzzer.models import FuzzInput, FuzzResult
from deep_code_security.fuzzer.replay.runner import _validate_fuzz_input_expressions


class TestReplayExpressionValidation:
    def test_valid_expressions(self) -> None:
        result = FuzzResult(
            input=FuzzInput(
                target_function="f",
                args=("42", "'hello'", "None"),
                kwargs={"x": "float('inf')"},
            ),
            success=False,
            exception="ZeroDivisionError",
            duration_ms=1.0,
        )
        _validate_fuzz_input_expressions(result)  # Should not raise

    def test_rejects_malicious_arg(self) -> None:
        result = FuzzResult(
            input=FuzzInput(
                target_function="f",
                args=("__import__('os')",),
            ),
            success=False,
            exception="ValueError",
            duration_ms=1.0,
        )
        with pytest.raises(CorpusError, match="expression validation"):
            _validate_fuzz_input_expressions(result)

    def test_rejects_malicious_kwarg(self) -> None:
        result = FuzzResult(
            input=FuzzInput(
                target_function="f",
                kwargs={"x": "eval('bad')"},
            ),
            success=False,
            exception="ValueError",
            duration_ms=1.0,
        )
        with pytest.raises(CorpusError, match="expression validation"):
            _validate_fuzz_input_expressions(result)
