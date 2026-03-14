"""Shared fixtures for fuzzer tests."""

from __future__ import annotations

import pytest

from deep_code_security.fuzzer.models import FuzzInput, FuzzResult, TargetInfo


@pytest.fixture
def sample_fuzz_input() -> FuzzInput:
    return FuzzInput(
        target_function="my_func",
        args=("42", "None"),
        kwargs={"key": "'hello'"},
        metadata={"rationale": "test", "source": "test"},
    )


@pytest.fixture
def sample_fuzz_result(sample_fuzz_input: FuzzInput) -> FuzzResult:
    return FuzzResult(
        input=sample_fuzz_input,
        success=True,
        exception=None,
        traceback=None,
        duration_ms=10.5,
        coverage_data={},
        stdout="",
        stderr="",
    )


@pytest.fixture
def crash_fuzz_result(sample_fuzz_input: FuzzInput) -> FuzzResult:
    return FuzzResult(
        input=sample_fuzz_input,
        success=False,
        exception="ZeroDivisionError: division by zero",
        traceback='Traceback (most recent call last):\n  File "test.py", line 10, in my_func\n    return 1/0\nZeroDivisionError: division by zero',
        duration_ms=5.0,
        coverage_data={},
        stdout="",
        stderr="",
    )


@pytest.fixture
def sample_target_info() -> TargetInfo:
    return TargetInfo(
        module_path="/tmp/test.py",
        function_name="my_func",
        qualified_name="my_func",
        signature="my_func(x: int, y: str = 'hello')",
        parameters=[
            {"name": "x", "type_hint": "int", "default": "", "kind": "POSITIONAL_OR_KEYWORD"},
            {
                "name": "y",
                "type_hint": "str",
                "default": "'hello'",
                "kind": "POSITIONAL_OR_KEYWORD",
            },
        ],
        docstring="A test function.",
        source_code="def my_func(x: int, y: str = 'hello'):\n    return x",
        decorators=[],
        complexity=1,
        is_static_method=False,
        has_side_effects=False,
    )
