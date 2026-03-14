"""Tests for corpus serialization with expression re-validation."""

from __future__ import annotations

import pytest

from deep_code_security.fuzzer.corpus.serialization import (
    SCHEMA_VERSION,
    deserialize_fuzz_result,
    serialize_fuzz_result,
)
from deep_code_security.fuzzer.exceptions import CorpusError
from deep_code_security.fuzzer.models import FuzzInput, FuzzResult


class TestSerialization:
    def test_roundtrip(self, sample_fuzz_result: FuzzResult) -> None:
        data = serialize_fuzz_result(sample_fuzz_result)
        result = deserialize_fuzz_result(data)
        assert result.input.target_function == sample_fuzz_result.input.target_function
        assert result.success == sample_fuzz_result.success

    def test_schema_version(self, sample_fuzz_result: FuzzResult) -> None:
        data = serialize_fuzz_result(sample_fuzz_result)
        assert data["schema_version"] == SCHEMA_VERSION

    def test_stdout_truncated(self) -> None:
        fi = FuzzInput(target_function="f", args=("1",))
        fr = FuzzResult(
            input=fi,
            success=True,
            duration_ms=1.0,
            stdout="x" * 5000,
        )
        data = serialize_fuzz_result(fr)
        assert len(data["stdout"]) == 1000

    def test_args_coerced_to_tuple(self) -> None:
        data = {
            "schema_version": 1,
            "timestamp": 0,
            "input": {
                "target_function": "f",
                "args": ["1", "2"],
                "kwargs": {},
                "metadata": {},
            },
            "success": True,
            "duration_ms": 1.0,
        }
        result = deserialize_fuzz_result(data)
        assert isinstance(result.input.args, tuple)
        assert result.input.args == ("1", "2")

    def test_expression_revalidation_rejects_malicious(self) -> None:
        """Tampered corpus file with malicious expression is rejected on load."""
        data = {
            "schema_version": 1,
            "timestamp": 0,
            "input": {
                "target_function": "f",
                "args": ["__import__('os')"],
                "kwargs": {},
                "metadata": {},
            },
            "success": False,
            "duration_ms": 1.0,
        }
        with pytest.raises(CorpusError, match="expression validation"):
            deserialize_fuzz_result(data)

    def test_expression_revalidation_kwargs(self) -> None:
        data = {
            "schema_version": 1,
            "timestamp": 0,
            "input": {
                "target_function": "f",
                "args": [],
                "kwargs": {"x": "eval('bad')"},
                "metadata": {},
            },
            "success": False,
            "duration_ms": 1.0,
        }
        with pytest.raises(CorpusError, match="expression validation"):
            deserialize_fuzz_result(data)

    def test_wrong_schema_version(self) -> None:
        data = {"schema_version": 999}
        with pytest.raises(CorpusError, match="Unsupported corpus schema"):
            deserialize_fuzz_result(data)
