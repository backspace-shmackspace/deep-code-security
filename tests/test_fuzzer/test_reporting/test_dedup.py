"""Tests for crash deduplication."""

from __future__ import annotations

from deep_code_security.fuzzer.models import FuzzInput, FuzzResult
from deep_code_security.fuzzer.reporting.dedup import deduplicate_crashes


class TestDeduplicate:
    def test_single_crash(self) -> None:
        fi = FuzzInput(target_function="f", args=("1",))
        fr = FuzzResult(
            input=fi,
            success=False,
            exception="ZeroDivisionError: division by zero",
            traceback='File "t.py", line 5',
            duration_ms=1.0,
        )
        result = deduplicate_crashes([fr])
        assert len(result) == 1
        assert result[0].exception_type == "ZeroDivisionError"
        assert result[0].count == 1

    def test_duplicate_crashes(self) -> None:
        fi = FuzzInput(target_function="f", args=("1",))
        fr1 = FuzzResult(
            input=fi,
            success=False,
            exception="ValueError: bad",
            traceback='File "t.py", line 10',
            duration_ms=1.0,
        )
        fr2 = FuzzResult(
            input=FuzzInput(target_function="f", args=("2",)),
            success=False,
            exception="ValueError: also bad",
            traceback='File "t.py", line 10',
            duration_ms=1.0,
        )
        result = deduplicate_crashes([fr1, fr2])
        assert len(result) == 1
        assert result[0].count == 2

    def test_different_crashes(self) -> None:
        fi1 = FuzzInput(target_function="f", args=("1",))
        fi2 = FuzzInput(target_function="g", args=("2",))
        fr1 = FuzzResult(
            input=fi1,
            success=False,
            exception="ValueError: bad",
            traceback='File "t.py", line 10',
            duration_ms=1.0,
        )
        fr2 = FuzzResult(
            input=fi2,
            success=False,
            exception="TypeError: wrong",
            traceback='File "t.py", line 20',
            duration_ms=1.0,
        )
        result = deduplicate_crashes([fr1, fr2])
        assert len(result) == 2
