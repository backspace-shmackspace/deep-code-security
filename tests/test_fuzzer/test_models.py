"""Tests for Pydantic model conversions."""

from __future__ import annotations

from deep_code_security.fuzzer.models import (
    CoverageReport,
    FuzzInput,
    FuzzReport,
    FuzzResult,
    TargetInfo,
    UniqueCrash,
)


class TestFuzzInput:
    def test_roundtrip(self) -> None:
        fi = FuzzInput(
            target_function="my_func",
            args=("42", "None"),
            kwargs={"key": "'hello'"},
            metadata={"rationale": "test"},
        )
        data = fi.model_dump()
        fi2 = FuzzInput.model_validate(data)
        assert fi2.target_function == "my_func"
        assert fi2.args == ("42", "None")
        assert fi2.kwargs == {"key": "'hello'"}

    def test_args_list_to_tuple(self) -> None:
        """model_validate with list args should coerce to tuple."""
        fi = FuzzInput.model_validate(
            {
                "target_function": "f",
                "args": ["a", "b"],
                "kwargs": {},
            }
        )
        assert isinstance(fi.args, tuple)
        assert fi.args == ("a", "b")

    def test_not_frozen(self) -> None:
        """FuzzInput allows attribute reassignment."""
        fi = FuzzInput(target_function="f", args=("1",))
        fi.target_function = "g"
        assert fi.target_function == "g"

    def test_default_factory(self) -> None:
        fi = FuzzInput(target_function="f")
        assert fi.args == ()
        assert fi.kwargs == {}
        assert fi.metadata == {}


class TestFuzzResult:
    def test_roundtrip(self, sample_fuzz_input: FuzzInput) -> None:
        fr = FuzzResult(
            input=sample_fuzz_input,
            success=True,
            duration_ms=10.0,
        )
        data = fr.model_dump()
        fr2 = FuzzResult.model_validate(data)
        assert fr2.success is True
        assert fr2.input.target_function == "my_func"

    def test_defaults(self, sample_fuzz_input: FuzzInput) -> None:
        fr = FuzzResult(input=sample_fuzz_input, success=True)
        assert fr.exception is None
        assert fr.traceback is None
        assert fr.coverage_data == {}
        assert fr.stdout == ""
        assert fr.stderr == ""
        assert fr.timed_out is False


class TestFuzzReport:
    def test_unique_crashes_property(self, crash_fuzz_result: FuzzResult) -> None:
        report = FuzzReport(
            crashes=[crash_fuzz_result, crash_fuzz_result],
            total_iterations=1,
        )
        unique = report.unique_crashes
        assert len(unique) == 1
        assert unique[0].count == 2

    def test_computed_properties(
        self, sample_fuzz_result: FuzzResult, crash_fuzz_result: FuzzResult
    ) -> None:
        report = FuzzReport(
            all_results=[sample_fuzz_result, crash_fuzz_result],
            crashes=[crash_fuzz_result],
            total_iterations=1,
        )
        assert report.total_inputs == 2
        assert report.crash_count == 1
        assert report.success_count == 1
        assert report.timeout_count == 0


class TestTargetInfo:
    def test_roundtrip(self, sample_target_info: TargetInfo) -> None:
        data = sample_target_info.model_dump()
        ti = TargetInfo.model_validate(data)
        assert ti.qualified_name == "my_func"


class TestUniqueCrash:
    def test_pydantic(self, crash_fuzz_result: FuzzResult) -> None:
        uc = UniqueCrash(
            signature="ZeroDivisionError|test.py:10",
            exception_type="ZeroDivisionError",
            exception_message="division by zero",
            location='File "test.py", line 10',
            representative=crash_fuzz_result,
            count=3,
            target_functions=["my_func"],
        )
        assert uc.count == 3
        data = uc.model_dump()
        uc2 = UniqueCrash.model_validate(data)
        assert uc2.exception_type == "ZeroDivisionError"


class TestCoverageReport:
    def test_defaults(self) -> None:
        cr = CoverageReport()
        assert cr.total_lines == 0
        assert cr.coverage_percent == 0.0
