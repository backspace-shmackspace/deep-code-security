"""Tests for SAST-fuzz correlation logic in BridgeOrchestrator."""

from __future__ import annotations

from deep_code_security.bridge.models import BridgeResult, CorrelationReport, FuzzTarget, SASTContext
from deep_code_security.bridge.orchestrator import BridgeOrchestrator
from deep_code_security.fuzzer.models import FuzzInput, FuzzReport, FuzzResult, UniqueCrash


def _make_crash(target_function: str, exception: str = "ValueError: bad") -> FuzzResult:
    fi = FuzzInput(target_function=target_function, args=("'x'",))
    return FuzzResult(
        input=fi,
        success=False,
        exception=exception,
        traceback=f'Traceback (most recent call last):\n  File "test.py", line 3, in {target_function}\n{exception}',
    )


def _make_ok(target_function: str) -> FuzzResult:
    fi = FuzzInput(target_function=target_function, args=("'ok'",))
    return FuzzResult(input=fi, success=True)


def _make_target(function_name: str, finding_ids: list[str]) -> FuzzTarget:
    return FuzzTarget(
        file_path="/tmp/app.py",
        function_name=function_name,
        sast_context=SASTContext(
            cwe_ids=["CWE-78"],
            vulnerability_classes=["CWE-78: OS Command Injection"],
            sink_functions=["os.system"],
            source_categories=["web_input"],
            severity="high",
            finding_count=len(finding_ids),
        ),
        finding_ids=finding_ids,
        requires_instance=False,
        parameter_count=1,
    )


def test_correlation_report_type() -> None:
    """correlate() returns a CorrelationReport instance."""
    orc = BridgeOrchestrator()
    bridge_result = BridgeResult(fuzz_targets=[], total_findings=0)
    fuzz_report = FuzzReport(targets=[], all_results=[], crashes=[], total_iterations=0)
    result = orc.correlate(bridge_result, fuzz_report)
    assert isinstance(result, CorrelationReport)


def test_correlation_crash_in_scope(
) -> None:
    """Crash in same function as SAST finding sets crash_in_finding_scope=True."""
    orc = BridgeOrchestrator()
    target = _make_target("vuln_func", ["f-1"])
    bridge_result = BridgeResult(fuzz_targets=[target], total_findings=1)

    crash = _make_crash("vuln_func")
    fuzz_report = FuzzReport(
        targets=[],
        all_results=[crash],
        crashes=[crash],
        total_iterations=1,
    )
    report = orc.correlate(bridge_result, fuzz_report)
    assert len(report.entries) == 1
    assert report.entries[0].crash_in_finding_scope is True
    assert report.entries[0].crash_count == 1
    assert report.crash_in_scope_count == 1


def test_correlation_no_crash_in_scope() -> None:
    """No crashes in the SAST function: crash_in_finding_scope=False."""
    orc = BridgeOrchestrator()
    target = _make_target("safe_func", ["f-2"])
    bridge_result = BridgeResult(fuzz_targets=[target], total_findings=1)

    ok_result = _make_ok("safe_func")
    fuzz_report = FuzzReport(
        targets=[],
        all_results=[ok_result],
        crashes=[],
        total_iterations=1,
    )
    report = orc.correlate(bridge_result, fuzz_report)
    assert report.entries[0].crash_in_finding_scope is False
    assert report.crash_in_scope_count == 0


def test_correlation_crash_different_function() -> None:
    """Crash in a different function does not affect SAST correlation."""
    orc = BridgeOrchestrator()
    target = _make_target("my_func", ["f-3"])
    bridge_result = BridgeResult(fuzz_targets=[target], total_findings=1)

    crash = _make_crash("other_func")
    fuzz_report = FuzzReport(
        targets=[],
        all_results=[crash],
        crashes=[crash],
        total_iterations=1,
    )
    report = orc.correlate(bridge_result, fuzz_report)
    assert report.entries[0].crash_in_finding_scope is False
    assert report.crash_in_scope_count == 0


def test_correlation_multiple_findings_same_target() -> None:
    """Multiple findings in the same target function each get a correlation entry."""
    orc = BridgeOrchestrator()
    target = _make_target("risky_func", ["f-4", "f-5"])
    bridge_result = BridgeResult(fuzz_targets=[target], total_findings=2)

    crash = _make_crash("risky_func")
    fuzz_report = FuzzReport(
        targets=[],
        all_results=[crash],
        crashes=[crash],
        total_iterations=1,
    )
    report = orc.correlate(bridge_result, fuzz_report)
    # Two findings -> two entries
    assert len(report.entries) == 2
    for entry in report.entries:
        assert entry.crash_in_finding_scope is True
    assert report.crash_in_scope_count == 2


def test_correlation_totals_empty_report() -> None:
    """Empty fuzz report with findings produces no scope matches."""
    orc = BridgeOrchestrator()
    t1 = _make_target("func_a", ["f-10"])
    t2 = _make_target("func_b", ["f-11"])
    bridge_result = BridgeResult(fuzz_targets=[t1, t2], total_findings=2)

    fuzz_report = FuzzReport(targets=[], all_results=[], crashes=[], total_iterations=0)
    report = orc.correlate(bridge_result, fuzz_report)

    assert report.total_crashes == 0
    assert report.crash_in_scope_count == 0
    assert report.fuzz_targets_count == 2
    assert report.total_sast_findings == 2
    for entry in report.entries:
        assert entry.crash_in_finding_scope is False


def test_correlation_crash_in_scope_uses_field_name() -> None:
    """The field is named crash_in_finding_scope, not fuzz_confirmed."""
    orc = BridgeOrchestrator()
    target = _make_target("func_x", ["f-6"])
    bridge_result = BridgeResult(fuzz_targets=[target], total_findings=1)
    fuzz_report = FuzzReport(targets=[], all_results=[], crashes=[], total_iterations=0)
    report = orc.correlate(bridge_result, fuzz_report)

    entry = report.entries[0]
    # Correct field name
    assert hasattr(entry, "crash_in_finding_scope")
    # Wrong field name should not exist
    assert not hasattr(entry, "fuzz_confirmed")


def test_correlation_unique_crash_signatures_included() -> None:
    """Unique crash signatures are included in correlation entries."""
    orc = BridgeOrchestrator()
    target = _make_target("analyze_data", ["f-7"])
    bridge_result = BridgeResult(fuzz_targets=[target], total_findings=1)

    crash = _make_crash("analyze_data", "TypeError: bad type")
    unique_crash = UniqueCrash(
        signature="TypeError|analyze_data",
        exception_type="TypeError",
        exception_message="bad type",
        location='File "test.py", line 3, in analyze_data',
        representative=crash,
        count=1,
        target_functions=["analyze_data"],
    )

    fuzz_report = FuzzReport(
        targets=[],
        all_results=[crash],
        crashes=[crash],
        total_iterations=1,
    )
    # Manually inject unique_crashes by patching the property
    from unittest.mock import patch, PropertyMock

    with patch.object(
        type(fuzz_report),
        "unique_crashes",
        new_callable=PropertyMock,
        return_value=[unique_crash],
    ):
        report = orc.correlate(bridge_result, fuzz_report)

    entry = report.entries[0]
    assert entry.crash_in_finding_scope is True
    assert len(entry.crash_signatures) > 0
