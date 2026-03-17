"""Tests for the BridgeOrchestrator."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from deep_code_security.bridge.models import BridgeConfig, BridgeResult, FuzzTarget, SASTContext
from deep_code_security.bridge.orchestrator import BridgeOrchestrator
from deep_code_security.fuzzer.models import FuzzInput, FuzzReport, FuzzResult
from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath


def _make_finding(
    sink_file: str,
    sink_line: int,
    language: str = "python",
    severity: str = "high",
) -> RawFinding:
    return RawFinding(
        source=Source(
            file=sink_file, line=1, column=0,
            function="request.form", category="web_input", language=language,
        ),
        sink=Sink(
            file=sink_file, line=sink_line, column=4,
            function="os.system", category="command_injection",
            cwe="CWE-78", language=language,
        ),
        taint_path=TaintPath(steps=[], sanitized=False),
        vulnerability_class="CWE-78: OS Command Injection",
        severity=severity,
        language=language,
        raw_confidence=0.8,
    )


def _make_fuzz_result(target_function: str, success: bool = True) -> FuzzResult:
    fi = FuzzInput(target_function=target_function, args=("'hello'",))
    return FuzzResult(input=fi, success=success, exception="ValueError: bad" if not success else None)


@pytest.fixture
def orchestrator() -> BridgeOrchestrator:
    return BridgeOrchestrator()


def test_run_bridge_with_findings(tmp_path: Path, orchestrator: BridgeOrchestrator) -> None:
    """Produces FuzzTargets from fixture findings."""
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def process(cmd: str) -> None:
            import os
            os.system(cmd)
        """)
    )
    finding = _make_finding(str(py_file), sink_line=3)
    result = orchestrator.run_bridge([finding])
    assert isinstance(result, BridgeResult)
    assert len(result.fuzz_targets) == 1
    assert result.fuzz_targets[0].function_name == "process"


def test_run_bridge_no_findings(orchestrator: BridgeOrchestrator) -> None:
    """Empty findings produce empty result."""
    result = orchestrator.run_bridge([])
    assert result.fuzz_targets == []
    assert result.total_findings == 0


def test_run_bridge_with_config(tmp_path: Path, orchestrator: BridgeOrchestrator) -> None:
    """Bridge config is respected."""
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def cmd_a(x: str) -> None:
            import os
            os.system(x)

        def cmd_b(y: str) -> None:
            import os
            os.system(y)
        """)
    )
    f1 = _make_finding(str(py_file), sink_line=3)
    f2 = _make_finding(str(py_file), sink_line=7)
    config = BridgeConfig(max_targets=1)
    result = orchestrator.run_bridge([f1, f2], config=config)
    assert len(result.fuzz_targets) <= 1


def test_correlate_with_crashes(orchestrator: BridgeOrchestrator) -> None:
    """Crash in target function sets crash_in_finding_scope=True."""
    target = FuzzTarget(
        file_path="/tmp/app.py",
        function_name="vulnerable_func",
        sast_context=SASTContext(
            cwe_ids=["CWE-78"],
            vulnerability_classes=["CWE-78: OS Command Injection"],
            sink_functions=["os.system"],
            source_categories=["web_input"],
            severity="high",
            finding_count=1,
        ),
        finding_ids=["finding-1"],
        requires_instance=False,
        parameter_count=1,
    )
    bridge_result = BridgeResult(fuzz_targets=[target], total_findings=1)

    crash_result = _make_fuzz_result("vulnerable_func", success=False)
    report = FuzzReport(
        targets=[],
        all_results=[crash_result],
        crashes=[crash_result],
        total_iterations=1,
    )

    corr = orchestrator.correlate(bridge_result, report)
    assert len(corr.entries) == 1
    assert corr.entries[0].crash_in_finding_scope is True
    assert corr.entries[0].crash_count == 1
    assert corr.crash_in_scope_count == 1


def test_correlate_no_crashes(orchestrator: BridgeOrchestrator) -> None:
    """No crashes means no scope matches."""
    target = FuzzTarget(
        file_path="/tmp/app.py",
        function_name="safe_func",
        sast_context=SASTContext(severity="medium", finding_count=1),
        finding_ids=["finding-2"],
    )
    bridge_result = BridgeResult(fuzz_targets=[target], total_findings=1)
    report = FuzzReport(targets=[], all_results=[], crashes=[], total_iterations=1)

    corr = orchestrator.correlate(bridge_result, report)
    assert len(corr.entries) == 1
    assert corr.entries[0].crash_in_finding_scope is False
    assert corr.crash_in_scope_count == 0


def test_correlate_crash_in_different_function(orchestrator: BridgeOrchestrator) -> None:
    """Crash in a non-SAST function is not correlated with SAST findings."""
    target = FuzzTarget(
        file_path="/tmp/app.py",
        function_name="sast_func",
        sast_context=SASTContext(severity="high", finding_count=1),
        finding_ids=["finding-3"],
    )
    bridge_result = BridgeResult(fuzz_targets=[target], total_findings=1)

    # Crash is in a different function
    crash_result = _make_fuzz_result("other_func", success=False)
    report = FuzzReport(
        targets=[],
        all_results=[crash_result],
        crashes=[crash_result],
        total_iterations=1,
    )

    corr = orchestrator.correlate(bridge_result, report)
    assert len(corr.entries) == 1
    assert corr.entries[0].crash_in_finding_scope is False
    assert corr.crash_in_scope_count == 0
