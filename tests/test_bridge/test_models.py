"""Tests for bridge Pydantic models."""

from __future__ import annotations

import pytest

from deep_code_security.bridge.models import (
    BridgeConfig,
    BridgeResult,
    CorrelationEntry,
    CorrelationReport,
    FuzzTarget,
    SASTContext,
)


def test_sast_context_defaults() -> None:
    """Empty SASTContext is valid with sensible defaults."""
    ctx = SASTContext()
    assert ctx.cwe_ids == []
    assert ctx.vulnerability_classes == []
    assert ctx.sink_functions == []
    assert ctx.source_categories == []
    assert ctx.severity == "medium"
    assert ctx.finding_count == 0


def test_sast_context_with_data() -> None:
    """Populated SASTContext round-trips correctly."""
    ctx = SASTContext(
        cwe_ids=["CWE-78", "CWE-89"],
        vulnerability_classes=["CWE-78: OS Command Injection", "CWE-89: SQL Injection"],
        sink_functions=["os.system", "cursor.execute"],
        source_categories=["web_input"],
        severity="critical",
        finding_count=3,
    )
    assert ctx.cwe_ids == ["CWE-78", "CWE-89"]
    assert ctx.severity == "critical"
    assert ctx.finding_count == 3


def test_fuzz_target_construction(sample_sast_context: SASTContext) -> None:
    """FuzzTarget constructed with all fields."""
    target = FuzzTarget(
        file_path="/tmp/app.py",
        function_name="process_input",
        sast_context=sample_sast_context,
        finding_ids=["id-1", "id-2"],
        requires_instance=False,
        parameter_count=2,
    )
    assert target.file_path == "/tmp/app.py"
    assert target.function_name == "process_input"
    assert target.requires_instance is False
    assert target.parameter_count == 2
    assert len(target.finding_ids) == 2


def test_fuzz_target_requires_instance() -> None:
    """FuzzTarget with requires_instance=True for instance methods."""
    target = FuzzTarget(
        file_path="/tmp/view.py",
        function_name="MyView.handle_request",
        requires_instance=True,
        parameter_count=1,
    )
    assert target.requires_instance is True


def test_fuzz_target_defaults() -> None:
    """FuzzTarget can be constructed with minimal required fields."""
    target = FuzzTarget(
        file_path="/tmp/a.py",
        function_name="my_func",
    )
    assert target.sast_context.cwe_ids == []
    assert target.finding_ids == []
    assert target.requires_instance is False
    assert target.parameter_count == 0


def test_bridge_result_empty() -> None:
    """Empty BridgeResult is valid."""
    result = BridgeResult(total_findings=0)
    assert result.fuzz_targets == []
    assert result.skipped_findings == 0
    assert result.not_directly_fuzzable == 0
    assert result.skipped_reasons == []


def test_bridge_result_with_skips() -> None:
    """Skipped findings are counted correctly."""
    result = BridgeResult(
        total_findings=5,
        skipped_findings=3,
        skipped_reasons=["unsupported language: go", "no function", "syntax error"],
        not_directly_fuzzable=0,
    )
    assert result.skipped_findings == 3
    assert len(result.skipped_reasons) == 3


def test_bridge_result_not_directly_fuzzable() -> None:
    """not_directly_fuzzable counter works correctly."""
    result = BridgeResult(
        total_findings=10,
        skipped_findings=4,
        not_directly_fuzzable=4,
    )
    assert result.not_directly_fuzzable == 4


def test_correlation_entry_defaults() -> None:
    """CorrelationEntry has correct defaults."""
    entry = CorrelationEntry(
        finding_id="abc-123",
        vulnerability_class="CWE-78: OS Command Injection",
        severity="high",
        sink_function="os.system",
        target_function="run_command",
    )
    assert entry.crash_in_finding_scope is False
    assert entry.crash_count == 0
    assert entry.crash_signatures == []


def test_correlation_entry_crash_in_finding_scope() -> None:
    """crash_in_finding_scope semantics -- True indicates crash activity in function scope."""
    entry = CorrelationEntry(
        finding_id="abc-123",
        vulnerability_class="CWE-78: OS Command Injection",
        severity="high",
        sink_function="os.system",
        target_function="run_command",
        crash_in_finding_scope=True,
        crash_count=3,
        crash_signatures=["ZeroDivisionError", "ValueError"],
    )
    assert entry.crash_in_finding_scope is True
    assert entry.crash_count == 3
    # The field name is crash_in_finding_scope, NOT fuzz_confirmed
    assert not hasattr(entry, "fuzz_confirmed")


def test_correlation_report_counts() -> None:
    """CorrelationReport aggregation is correct."""
    entries = [
        CorrelationEntry(
            finding_id="id-1",
            vulnerability_class="CWE-78: OS Command Injection",
            severity="high",
            sink_function="os.system",
            target_function="run_command",
            crash_in_finding_scope=True,
            crash_count=2,
        ),
        CorrelationEntry(
            finding_id="id-2",
            vulnerability_class="CWE-89: SQL Injection",
            severity="medium",
            sink_function="cursor.execute",
            target_function="query_db",
            crash_in_finding_scope=False,
            crash_count=0,
        ),
    ]
    report = CorrelationReport(
        entries=entries,
        total_sast_findings=2,
        crash_in_scope_count=1,
        fuzz_targets_count=2,
        total_crashes=2,
    )
    assert report.total_sast_findings == 2
    assert report.crash_in_scope_count == 1
    assert report.fuzz_targets_count == 2
    assert report.total_crashes == 2
    assert len(report.entries) == 2


def test_bridge_config_defaults() -> None:
    """BridgeConfig.max_targets defaults to 10."""
    config = BridgeConfig()
    assert config.max_targets == 10


def test_bridge_config_custom() -> None:
    """BridgeConfig.max_targets can be overridden."""
    config = BridgeConfig(max_targets=25)
    assert config.max_targets == 25


def test_bridge_config_min_one() -> None:
    """BridgeConfig.max_targets must be >= 1."""
    with pytest.raises(Exception):
        BridgeConfig(max_targets=0)
