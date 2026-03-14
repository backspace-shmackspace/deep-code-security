"""Shared fixtures for formatter tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from deep_code_security.architect.models import RemediateStats, RemediationGuidance
from deep_code_security.auditor.models import VerifiedFinding, VerifyStats
from deep_code_security.hunter.models import (
    RawFinding,
    ScanStats,
    Sink,
    Source,
    TaintPath,
    TaintStep,
)
from deep_code_security.shared.formatters.protocol import FullScanResult, HuntResult

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"


@pytest.fixture
def sarif_schema() -> dict:
    """Load the vendored SARIF 2.1.0 JSON Schema."""
    import json

    schema_path = FIXTURES_DIR / "sarif-schema-2.1.0.json"
    with open(schema_path) as f:
        return json.load(f)


@pytest.fixture
def sample_source() -> Source:
    return Source(
        file="/tmp/project/app.py",
        line=10,
        column=12,
        function="request.form",
        category="web_input",
        language="python",
    )


@pytest.fixture
def sample_sink() -> Sink:
    return Sink(
        file="/tmp/project/app.py",
        line=15,
        column=4,
        function="cursor.execute",
        category="sql_injection",
        cwe="CWE-89",
        language="python",
    )


@pytest.fixture
def sample_taint_path(sample_source: Source, sample_sink: Sink) -> TaintPath:
    return TaintPath(
        steps=[
            TaintStep(
                file=sample_source.file,
                line=sample_source.line,
                column=sample_source.column,
                variable="user_input",
                transform="assignment",
            ),
            TaintStep(
                file=sample_sink.file,
                line=sample_sink.line,
                column=sample_sink.column,
                variable="user_input",
                transform="sink_argument",
            ),
        ],
        sanitized=False,
    )


@pytest.fixture
def sample_finding(
    sample_source: Source,
    sample_sink: Sink,
    sample_taint_path: TaintPath,
) -> RawFinding:
    return RawFinding(
        id="test-finding-001",
        source=sample_source,
        sink=sample_sink,
        taint_path=sample_taint_path,
        vulnerability_class="CWE-89: SQL Injection",
        severity="critical",
        language="python",
        raw_confidence=0.7,
    )


@pytest.fixture
def sample_finding_medium() -> RawFinding:
    return RawFinding(
        id="test-finding-002",
        source=Source(
            file="/tmp/project/views.py",
            line=20,
            column=0,
            function="request.args",
            category="web_input",
            language="python",
        ),
        sink=Sink(
            file="/tmp/project/views.py",
            line=25,
            column=8,
            function="os.system",
            category="command_injection",
            cwe="CWE-78",
            language="python",
        ),
        taint_path=TaintPath(steps=[], sanitized=False),
        vulnerability_class="CWE-78: OS Command Injection",
        severity="medium",
        language="python",
        raw_confidence=0.5,
    )


@pytest.fixture
def sample_finding_low() -> RawFinding:
    return RawFinding(
        id="test-finding-003",
        source=Source(
            file="/tmp/project/util.py",
            line=5,
            column=0,
            function="input",
            category="cli_input",
            language="python",
        ),
        sink=Sink(
            file="/tmp/project/util.py",
            line=8,
            column=4,
            function="eval",
            category="code_injection",
            cwe="CWE-94",
            language="python",
        ),
        taint_path=TaintPath(steps=[], sanitized=False),
        vulnerability_class="CWE-94: Code Injection",
        severity="low",
        language="python",
        raw_confidence=0.3,
    )


@pytest.fixture
def sample_stats() -> ScanStats:
    return ScanStats(
        files_scanned=42,
        files_skipped=3,
        languages_detected=["python"],
        sources_found=10,
        sinks_found=5,
        taint_paths_found=3,
        scan_duration_ms=150,
        registry_version_hash="abc123",
    )


@pytest.fixture
def sample_hunt_result(
    sample_finding: RawFinding,
    sample_stats: ScanStats,
) -> HuntResult:
    return HuntResult(
        findings=[sample_finding],
        stats=sample_stats,
        total_count=1,
        has_more=False,
    )


@pytest.fixture
def sample_verified_finding(sample_finding: RawFinding) -> VerifiedFinding:
    return VerifiedFinding(
        finding=sample_finding,
        exploit_results=[],
        confidence_score=75,
        verification_status="likely",
    )


@pytest.fixture
def sample_guidance() -> RemediationGuidance:
    return RemediationGuidance(
        finding_id="test-finding-001",
        vulnerability_explanation="SQL injection allows attackers to execute arbitrary SQL.",
        fix_pattern="Use parameterized queries",
        code_example='cursor.execute("SELECT * FROM users WHERE name = ?", (name,))',
        effort_estimate="small",
        test_suggestions=["Test with SQL metacharacters in input"],
        references=["https://cwe.mitre.org/data/definitions/89.html"],
    )


@pytest.fixture
def sample_verify_stats() -> VerifyStats:
    return VerifyStats(
        total_findings=1,
        verified_count=1,
        confirmed=0,
        likely=1,
        unconfirmed=0,
        false_positives=0,
        sandbox_available=False,
        verification_duration_ms=50,
    )


@pytest.fixture
def sample_remediate_stats() -> RemediateStats:
    return RemediateStats(
        total_verified=1,
        guidance_generated=1,
        dependencies_affected=0,
        remediation_duration_ms=30,
    )


@pytest.fixture
def sample_full_scan_result(
    sample_finding: RawFinding,
    sample_verified_finding: VerifiedFinding,
    sample_guidance: RemediationGuidance,
    sample_stats: ScanStats,
    sample_verify_stats: VerifyStats,
    sample_remediate_stats: RemediateStats,
) -> FullScanResult:
    return FullScanResult(
        findings=[sample_finding],
        verified=[sample_verified_finding],
        guidance=[sample_guidance],
        hunt_stats=sample_stats,
        verify_stats=sample_verify_stats,
        remediate_stats=sample_remediate_stats,
        total_count=1,
        has_more=False,
    )
