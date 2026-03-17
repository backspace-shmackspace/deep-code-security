"""Bridge-specific fixtures for test_bridge tests."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from deep_code_security.bridge.models import BridgeConfig, BridgeResult, FuzzTarget, SASTContext
from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath, TaintStep


def _make_source(file: str = "/tmp/test.py", line: int = 5) -> Source:
    return Source(
        file=file,
        line=line,
        column=0,
        function="request.form",
        category="web_input",
        language="python",
    )


def _make_sink(
    file: str = "/tmp/test.py",
    line: int = 10,
    function: str = "os.system",
    cwe: str = "CWE-78",
) -> Sink:
    return Sink(
        file=file,
        line=line,
        column=4,
        function=function,
        category="command_injection",
        cwe=cwe,
        language="python",
    )


def _make_finding(
    source_file: str = "/tmp/test.py",
    source_line: int = 5,
    sink_file: str = "/tmp/test.py",
    sink_line: int = 10,
    sink_function: str = "os.system",
    cwe: str = "CWE-78",
    vulnerability_class: str = "CWE-78: OS Command Injection",
    severity: str = "high",
    language: str = "python",
) -> RawFinding:
    return RawFinding(
        source=Source(
            file=source_file,
            line=source_line,
            column=0,
            function="request.form",
            category="web_input",
            language=language,
        ),
        sink=Sink(
            file=sink_file,
            line=sink_line,
            column=4,
            function=sink_function,
            category="command_injection",
            cwe=cwe,
            language=language,
        ),
        taint_path=TaintPath(
            steps=[
                TaintStep(
                    file=sink_file,
                    line=source_line,
                    column=0,
                    variable="user_input",
                    transform="assignment",
                )
            ],
            sanitized=False,
        ),
        vulnerability_class=vulnerability_class,
        severity=severity,
        language=language,
        raw_confidence=0.8,
    )


@pytest.fixture
def python_finding(tmp_path: Path) -> RawFinding:
    """A Python finding with a known function containing the sink."""
    py_file = tmp_path / "sample.py"
    py_file.write_text(
        textwrap.dedent("""\
        def process_data(user_input: str) -> str:
            import os
            result = os.system(user_input)
            return str(result)
        """)
    )
    return _make_finding(
        source_file=str(py_file),
        source_line=1,
        sink_file=str(py_file),
        sink_line=3,
        sink_function="os.system",
        cwe="CWE-78",
    )


@pytest.fixture
def go_finding() -> RawFinding:
    """A Go finding (non-Python, should be skipped)."""
    return _make_finding(
        source_file="/tmp/main.go",
        sink_file="/tmp/main.go",
        language="go",
    )


@pytest.fixture
def bridge_config() -> BridgeConfig:
    return BridgeConfig(max_targets=10)


@pytest.fixture
def sample_sast_context() -> SASTContext:
    return SASTContext(
        cwe_ids=["CWE-78"],
        vulnerability_classes=["CWE-78: OS Command Injection"],
        sink_functions=["os.system"],
        source_categories=["web_input"],
        severity="high",
        finding_count=1,
    )


@pytest.fixture
def sample_fuzz_target(sample_sast_context: SASTContext) -> FuzzTarget:
    return FuzzTarget(
        file_path="/tmp/test.py",
        function_name="process_data",
        sast_context=sample_sast_context,
        finding_ids=["abc-123"],
        requires_instance=False,
        parameter_count=1,
    )


@pytest.fixture
def empty_bridge_result() -> BridgeResult:
    return BridgeResult(
        fuzz_targets=[],
        skipped_findings=0,
        skipped_reasons=[],
        total_findings=0,
        not_directly_fuzzable=0,
    )
