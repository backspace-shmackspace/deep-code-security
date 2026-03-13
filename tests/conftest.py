"""Shared test fixtures and configuration."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from deep_code_security.hunter.models import (
    RawFinding,
    Sink,
    Source,
    TaintPath,
    TaintStep,
)
from deep_code_security.shared.config import Config, reset_config

# Directory containing test fixtures
FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULNERABLE_PYTHON = FIXTURES_DIR / "vulnerable_samples" / "python"
VULNERABLE_GO = FIXTURES_DIR / "vulnerable_samples" / "go"
SAFE_PYTHON = FIXTURES_DIR / "safe_samples" / "python"
SAFE_GO = FIXTURES_DIR / "safe_samples" / "go"


@pytest.fixture(autouse=True)
def reset_global_config():
    """Reset the global config singleton before each test."""
    reset_config()
    yield
    reset_config()


@pytest.fixture
def tmp_allowed_dir(tmp_path: Path) -> Path:
    """A temporary directory that is allowed for scanning."""
    return tmp_path


@pytest.fixture
def test_config(tmp_allowed_dir: Path) -> Config:
    """A Config with the temp directory as the allowed path."""
    os.environ["DCS_ALLOWED_PATHS"] = str(tmp_allowed_dir)
    os.environ["DCS_REGISTRY_PATH"] = str(Path(__file__).parent.parent / "registries")
    reset_config()
    config = Config()
    yield config
    # Cleanup
    os.environ.pop("DCS_ALLOWED_PATHS", None)
    os.environ.pop("DCS_REGISTRY_PATH", None)
    reset_config()


@pytest.fixture
def registry_path() -> Path:
    """Path to the real registries directory."""
    return Path(__file__).parent.parent / "registries"


@pytest.fixture
def sample_source() -> Source:
    """A sample Source model for testing."""
    return Source(
        file="/tmp/test.py",
        line=10,
        column=12,
        function="request.form",
        category="web_input",
        language="python",
    )


@pytest.fixture
def sample_sink() -> Sink:
    """A sample Sink model for testing."""
    return Sink(
        file="/tmp/test.py",
        line=15,
        column=4,
        function="cursor.execute",
        category="sql_injection",
        cwe="CWE-89",
        language="python",
    )


@pytest.fixture
def sample_taint_step(sample_source: Source) -> TaintStep:
    """A sample TaintStep for testing."""
    return TaintStep(
        file=sample_source.file,
        line=sample_source.line,
        column=sample_source.column,
        variable="user_input",
        transform="assignment",
    )


@pytest.fixture
def sample_taint_path(sample_taint_step: TaintStep, sample_sink: Sink) -> TaintPath:
    """A sample TaintPath for testing."""
    sink_step = TaintStep(
        file=sample_sink.file,
        line=sample_sink.line,
        column=sample_sink.column,
        variable="user_input",
        transform="sink_argument",
    )
    return TaintPath(steps=[sample_taint_step, sink_step], sanitized=False)


@pytest.fixture
def sample_raw_finding(
    sample_source: Source,
    sample_sink: Sink,
    sample_taint_path: TaintPath,
) -> RawFinding:
    """A sample RawFinding for testing."""
    return RawFinding(
        source=sample_source,
        sink=sample_sink,
        taint_path=sample_taint_path,
        vulnerability_class="CWE-89: SQL Injection",
        severity="critical",
        language="python",
        raw_confidence=0.7,
    )


@pytest.fixture
def mock_sandbox():
    """A mock SandboxProvider that never runs containers."""
    mock = MagicMock()
    mock.is_available.return_value = False
    mock._runtime_cmd = None
    return mock


@pytest.fixture
def mock_sandbox_available():
    """A mock SandboxProvider that reports available but returns non-exploitable results."""
    from deep_code_security.auditor.models import ExploitResult

    mock = MagicMock()
    mock.is_available.return_value = True
    mock._runtime_cmd = "docker"

    mock.run_exploit.return_value = ExploitResult(
        exploit_script_hash="abc123" * 10 + "ab",
        exit_code=0,
        stdout_truncated="PoC executed\n",
        stderr_truncated="",
        exploitable=False,
        execution_time_ms=250,
        timed_out=False,
    )
    return mock


@pytest.fixture
def mock_sandbox_exploitable():
    """A mock SandboxProvider that returns exploitable results."""
    from deep_code_security.auditor.models import ExploitResult

    mock = MagicMock()
    mock.is_available.return_value = True
    mock._runtime_cmd = "docker"

    mock.run_exploit.return_value = ExploitResult(
        exploit_script_hash="abc123" * 10 + "ab",
        exit_code=0,
        stdout_truncated="uid=0(root) gid=0(root)\n",
        stderr_truncated="",
        exploitable=True,
        execution_time_ms=500,
        timed_out=False,
    )
    return mock


@pytest.fixture
def python_sql_injection_code() -> str:
    """Python code with SQL injection for testing."""
    return """\
import sqlite3
from flask import request

def get_user(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    user_input = request.form["username"]
    query = "SELECT * FROM users WHERE name='" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchall()
"""


@pytest.fixture
def python_safe_code() -> str:
    """Python code with parameterized query (safe) for testing."""
    return """\
import sqlite3
from flask import request

def get_user(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    user_input = request.form["username"]
    query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (user_input,))
    return cursor.fetchall()
"""
