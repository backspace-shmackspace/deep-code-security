"""Shared fixtures for TUI tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from deep_code_security.tui.models import RunMeta, ScanConfig
from deep_code_security.tui.storage import ReportStorage


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory for report storage."""
    return tmp_path / "reports"


@pytest.fixture
def storage(output_dir: Path) -> ReportStorage:
    """Provide a ReportStorage instance rooted at a temp directory."""
    return ReportStorage(output_dir=output_dir)


@pytest.fixture
def sample_run_meta() -> RunMeta:
    """Provide a fully-populated RunMeta for testing."""
    return RunMeta(
        run_id="550e8400-e29b-41d4-a716-446655440000",
        timestamp="2026-03-20T14:30:00Z",
        target_path="/home/user/projects/openssl",
        project_name="openssl",
        scan_type="hunt",
        duration_seconds=42.5,
        findings_count=7,
        backend_used="semgrep",
        exit_code=0,
        languages=["c"],
        severity_threshold="medium",
        report_files=["hunt.json", "hunt.sarif", "hunt.html"],
        error_message="",
        dcs_version="1.0.0",
    )


@pytest.fixture
def sample_scan_config() -> ScanConfig:
    """Provide a sample ScanConfig for testing."""
    return ScanConfig(
        target_path="/home/user/projects/openssl",
        scan_type="hunt",
        languages=["python", "go"],
        severity_threshold="medium",
        skip_verify=False,
        ignore_suppressions=False,
    )


@pytest.fixture
def populated_storage(storage: ReportStorage, sample_run_meta: RunMeta) -> ReportStorage:
    """Provide a ReportStorage with some existing runs."""
    # Create two runs for "openssl"
    run_dir_1 = storage.create_run_dir("openssl")
    meta_1 = sample_run_meta.model_copy(
        update={"timestamp": "2026-03-20T14:30:00Z", "run_id": "id-1"}
    )
    storage.write_meta(run_dir_1, meta_1)

    run_dir_2 = storage.create_run_dir("openssl")
    meta_2 = sample_run_meta.model_copy(
        update={
            "timestamp": "2026-03-21T10:00:00Z",
            "run_id": "id-2",
            "scan_type": "full-scan",
            "findings_count": 12,
        }
    )
    storage.write_meta(run_dir_2, meta_2)

    # Create one run for "flask-app"
    run_dir_3 = storage.create_run_dir("flask-app")
    meta_3 = sample_run_meta.model_copy(
        update={
            "timestamp": "2026-03-19T09:00:00Z",
            "run_id": "id-3",
            "project_name": "flask-app",
            "target_path": "/home/user/projects/flask-app",
        }
    )
    storage.write_meta(run_dir_3, meta_3)

    return storage
