"""Tests for CLI --format, --output-file, and --force options."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from deep_code_security.cli import cli
from deep_code_security.hunter.models import (
    RawFinding,
    ScanStats,
    Sink,
    Source,
    TaintPath,
    TaintStep,
)


@pytest.fixture
def runner():
    return CliRunner()


def _extract_json(output: str) -> dict:
    """Extract JSON object from CLI output that may contain stderr progress messages."""
    idx = output.find("{")
    if idx == -1:
        raise ValueError(f"No JSON found in output: {output!r}")
    return json.loads(output[idx:])


@pytest.fixture
def mock_hunter_scan():
    """Patch HunterOrchestrator.scan to return a sample finding."""
    source = Source(
        file="/tmp/test_target/app.py",
        line=10,
        column=12,
        function="request.form",
        category="web_input",
        language="python",
    )
    sink = Sink(
        file="/tmp/test_target/app.py",
        line=15,
        column=4,
        function="cursor.execute",
        category="sql_injection",
        cwe="CWE-89",
        language="python",
    )
    taint_path = TaintPath(
        steps=[
            TaintStep(
                file="/tmp/test_target/app.py",
                line=10,
                column=12,
                variable="user_input",
                transform="assignment",
            ),
        ],
        sanitized=False,
    )
    finding = RawFinding(
        id="cli-test-001",
        source=source,
        sink=sink,
        taint_path=taint_path,
        vulnerability_class="CWE-89: SQL Injection",
        severity="critical",
        language="python",
        raw_confidence=0.7,
    )
    stats = ScanStats(
        files_scanned=10,
        files_skipped=0,
        languages_detected=["python"],
        sources_found=5,
        sinks_found=3,
        taint_paths_found=1,
        scan_duration_ms=100,
    )
    return_value = ([finding], stats, 1, False)

    with patch(
        "deep_code_security.cli.HunterOrchestrator"
    ) as mock_cls:
        instance = MagicMock()
        instance.scan.return_value = return_value
        mock_cls.return_value = instance
        yield instance


@pytest.fixture
def allowed_target(tmp_path):
    """Create a valid scan target within a tmp directory."""
    target = tmp_path / "test_target"
    target.mkdir()
    (target / "app.py").write_text("# placeholder")
    return target


class TestHuntFormat:
    def test_hunt_format_json(self, runner, mock_hunter_scan, allowed_target):
        os.environ["DCS_ALLOWED_PATHS"] = str(allowed_target.parent)
        try:
            result = runner.invoke(cli, ["hunt", str(allowed_target), "--format", "json"])
            assert result.exit_code == 0
            parsed = _extract_json(result.output)
            assert "findings" in parsed
        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)

    def test_hunt_format_sarif(self, runner, mock_hunter_scan, allowed_target):
        os.environ["DCS_ALLOWED_PATHS"] = str(allowed_target.parent)
        try:
            result = runner.invoke(cli, ["hunt", str(allowed_target), "--format", "sarif"])
            assert result.exit_code == 0
            parsed = _extract_json(result.output)
            assert parsed["version"] == "2.1.0"
        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)

    def test_hunt_format_text_default(self, runner, mock_hunter_scan, allowed_target):
        os.environ["DCS_ALLOWED_PATHS"] = str(allowed_target.parent)
        try:
            result = runner.invoke(cli, ["hunt", str(allowed_target)])
            assert result.exit_code == 0
            assert "CRITICAL" in result.output or "SQL Injection" in result.output
        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)

    def test_hunt_json_output_deprecated(self, runner, mock_hunter_scan, allowed_target):
        os.environ["DCS_ALLOWED_PATHS"] = str(allowed_target.parent)
        try:
            result = runner.invoke(cli, ["hunt", str(allowed_target), "--json-output"])
            assert result.exit_code == 0
            # Should produce valid JSON on stdout
            parsed = _extract_json(result.output)
            assert "findings" in parsed
            # Deprecation warning appears in output (CliRunner mixes stderr)
            assert "deprecated" in result.output.lower()
        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)

    def test_format_sarif_with_json_output_conflict(
        self, runner, mock_hunter_scan, allowed_target
    ):
        os.environ["DCS_ALLOWED_PATHS"] = str(allowed_target.parent)
        try:
            result = runner.invoke(
                cli, ["hunt", str(allowed_target), "--format", "sarif", "--json-output"]
            )
            assert result.exit_code == 0
            # --json-output wins
            parsed = _extract_json(result.output)
            assert "findings" in parsed
            assert "version" not in parsed  # Not SARIF
        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)


class TestFullScanFormat:
    def test_full_scan_format_html(self, runner, allowed_target):
        os.environ["DCS_ALLOWED_PATHS"] = str(allowed_target.parent)
        with patch("deep_code_security.cli.HunterOrchestrator") as mock_hunter_cls, \
             patch("deep_code_security.cli.AuditorOrchestrator"), \
             patch("deep_code_security.cli.ArchitectOrchestrator"):

            stats = ScanStats(files_scanned=1, scan_duration_ms=10)
            mock_hunter_cls.return_value.scan.return_value = ([], stats, 0, False)

            try:
                result = runner.invoke(
                    cli, ["full-scan", str(allowed_target), "--format", "html"]
                )
                assert result.exit_code == 0
                assert "<html" in result.output
            finally:
                os.environ.pop("DCS_ALLOWED_PATHS", None)


class TestOutputFile:
    def test_output_file_writes_to_disk(self, runner, mock_hunter_scan, allowed_target):
        os.environ["DCS_ALLOWED_PATHS"] = str(allowed_target.parent)
        output_path = allowed_target.parent / "output.txt"
        try:
            result = runner.invoke(
                cli,
                ["hunt", str(allowed_target), "--format", "json", "-o", str(output_path)],
            )
            assert result.exit_code == 0
            assert output_path.exists()
            parsed = json.loads(output_path.read_text(encoding="utf-8"))
            assert "findings" in parsed
            # stdout should NOT contain the JSON output
            assert result.output == "" or "findings" not in result.output
        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)

    def test_output_file_json(self, runner, mock_hunter_scan, allowed_target):
        os.environ["DCS_ALLOWED_PATHS"] = str(allowed_target.parent)
        output_path = allowed_target.parent / "report.json"
        try:
            result = runner.invoke(
                cli,
                ["hunt", str(allowed_target), "--format", "json", "-o", str(output_path)],
            )
            assert result.exit_code == 0
            content = output_path.read_text(encoding="utf-8")
            parsed = json.loads(content)
            assert "findings" in parsed
        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)

    def test_output_file_validated_by_path_validator(
        self, runner, mock_hunter_scan, allowed_target
    ):
        os.environ["DCS_ALLOWED_PATHS"] = str(allowed_target)
        try:
            # Try to write outside allowed paths
            result = runner.invoke(
                cli,
                ["hunt", str(allowed_target), "-o", "/tmp/not_allowed/output.json"],
            )
            assert result.exit_code != 0
        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)

    def test_output_file_refuses_overwrite(self, runner, mock_hunter_scan, allowed_target):
        os.environ["DCS_ALLOWED_PATHS"] = str(allowed_target.parent)
        output_path = allowed_target.parent / "existing.txt"
        output_path.write_text("existing content")
        try:
            result = runner.invoke(
                cli,
                ["hunt", str(allowed_target), "-o", str(output_path)],
            )
            assert result.exit_code != 0
            assert "already exists" in (result.output or "")
        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)

    def test_output_file_force_overwrites(self, runner, mock_hunter_scan, allowed_target):
        os.environ["DCS_ALLOWED_PATHS"] = str(allowed_target.parent)
        output_path = allowed_target.parent / "existing.txt"
        output_path.write_text("old content")
        try:
            result = runner.invoke(
                cli,
                [
                    "hunt", str(allowed_target),
                    "--format", "json",
                    "-o", str(output_path),
                    "--force",
                ],
            )
            assert result.exit_code == 0
            new_content = output_path.read_text(encoding="utf-8")
            assert new_content != "old content"
            parsed = json.loads(new_content)
            assert "findings" in parsed
        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)

    def test_output_file_write_error(self, runner, mock_hunter_scan, allowed_target):
        os.environ["DCS_ALLOWED_PATHS"] = str(allowed_target.parent)
        # Try to write to a directory (should fail)
        output_path = allowed_target  # This is a directory
        try:
            result = runner.invoke(
                cli,
                ["hunt", str(allowed_target), "-o", str(output_path)],
            )
            assert result.exit_code != 0
        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)

    def test_output_file_utf8_encoding(self, runner, mock_hunter_scan, allowed_target):
        os.environ["DCS_ALLOWED_PATHS"] = str(allowed_target.parent)
        output_path = allowed_target.parent / "utf8_output.json"
        try:
            result = runner.invoke(
                cli,
                ["hunt", str(allowed_target), "--format", "json", "-o", str(output_path)],
            )
            assert result.exit_code == 0
            # Read with explicit UTF-8 to verify
            content = output_path.read_text(encoding="utf-8")
            assert len(content) > 0
        finally:
            os.environ.pop("DCS_ALLOWED_PATHS", None)
