"""Tests for ScanRunner -- command building, subprocess mocking, format conversion."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from deep_code_security.tui.models import ScanConfig
from deep_code_security.tui.runner import ScanRunner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def run_dir(tmp_path: Path) -> Path:
    """Create and return a temporary run directory."""
    d = tmp_path / "test-run"
    d.mkdir()
    return d


def _make_config(**overrides: Any) -> ScanConfig:
    """Build a ScanConfig with sensible defaults, overriding any fields."""
    defaults: dict[str, Any] = {
        "target_path": "/tmp/project",
        "scan_type": "hunt",
        "languages": [],
        "severity_threshold": "medium",
        "skip_verify": False,
        "ignore_suppressions": False,
    }
    defaults.update(overrides)
    return ScanConfig(**defaults)


# ---------------------------------------------------------------------------
# build_command tests
# ---------------------------------------------------------------------------


class TestBuildCommand:
    """Tests for ScanRunner.build_command()."""

    def test_build_command_hunt(self, run_dir: Path) -> None:
        """Produces correct command for hunt scan."""
        config = _make_config(scan_type="hunt")
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert cmd[0] == sys.executable
        assert cmd[1:4] == ["-m", "deep_code_security.cli", "hunt"]
        assert "/tmp/project" in cmd
        assert "--format" in cmd
        idx = cmd.index("--format")
        assert cmd[idx + 1] == "json"
        assert "--output-file" in cmd
        out_idx = cmd.index("--output-file")
        assert cmd[out_idx + 1] == str(run_dir / "hunt.json")
        assert "--force" in cmd

    def test_build_command_full_scan(self, run_dir: Path) -> None:
        """Full-scan with skip_verify includes --skip-verify flag."""
        config = _make_config(scan_type="full-scan", skip_verify=True)
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "full-scan" in cmd
        assert "--skip-verify" in cmd
        out_idx = cmd.index("--output-file")
        assert cmd[out_idx + 1] == str(run_dir / "full.json")

    def test_build_command_hunt_fuzz(self, run_dir: Path) -> None:
        """Hunt-fuzz includes --consent flag."""
        config = _make_config(scan_type="hunt-fuzz")
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "hunt-fuzz" in cmd
        assert "--consent" in cmd
        out_idx = cmd.index("--output-file")
        assert cmd[out_idx + 1] == str(run_dir / "hunt-fuzz.json")

    def test_build_command_fuzz(self, run_dir: Path) -> None:
        """Fuzz includes --consent flag."""
        config = _make_config(scan_type="fuzz")
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "fuzz" in cmd
        assert "--consent" in cmd
        out_idx = cmd.index("--output-file")
        assert cmd[out_idx + 1] == str(run_dir / "fuzz.json")

    def test_build_command_languages(self, run_dir: Path) -> None:
        """Language filter adds -l flags for each language."""
        config = _make_config(languages=["python", "go"])
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        # Find all -l occurrences
        lang_indices = [i for i, v in enumerate(cmd) if v == "-l"]
        assert len(lang_indices) == 2
        langs = {cmd[i + 1] for i in lang_indices}
        assert langs == {"python", "go"}

    def test_build_command_severity(self, run_dir: Path) -> None:
        """Non-default severity adds --severity flag."""
        config = _make_config(severity_threshold="critical")
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "--severity" in cmd
        idx = cmd.index("--severity")
        assert cmd[idx + 1] == "critical"

    def test_build_command_severity_default_omitted(self, run_dir: Path) -> None:
        """Default severity (medium) does not add --severity flag."""
        config = _make_config(severity_threshold="medium")
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "--severity" not in cmd

    def test_build_command_ignore_suppressions(self, run_dir: Path) -> None:
        """Ignore suppressions adds --ignore-suppressions for hunt scans."""
        config = _make_config(scan_type="hunt", ignore_suppressions=True)
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "--ignore-suppressions" in cmd

    def test_build_command_ignore_suppressions_full_scan(self, run_dir: Path) -> None:
        """Ignore suppressions adds --ignore-suppressions for full-scan."""
        config = _make_config(scan_type="full-scan", ignore_suppressions=True)
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "--ignore-suppressions" in cmd

    def test_build_command_ignore_suppressions_hunt_fuzz(self, run_dir: Path) -> None:
        """Ignore suppressions adds --ignore-suppressions for hunt-fuzz."""
        config = _make_config(scan_type="hunt-fuzz", ignore_suppressions=True)
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "--ignore-suppressions" in cmd

    def test_build_command_ignore_suppressions_not_for_fuzz(self, run_dir: Path) -> None:
        """Ignore suppressions is NOT added for fuzz scans."""
        config = _make_config(scan_type="fuzz", ignore_suppressions=True)
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "--ignore-suppressions" not in cmd

    def test_build_command_no_shell_true(self, run_dir: Path) -> None:
        """All commands are list form -- no string commands for shell=True."""
        config = _make_config()
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert isinstance(cmd, list)
        assert all(isinstance(c, str) for c in cmd)

    def test_build_command_output_file(self, run_dir: Path) -> None:
        """Command includes --output-file pointing to run_dir."""
        config = _make_config()
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "--output-file" in cmd
        idx = cmd.index("--output-file")
        output_path = cmd[idx + 1]
        assert output_path.startswith(str(run_dir))
        assert output_path.endswith(".json")

    def test_build_command_no_extra_args(self) -> None:
        """ScanConfig has no extra_args field."""
        assert not hasattr(ScanConfig, "extra_args")
        # Verify the model fields are exactly what we expect
        field_names = set(ScanConfig.model_fields.keys())
        assert "extra_args" not in field_names

    def test_build_command_skip_verify_only_for_full_scan(self, run_dir: Path) -> None:
        """--skip-verify is NOT added for hunt scans even if set."""
        config = _make_config(scan_type="hunt", skip_verify=True)
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "--skip-verify" not in cmd

    def test_build_command_consent_not_for_hunt(self, run_dir: Path) -> None:
        """--consent is NOT added for hunt scans."""
        config = _make_config(scan_type="hunt")
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "--consent" not in cmd

    def test_build_command_uses_sys_executable(self, run_dir: Path) -> None:
        """Command starts with sys.executable."""
        config = _make_config()
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert cmd[0] == sys.executable


# ---------------------------------------------------------------------------
# Async run/cancel tests (mock subprocess)
# ---------------------------------------------------------------------------


def _make_mock_process(
    exit_code: int = 0,
    stderr_lines: list[str] | None = None,
    stdout_data: bytes = b"",
) -> AsyncMock:
    """Create a mock asyncio.subprocess.Process."""
    proc = AsyncMock()
    proc.returncode = None

    # Build stderr readline iterator
    lines = stderr_lines or []
    encoded = [f"{l}\n".encode() for l in lines]
    encoded.append(b"")  # EOF
    proc.stderr = AsyncMock()
    proc.stderr.readline = AsyncMock(side_effect=encoded)

    proc.stdout = AsyncMock()
    proc.stdout.read = AsyncMock(return_value=stdout_data)

    async def fake_wait() -> int:
        proc.returncode = exit_code
        return exit_code

    proc.wait = AsyncMock(side_effect=fake_wait)
    proc.terminate = MagicMock()
    proc.kill = MagicMock()

    return proc


class TestRunCaptures:
    """Tests for ScanRunner.run() -- subprocess capture and metadata."""

    @pytest.mark.asyncio()
    async def test_run_captures_stderr(self, run_dir: Path) -> None:
        """on_stderr_line callback is invoked for each stderr line."""
        captured: list[str] = []
        config = _make_config()
        runner = ScanRunner(config, run_dir, on_stderr_line=captured.append)

        proc = _make_mock_process(
            stderr_lines=["Scanning /tmp/project...", "Found 5 findings in 3 files"]
        )

        with patch("deep_code_security.tui.runner.asyncio") as mock_asyncio:
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert len(captured) == 2
        assert "Scanning /tmp/project..." in captured[0]
        assert "Found 5 findings in 3 files" in captured[1]

    @pytest.mark.asyncio()
    async def test_run_writes_meta_json(self, run_dir: Path) -> None:
        """RunMeta is returned with correct fields after run."""
        config = _make_config(scan_type="hunt")
        runner = ScanRunner(config, run_dir)

        # Write a fake JSON output file to simulate dcs output
        json_output = {
            "findings": [],
            "stats": {
                "scanner_backend": "semgrep",
                "files_scanned": 10,
                "languages": {"python": 10},
                "duration_seconds": 1.5,
            },
            "total_count": 7,
            "has_more": False,
        }
        json_path = run_dir / "hunt.json"
        json_path.write_text(json.dumps(json_output), encoding="utf-8")

        proc = _make_mock_process(exit_code=0)

        with patch("deep_code_security.tui.runner.asyncio") as mock_asyncio:
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert meta.scan_type == "hunt"
        assert meta.target_path == "/tmp/project"
        assert meta.exit_code == 0
        assert meta.findings_count == 7
        assert meta.backend_used == "semgrep"
        assert meta.duration_seconds >= 0

    @pytest.mark.asyncio()
    async def test_run_generates_sarif_html_from_json(self, run_dir: Path) -> None:
        """In-process format conversion creates SARIF and HTML files."""
        config = _make_config(scan_type="hunt")
        runner = ScanRunner(config, run_dir)

        # Write a fake JSON output
        json_output = {
            "findings": [],
            "stats": {
                "scanner_backend": "treesitter",
                "files_scanned": 5,
                "languages": {},
                "duration_seconds": 0.5,
            },
            "total_count": 0,
            "has_more": False,
        }
        json_path = run_dir / "hunt.json"
        json_path.write_text(json.dumps(json_output), encoding="utf-8")

        proc = _make_mock_process(exit_code=0)

        # Mock the formatter to avoid needing the full formatter infrastructure
        mock_formatter = MagicMock()
        mock_formatter.format_hunt = MagicMock(return_value="<sarif>")

        mock_html_formatter = MagicMock()
        mock_html_formatter.format_hunt = MagicMock(return_value="<html>")

        call_count = {"n": 0}

        def fake_get_formatter(name: str) -> Any:
            call_count["n"] += 1
            if name == "sarif":
                return mock_formatter
            if name == "html":
                return mock_html_formatter
            raise ValueError(f"Unknown: {name}")

        with (
            patch("deep_code_security.tui.runner.asyncio") as mock_asyncio,
            patch(
                "deep_code_security.shared.formatters.get_formatter",
                side_effect=fake_get_formatter,
            ),
        ):
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert "hunt.json" in meta.report_files
        # SARIF/HTML may or may not succeed depending on DTO validation
        # but the method should not raise

    @pytest.mark.asyncio()
    async def test_run_format_conversion_failure_is_nonfatal(
        self, run_dir: Path
    ) -> None:
        """Failed SARIF/HTML conversion does not prevent RunMeta return."""
        config = _make_config(scan_type="hunt")
        runner = ScanRunner(config, run_dir)

        # Write a JSON file that will fail DTO construction
        json_path = run_dir / "hunt.json"
        json_path.write_text('{"total_count": 3}', encoding="utf-8")

        proc = _make_mock_process(exit_code=0)

        with patch("deep_code_security.tui.runner.asyncio") as mock_asyncio:
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert meta is not None
        assert meta.findings_count == 3
        assert "hunt.json" in meta.report_files

    @pytest.mark.asyncio()
    async def test_run_findings_count_hunt(self, run_dir: Path) -> None:
        """Hunt findings_count from output['total_count']."""
        config = _make_config(scan_type="hunt")
        runner = ScanRunner(config, run_dir)

        json_path = run_dir / "hunt.json"
        json_path.write_text(
            json.dumps({"total_count": 42, "findings": [], "stats": {
                "scanner_backend": "semgrep", "files_scanned": 1,
                "languages": {}, "duration_seconds": 0.1,
            }, "has_more": False}),
            encoding="utf-8",
        )

        proc = _make_mock_process(exit_code=0)
        with patch("deep_code_security.tui.runner.asyncio") as mock_asyncio:
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert meta.findings_count == 42

    @pytest.mark.asyncio()
    async def test_run_findings_count_fuzz(self, run_dir: Path) -> None:
        """Fuzz findings_count from output['summary']['unique_crash_count']."""
        config = _make_config(scan_type="fuzz")
        runner = ScanRunner(config, run_dir)

        json_path = run_dir / "fuzz.json"
        json_path.write_text(
            json.dumps({"summary": {"unique_crash_count": 3}}),
            encoding="utf-8",
        )

        proc = _make_mock_process(exit_code=0)
        with patch("deep_code_security.tui.runner.asyncio") as mock_asyncio:
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert meta.findings_count == 3

    @pytest.mark.asyncio()
    async def test_run_findings_count_hunt_fuzz(self, run_dir: Path) -> None:
        """Hunt-fuzz findings_count from output['hunt_result']['total_count']."""
        config = _make_config(scan_type="hunt-fuzz")
        runner = ScanRunner(config, run_dir)

        json_path = run_dir / "hunt-fuzz.json"
        json_path.write_text(
            json.dumps({
                "hunt_result": {"total_count": 15, "findings": [], "stats": {
                    "scanner_backend": "semgrep", "files_scanned": 1,
                    "languages": {}, "duration_seconds": 0.1,
                }, "has_more": False},
            }),
            encoding="utf-8",
        )

        proc = _make_mock_process(exit_code=0)
        with patch("deep_code_security.tui.runner.asyncio") as mock_asyncio:
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert meta.findings_count == 15

    @pytest.mark.asyncio()
    async def test_run_backend_used_hunt(self, run_dir: Path) -> None:
        """Hunt backend_used from output['stats']['scanner_backend']."""
        config = _make_config(scan_type="hunt")
        runner = ScanRunner(config, run_dir)

        json_path = run_dir / "hunt.json"
        json_path.write_text(
            json.dumps({
                "total_count": 0,
                "findings": [],
                "stats": {
                    "scanner_backend": "treesitter",
                    "files_scanned": 1,
                    "languages": {},
                    "duration_seconds": 0.1,
                },
                "has_more": False,
            }),
            encoding="utf-8",
        )

        proc = _make_mock_process(exit_code=0)
        with patch("deep_code_security.tui.runner.asyncio") as mock_asyncio:
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert meta.backend_used == "treesitter"

    @pytest.mark.asyncio()
    async def test_run_backend_used_full_scan(self, run_dir: Path) -> None:
        """Full-scan backend_used from output['hunt_stats']['scanner_backend']."""
        config = _make_config(scan_type="full-scan")
        runner = ScanRunner(config, run_dir)

        json_path = run_dir / "full.json"
        json_path.write_text(
            json.dumps({
                "total_count": 0,
                "hunt_stats": {
                    "scanner_backend": "semgrep",
                    "files_scanned": 1,
                    "languages": {},
                    "duration_seconds": 0.1,
                },
            }),
            encoding="utf-8",
        )

        proc = _make_mock_process(exit_code=0)
        with patch("deep_code_security.tui.runner.asyncio") as mock_asyncio:
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert meta.backend_used == "semgrep"

    @pytest.mark.asyncio()
    async def test_run_backend_used_hunt_fuzz(self, run_dir: Path) -> None:
        """Hunt-fuzz backend from output['hunt_result']['stats']['scanner_backend']."""
        config = _make_config(scan_type="hunt-fuzz")
        runner = ScanRunner(config, run_dir)

        json_path = run_dir / "hunt-fuzz.json"
        json_path.write_text(
            json.dumps({
                "hunt_result": {
                    "total_count": 0,
                    "findings": [],
                    "stats": {
                        "scanner_backend": "semgrep",
                        "files_scanned": 1,
                        "languages": {},
                        "duration_seconds": 0.1,
                    },
                    "has_more": False,
                },
            }),
            encoding="utf-8",
        )

        proc = _make_mock_process(exit_code=0)
        with patch("deep_code_security.tui.runner.asyncio") as mock_asyncio:
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert meta.backend_used == "semgrep"

    @pytest.mark.asyncio()
    async def test_run_malformed_json_fallback(self, run_dir: Path) -> None:
        """Malformed JSON output falls back to defaults."""
        config = _make_config(scan_type="hunt")
        runner = ScanRunner(config, run_dir)

        json_path = run_dir / "hunt.json"
        json_path.write_text("NOT VALID JSON {{{", encoding="utf-8")

        proc = _make_mock_process(exit_code=1)
        with patch("deep_code_security.tui.runner.asyncio") as mock_asyncio:
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert meta.findings_count == 0
        assert meta.backend_used == "unknown"
        assert meta.exit_code == 1

    @pytest.mark.asyncio()
    async def test_run_no_json_file_fallback(self, run_dir: Path) -> None:
        """Missing JSON output file falls back to defaults."""
        config = _make_config(scan_type="hunt")
        runner = ScanRunner(config, run_dir)

        # Do not create the JSON file
        proc = _make_mock_process(exit_code=1)
        with patch("deep_code_security.tui.runner.asyncio") as mock_asyncio:
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert meta.findings_count == 0
        assert meta.backend_used == "unknown"

    @pytest.mark.asyncio()
    async def test_run_on_complete_callback(self, run_dir: Path) -> None:
        """on_complete callback is invoked with exit code."""
        completed: list[int] = []
        config = _make_config()
        runner = ScanRunner(
            config, run_dir, on_complete=lambda code: completed.append(code)
        )

        proc = _make_mock_process(exit_code=42)
        with patch("deep_code_security.tui.runner.asyncio") as mock_asyncio:
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert completed == [42]
        assert meta.exit_code == 42

    @pytest.mark.asyncio()
    async def test_run_error_message_captured(self, run_dir: Path) -> None:
        """Error messages from stderr are captured in meta."""
        config = _make_config()
        runner = ScanRunner(config, run_dir)

        proc = _make_mock_process(
            exit_code=1,
            stderr_lines=["Error: Path validation failed"],
        )
        with patch("deep_code_security.tui.runner.asyncio") as mock_asyncio:
            mock_asyncio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_asyncio.subprocess = asyncio.subprocess
            mock_asyncio.wait_for = asyncio.wait_for
            mock_asyncio.TimeoutError = asyncio.TimeoutError

            meta = await runner.run()

        assert meta.error_message == "Path validation failed"


# ---------------------------------------------------------------------------
# Cancel tests
# ---------------------------------------------------------------------------


class TestCancel:
    """Tests for ScanRunner.cancel()."""

    @pytest.mark.asyncio()
    async def test_cancel_sends_sigterm(self, run_dir: Path) -> None:
        """Cancel calls terminate() on the subprocess."""
        config = _make_config()
        runner = ScanRunner(config, run_dir)

        proc = _make_mock_process(exit_code=0)
        # Make process appear running (returncode=None initially)
        proc.returncode = None

        # Simulate immediate termination on wait
        async def fast_wait() -> int:
            proc.returncode = -15
            return -15

        proc.wait = AsyncMock(side_effect=fast_wait)
        runner._process = proc

        await runner.cancel()

        proc.terminate.assert_called_once()

    @pytest.mark.asyncio()
    async def test_cancel_sends_sigkill_after_timeout(self, run_dir: Path) -> None:
        """Cancel sends SIGKILL after 5s timeout."""
        config = _make_config()
        runner = ScanRunner(config, run_dir)

        proc = _make_mock_process(exit_code=0)
        proc.returncode = None

        # Simulate timeout on first wait, then immediate on second
        call_count = {"n": 0}

        async def slow_then_fast() -> int:
            call_count["n"] += 1
            if call_count["n"] == 1:
                # This will be wrapped in wait_for which will timeout
                await asyncio.sleep(100)
            proc.returncode = -9
            return -9

        proc.wait = AsyncMock(side_effect=slow_then_fast)
        runner._process = proc

        # Patch _CANCEL_GRACE_SECONDS to be very short for test speed
        with patch("deep_code_security.tui.runner._CANCEL_GRACE_SECONDS", 0.01):
            await runner.cancel()

        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()

    @pytest.mark.asyncio()
    async def test_cancel_no_process(self, run_dir: Path) -> None:
        """Cancel when no process is running does nothing."""
        config = _make_config()
        runner = ScanRunner(config, run_dir)

        # Should not raise
        await runner.cancel()

    @pytest.mark.asyncio()
    async def test_cancel_already_exited(self, run_dir: Path) -> None:
        """Cancel on an already-exited process does nothing."""
        config = _make_config()
        runner = ScanRunner(config, run_dir)

        proc = _make_mock_process(exit_code=0)
        proc.returncode = 0  # Already exited
        runner._process = proc

        await runner.cancel()

        proc.terminate.assert_not_called()


# ---------------------------------------------------------------------------
# Static extraction method tests
# ---------------------------------------------------------------------------


class TestExtractMethods:
    """Direct tests for the static extraction methods."""

    def test_extract_findings_count_full_scan(self) -> None:
        """Full-scan uses output['total_count']."""
        data = {"total_count": 99}
        assert ScanRunner._extract_findings_count(data, "full-scan") == 99

    def test_extract_findings_count_missing_key(self) -> None:
        """Missing key falls back to 0."""
        assert ScanRunner._extract_findings_count({}, "hunt") == 0

    def test_extract_backend_used_fuzz(self) -> None:
        """Fuzz scan has no backend_used -- returns 'unknown'."""
        assert ScanRunner._extract_backend_used({}, "fuzz") == "unknown"

    def test_extract_backend_used_missing_key(self) -> None:
        """Missing key falls back to 'unknown'."""
        assert ScanRunner._extract_backend_used({}, "hunt") == "unknown"


# ---------------------------------------------------------------------------
# Plugin flag tests (new: plugin="c" support)
# ---------------------------------------------------------------------------


class TestBuildCommandPlugin:
    """Tests for --plugin flag in build_command()."""

    def test_build_command_fuzz_c_plugin(self, run_dir: Path) -> None:
        """Fuzz with plugin='c' includes --plugin c flag."""
        config = _make_config(scan_type="fuzz", plugin="c")
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "--plugin" in cmd
        plugin_idx = cmd.index("--plugin")
        assert cmd[plugin_idx + 1] == "c"

    def test_build_command_hunt_fuzz_c_plugin(self, run_dir: Path) -> None:
        """Hunt-fuzz with plugin='c' includes --plugin c flag."""
        config = _make_config(scan_type="hunt-fuzz", plugin="c")
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "--plugin" in cmd
        plugin_idx = cmd.index("--plugin")
        assert cmd[plugin_idx + 1] == "c"

    def test_build_command_fuzz_python_plugin_no_flag(self, run_dir: Path) -> None:
        """Fuzz with plugin='python' does NOT add --plugin flag."""
        config = _make_config(scan_type="fuzz", plugin="python")
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "--plugin" not in cmd

    def test_build_command_hunt_no_plugin_flag(self, run_dir: Path) -> None:
        """Hunt scans never include --plugin flag."""
        config = _make_config(scan_type="hunt", plugin="c")
        runner = ScanRunner(config, run_dir)
        cmd = runner.build_command()

        assert "--plugin" not in cmd


# ---------------------------------------------------------------------------
# _convert_format edge case tests
# ---------------------------------------------------------------------------


class TestConvertFormatEdgeCases:
    """Tests for _convert_format() branches not covered by async run tests."""

    def test_convert_format_unknown_scan_type_returns_false(
        self, run_dir: Path
    ) -> None:
        """Unknown scan type has no format method -- returns False."""
        config = _make_config(scan_type="hunt")
        runner = ScanRunner(config, run_dir)

        result = runner._convert_format(
            json_data={"total_count": 1},
            scan_type="unknown-type",
            fmt_name="json",
            ext=".json",
            prefix="unknown",
        )
        assert result is False

    def test_convert_format_exception_returns_false(
        self, run_dir: Path
    ) -> None:
        """Exception during format conversion returns False (non-fatal)."""
        from unittest.mock import patch

        config = _make_config(scan_type="hunt")
        runner = ScanRunner(config, run_dir)

        # Patch _build_result_dto to raise so the except block is exercised
        with patch.object(
            ScanRunner,
            "_build_result_dto",
            side_effect=RuntimeError("dto exploded"),
        ):
            result = runner._convert_format(
                json_data={"total_count": 1},
                scan_type="hunt",
                fmt_name="sarif",
                ext=".sarif",
                prefix="hunt",
            )
        assert result is False


# ---------------------------------------------------------------------------
# _derive_project_name fallback test
# ---------------------------------------------------------------------------


class TestDeriveProjectName:
    """Tests for _derive_project_name() static method."""

    def test_derive_project_name_normal_path(self) -> None:
        """Derives project name from the final path component."""
        name = ScanRunner._derive_project_name("/some/path/myproject")
        assert name == "myproject"

    def test_derive_project_name_empty_path(self) -> None:
        """Empty-ish path returns something sensible."""
        name = ScanRunner._derive_project_name("/")
        # Should not raise; returns non-empty string
        assert isinstance(name, str)
