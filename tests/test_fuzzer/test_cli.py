"""Tests for fuzzer CLI commands."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from deep_code_security.cli import cli
from deep_code_security.shared.config import reset_config


class TestFuzzCommand:
    def test_fuzz_requires_consent(self, tmp_path: Path) -> None:
        """dcs fuzz without --consent exits with error."""
        target = tmp_path / "mod.py"
        target.write_text("def add(x, y):\n    return x + y\n")

        runner = CliRunner()
        with (
            patch.dict("os.environ", {"DCS_ALLOWED_PATHS": str(tmp_path)}),
            patch(
                "deep_code_security.fuzzer.consent.has_stored_consent",
                return_value=False,
            ),
        ):
            reset_config()
            result = runner.invoke(cli, ["fuzz", str(target)])
            reset_config()
        # Should fail because no consent flag and no stored consent
        assert result.exit_code != 0

    def test_fuzz_path_validation(self) -> None:
        """Invalid paths are rejected."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["fuzz", "/nonexistent/path/to/file.py", "--consent"]
        )
        assert result.exit_code != 0

    def test_fuzz_output_dir_write_validation(self, tmp_path: Path) -> None:
        """--output-dir inside protected directories is rejected."""
        target = tmp_path / "mod.py"
        target.write_text("def add(x, y):\n    return x + y\n")

        runner = CliRunner()
        # Try to write to src/ which is a protected directory
        with patch.dict("os.environ", {"DCS_ALLOWED_PATHS": str(tmp_path)}):
            reset_config()
            result = runner.invoke(
                cli,
                ["fuzz", str(target), "--consent", "--output-dir", "./src/output"],
            )
            reset_config()
        assert result.exit_code != 0

    def test_fuzz_F_flag(self) -> None:
        """Verify -F flag is accepted for --function."""
        runner = CliRunner()
        # Just verify it parses (won't succeed without valid target, but should not crash
        # on flag parsing)
        result = runner.invoke(
            cli, ["fuzz", "--help"]
        )
        assert "-F" in result.output
        assert "--function" in result.output

    def test_fuzz_format_flag(self) -> None:
        """Verify -f flag is accepted for --format."""
        runner = CliRunner()
        result = runner.invoke(cli, ["fuzz", "--help"])
        assert "-f" in result.output
        assert "--format" in result.output

    def test_fuzz_output_file_flag(self) -> None:
        """Verify -o flag is accepted for --output-file."""
        runner = CliRunner()
        result = runner.invoke(cli, ["fuzz", "--help"])
        assert "-o" in result.output
        assert "--output-file" in result.output


class TestReplayCommand:
    def test_replay_missing_corpus(self) -> None:
        """Replay with nonexistent corpus dir exits with error."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["replay", "/nonexistent/corpus", "--target", "/tmp/test.py"]
        )
        assert result.exit_code != 0
        assert "not found" in (result.output or "").lower() or result.exit_code != 0

    def test_replay_text(self, tmp_path: Path) -> None:
        """Replay command accepts --format text."""
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", "--help"])
        assert "--format" in result.output
        assert "--target" in result.output


class TestCorpusCommand:
    def test_corpus_missing_dir(self) -> None:
        """Corpus command with nonexistent dir exits with error."""
        runner = CliRunner()
        result = runner.invoke(cli, ["corpus", "/nonexistent/corpus"])
        assert result.exit_code != 0

    def test_corpus_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["corpus", "--help"])
        assert "--crashes-only" in result.output


class TestFuzzPluginsCommand:
    def test_fuzz_plugins_list(self) -> None:
        """Lists available plugins."""
        runner = CliRunner()
        with patch.dict("os.environ", {"DCS_FUZZ_ALLOWED_PLUGINS": "python"}):
            result = runner.invoke(cli, ["fuzz-plugins"])
            # Should either list python or say no plugins
            assert result.exit_code == 0


class TestReportCommand:
    def test_report_missing_dir(self) -> None:
        """Report with nonexistent dir exits with error."""
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "/nonexistent/output"])
        assert result.exit_code != 0

    def test_report_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--help"])
        assert "--format" in result.output


class TestStatusFuzzerInfo:
    def test_status_includes_fuzzer_info(self) -> None:
        """Status command includes fuzzer availability info."""
        runner = CliRunner()
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0
        assert "Anthropic SDK" in result.output
        assert "Fuzz consent" in result.output
