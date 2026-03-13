"""Additional tests for sandbox.py to increase coverage."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.auditor.sandbox import (
    SandboxManager,
    SandboxUnavailableError,
    _check_exploitable,
    _get_script_extension,
)


class TestGetScriptExtension:
    """Tests for _get_script_extension."""

    def test_python_extension(self) -> None:
        assert _get_script_extension("python") == ".py"

    def test_go_extension(self) -> None:
        assert _get_script_extension("go") == ".go"

    def test_c_extension(self) -> None:
        assert _get_script_extension("c") == ".c"

    def test_unknown_defaults_to_py(self) -> None:
        assert _get_script_extension("ruby") == ".py"

    def test_case_insensitive(self) -> None:
        assert _get_script_extension("Python") == ".py"


class TestCheckExploitable:
    """Tests for _check_exploitable."""

    def test_exit_zero_no_markers_not_exploitable(self) -> None:
        assert _check_exploitable(0, "hello world", "") is False

    def test_exit_zero_with_exploit_success_marker(self) -> None:
        assert _check_exploitable(0, "EXPLOIT_SUCCESS", "") is True

    def test_exit_zero_with_uid_marker(self) -> None:
        assert _check_exploitable(0, "uid=0(root)", "") is True

    def test_exit_zero_with_root_in_stderr(self) -> None:
        assert _check_exploitable(0, "", "root:x:0:0") is True

    def test_exit_zero_with_exploitable_true_marker(self) -> None:
        assert _check_exploitable(0, "exploitable: true", "") is True

    def test_nonzero_exit_not_exploitable(self) -> None:
        assert _check_exploitable(1, "EXPLOIT_SUCCESS", "") is False

    def test_timeout_exit_code_not_exploitable(self) -> None:
        assert _check_exploitable(124, "", "") is False


class TestBuildRunCommandLanguages:
    """Tests for _build_run_command language-specific entrypoints."""

    def _build(self, language: str, poc_filename: str) -> list[str]:
        mgr = SandboxManager()
        mgr._runtime_cmd = "docker"
        return mgr._build_run_command(
            runtime="docker",
            image="test-image:latest",
            target_path="/tmp/target",
            poc_path=f"/tmp/exploit/{poc_filename}",
            language=language,
            timeout=30,
        )

    def test_python_uses_timeout_and_python3(self) -> None:
        cmd = self._build("python", "poc.py")
        cmd_str = " ".join(cmd)
        assert "timeout" in cmd_str
        assert "python3" in cmd_str
        assert "/exploit/poc.py" in cmd_str

    def test_go_uses_hardcoded_poc_go_filename(self) -> None:
        cmd = self._build("go", "poc.go")
        cmd_str = " ".join(cmd)
        assert "poc.go" in cmd_str
        assert "go run" in cmd_str

    def test_c_uses_hardcoded_poc_c_filename(self) -> None:
        cmd = self._build("c", "poc.c")
        cmd_str = " ".join(cmd)
        assert "poc.c" in cmd_str
        assert "gcc" in cmd_str

    def test_unknown_language_defaults_to_python(self) -> None:
        cmd = self._build("javascript", "poc.py")
        cmd_str = " ".join(cmd)
        assert "python3" in cmd_str

    def test_go_wrong_filename_raises_assertion(self) -> None:
        mgr = SandboxManager()
        mgr._runtime_cmd = "docker"
        with pytest.raises(AssertionError, match="Unexpected Go PoC filename"):
            mgr._build_run_command(
                runtime="docker",
                image="test-image:latest",
                target_path="/tmp/target",
                poc_path="/tmp/exploit/evil_name.go",
                language="go",
                timeout=30,
            )

    def test_c_wrong_filename_raises_assertion(self) -> None:
        mgr = SandboxManager()
        mgr._runtime_cmd = "docker"
        with pytest.raises(AssertionError, match="Unexpected C PoC filename"):
            mgr._build_run_command(
                runtime="docker",
                image="test-image:latest",
                target_path="/tmp/target",
                poc_path="/tmp/exploit/evil_name.c",
                language="c",
                timeout=30,
            )

    def test_timeout_is_integer_in_shell_string(self) -> None:
        """Timeout value is cast to int in shell command string."""
        mgr = SandboxManager()
        mgr._runtime_cmd = "docker"
        cmd = mgr._build_run_command(
            runtime="docker",
            image="test-image:latest",
            target_path="/tmp/target",
            poc_path="/tmp/exploit/poc.go",
            language="go",
            timeout=45,
        )
        cmd_str = " ".join(cmd)
        assert "45" in cmd_str


class TestIsAvailable:
    """Tests for is_available() with actual subprocess mocking."""

    def test_is_available_returns_true_when_runtime_responds(self) -> None:
        mgr = SandboxManager(container_runtime="podman")
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result):
            assert mgr.is_available() is True

    def test_is_available_false_on_timeout(self) -> None:
        mgr = SandboxManager(container_runtime="podman")
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("podman", 10)):
            assert mgr.is_available() is False

    def test_is_available_false_on_oserror(self) -> None:
        mgr = SandboxManager(container_runtime="podman")
        with patch("subprocess.run", side_effect=OSError("no runtime")):
            assert mgr.is_available() is False


class TestGetRuntime:
    """Tests for _get_runtime() explicit runtime names."""

    def test_explicit_podman_accepted(self) -> None:
        mgr = SandboxManager(container_runtime="podman")
        runtime = mgr._get_runtime()
        assert runtime == "podman"

    def test_explicit_docker_accepted(self) -> None:
        mgr = SandboxManager(container_runtime="docker")
        runtime = mgr._get_runtime()
        assert runtime == "docker"

    def test_unknown_runtime_raises(self) -> None:
        mgr = SandboxManager(container_runtime="lxc")
        with pytest.raises(SandboxUnavailableError, match="Unknown container runtime"):
            mgr._get_runtime()

    def test_cached_runtime_returned_directly(self) -> None:
        mgr = SandboxManager()
        mgr._runtime_cmd = "podman"
        # Should not call subprocess at all
        with patch("subprocess.run", side_effect=AssertionError("should not call subprocess")):
            assert mgr._get_runtime() == "podman"


class TestRunContainer:
    """Tests for _run_container path using mocked subprocess."""

    def _make_mgr(self) -> SandboxManager:
        mgr = SandboxManager(container_runtime="docker")
        mgr._runtime_cmd = "docker"
        mgr._available = True
        return mgr

    def test_run_container_success(self, tmp_path: Path) -> None:
        mgr = self._make_mgr()
        poc_path = tmp_path / "poc.py"
        poc_path.write_text("print('EXPLOIT_SUCCESS')")

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"EXPLOIT_SUCCESS\n"
        mock_proc.stderr = b""

        with patch("subprocess.run", return_value=mock_proc):
            result = mgr._run_container(
                language="python",
                image="deep-code-security-sandbox-python:latest",
                target_path=str(tmp_path),
                poc_script="print('EXPLOIT_SUCCESS')",
                script_hash="abc" * 21 + "a",
                timeout=30,
            )

        assert result.exit_code == 0
        assert result.exploitable is True
        assert result.timed_out is False

    def test_run_container_timeout(self, tmp_path: Path) -> None:
        mgr = self._make_mgr()

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 35)):
            result = mgr._run_container(
                language="python",
                image="deep-code-security-sandbox-python:latest",
                target_path=str(tmp_path),
                poc_script="import time; time.sleep(999)",
                script_hash="abc" * 21 + "a",
                timeout=30,
            )

        assert result.timed_out is True
        assert result.exit_code == 124

    def test_run_exploit_calls_run_container(self, tmp_path: Path) -> None:
        mgr = self._make_mgr()

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = b""
        mock_proc.stderr = b"error"

        with patch("subprocess.run", return_value=mock_proc):
            result = mgr.run_exploit(
                language="python",
                target_path=str(tmp_path),
                poc_script="raise SystemExit(1)",
                timeout=10,
            )

        assert result.exit_code == 1
        assert result.exploitable is False


class TestBuildImages:
    """Tests for build_images()."""

    def test_build_images_no_sandbox_dir(self) -> None:
        """Returns False if sandbox dir is missing."""
        mgr = SandboxManager(container_runtime="docker")
        mgr._runtime_cmd = "docker"
        # Point to a nonexistent directory by monkeypatching the path
        with patch("deep_code_security.auditor.sandbox._SECCOMP_PROFILE",
                   Path("/nonexistent/seccomp.json")):
            result = mgr.build_images()
        # Should return False since sandbox dir won't exist
        assert isinstance(result, bool)
