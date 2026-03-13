"""Tests for the sandbox manager."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.auditor.sandbox import SandboxManager, SandboxUnavailableError


class TestSandboxManager:
    """Tests for SandboxManager."""

    def test_is_available_when_runtime_missing(self) -> None:
        """is_available() returns False when no runtime is found."""
        mgr = SandboxManager(container_runtime="podman")
        with patch("subprocess.run", side_effect=FileNotFoundError("not found")):
            result = mgr.is_available()
        assert result is False

    def test_is_available_caches_result(self) -> None:
        """is_available() caches the result after first check."""
        mgr = SandboxManager()
        mgr._available = False
        # Should return cached value without subprocess call
        result = mgr.is_available()
        assert result is False

    def test_get_runtime_auto_prefers_podman(self) -> None:
        """Auto-detection prefers podman over docker."""
        mgr = SandboxManager(container_runtime="auto")

        def mock_run(cmd, **kwargs):
            result = MagicMock()
            if cmd[0] == "podman":
                result.returncode = 0
            else:
                result.returncode = 1
            return result

        with patch("subprocess.run", side_effect=mock_run):
            runtime = mgr._get_runtime()
        assert runtime == "podman"

    def test_get_runtime_falls_back_to_docker(self) -> None:
        """Auto-detection falls back to docker if podman is missing."""
        mgr = SandboxManager(container_runtime="auto")

        def mock_run(cmd, **kwargs):
            result = MagicMock()
            if cmd[0] == "podman":
                raise FileNotFoundError("not found")
            elif cmd[0] == "docker":
                result.returncode = 0
            return result

        with patch("subprocess.run", side_effect=mock_run):
            runtime = mgr._get_runtime()
        assert runtime == "docker"

    def test_get_runtime_raises_when_none_found(self) -> None:
        """Raises SandboxUnavailableError when no runtime is found."""
        mgr = SandboxManager(container_runtime="auto")
        with patch("subprocess.run", side_effect=FileNotFoundError("not found")):
            with pytest.raises(SandboxUnavailableError):
                mgr._get_runtime()

    def test_build_run_command_includes_security_flags(self) -> None:
        """Container run command includes all required security flags."""
        mgr = SandboxManager()
        mgr._runtime_cmd = "docker"
        cmd = mgr._build_run_command(
            runtime="docker",
            image="test-image:latest",
            target_path="/tmp/target",
            poc_path="/tmp/exploit/poc.py",
            language="python",
            timeout=30,
        )
        cmd_str = " ".join(cmd)

        # Verify all required security flags
        assert "--network=none" in cmd_str, "Missing --network=none"
        assert "--read-only" in cmd_str, "Missing --read-only"
        assert "noexec" in cmd_str, "Missing noexec in tmpfs"
        assert "--cap-drop=ALL" in cmd_str, "Missing --cap-drop=ALL"
        assert "no-new-privileges" in cmd_str, "Missing no-new-privileges"
        assert "seccomp=" in cmd_str, "Missing seccomp profile"
        assert "--pids-limit=64" in cmd_str, "Missing --pids-limit"
        assert "--memory=512m" in cmd_str, "Missing --memory limit"
        assert "--user=65534:65534" in cmd_str, "Missing --user (non-root)"

    def test_build_run_command_mounts_target_readonly(self) -> None:
        """Target code is mounted read-only."""
        mgr = SandboxManager()
        mgr._runtime_cmd = "docker"
        cmd = mgr._build_run_command(
            runtime="docker",
            image="test-image:latest",
            target_path="/tmp/target",
            poc_path="/tmp/exploit/poc.py",
            language="python",
            timeout=30,
        )
        # Find the volume mount for target
        cmd_str = " ".join(cmd)
        assert "/target:ro" in cmd_str, "Target must be mounted read-only"

    def test_build_run_command_no_shell_true(self) -> None:
        """Command is a list (never shell=True)."""
        mgr = SandboxManager()
        mgr._runtime_cmd = "docker"
        cmd = mgr._build_run_command(
            runtime="docker",
            image="test-image:latest",
            target_path="/tmp/target",
            poc_path="/tmp/exploit/poc.py",
            language="python",
            timeout=30,
        )
        # Result must be a list of strings
        assert isinstance(cmd, list)
        assert all(isinstance(arg, str) for arg in cmd)

    def test_run_exploit_unavailable_raises(self) -> None:
        """run_exploit raises when sandbox is not available."""
        mgr = SandboxManager()
        mgr._available = False
        with pytest.raises(SandboxUnavailableError):
            mgr.run_exploit(
                language="python",
                target_path="/tmp",
                poc_script="print('hello')",
                timeout=5,
            )

    def test_semaphore_limits_concurrency(self) -> None:
        """Semaphore has correct max_concurrent value."""
        mgr = SandboxManager(max_concurrent=3)
        assert mgr._semaphore._value == 3

    def test_unknown_language_raises(self) -> None:
        """Unknown language raises ValueError."""
        mgr = SandboxManager()
        mgr._available = True
        mgr._runtime_cmd = "docker"
        with pytest.raises(ValueError, match="No sandbox image"):
            mgr.run_exploit(
                language="javascript",
                target_path="/tmp",
                poc_script="console.log('test')",
            )
