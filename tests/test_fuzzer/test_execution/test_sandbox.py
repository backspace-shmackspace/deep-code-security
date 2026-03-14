"""Tests for sandbox manager."""

from __future__ import annotations

import os

from deep_code_security.fuzzer.execution.sandbox import SandboxManager, SubprocessBackend


class TestSandboxManager:
    def test_create_and_cleanup_dir(self) -> None:
        sm = SandboxManager()
        tmp = sm.create_isolated_dir()
        assert os.path.isdir(tmp)
        sm.cleanup_dir(tmp)
        assert not os.path.exists(tmp)

    def test_run_command(self) -> None:
        sm = SandboxManager()
        returncode, stdout, stderr, tmp_dir = sm.run(
            ["echo", "hello"],
            timeout_seconds=5.0,
        )
        assert returncode == 0
        assert "hello" in stdout


class TestSubprocessBackend:
    def test_timeout(self) -> None:
        backend = SubprocessBackend()
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            returncode, stdout, stderr = backend.run(
                ["sleep", "10"],
                timeout_seconds=0.1,
                cwd=tmp,
            )
            assert returncode == -1
            assert stderr == "TIMEOUT"
