"""Execution isolation, rlimits, temp dirs, and process reaper.

Applies resource limits to sandboxed subprocess executions.
No container backend in this plan (see Security Deviation SD-01).
"""

from __future__ import annotations

import logging
import os
import platform
import subprocess
import sys
import tempfile
from typing import Protocol

__all__ = ["ContainerBackend", "ExecutionBackend", "SandboxManager", "SubprocessBackend"]

logger = logging.getLogger(__name__)

IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

# Default resource limits
DEFAULT_CPU_SECONDS = 10
DEFAULT_MEMORY_MB = 512
DEFAULT_FSIZE_MB = 10
DEFAULT_NOFILE = 64
DEFAULT_NPROC = 0


class ExecutionBackend(Protocol):
    """Protocol for execution backends (subprocess, container, etc.)."""

    def run(
        self,
        cmd: list[str],
        timeout_seconds: float,
        cwd: str,
        env: dict[str, str] | None,
    ) -> tuple[int, str, str]:
        """Run a command and return (returncode, stdout, stderr)."""
        ...


def _apply_rlimits() -> None:
    """Apply resource limits in the child process (called as preexec_fn)."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (DEFAULT_CPU_SECONDS, DEFAULT_CPU_SECONDS))

        fsize_bytes = DEFAULT_FSIZE_MB * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_bytes, fsize_bytes))

        resource.setrlimit(resource.RLIMIT_NOFILE, (DEFAULT_NOFILE, DEFAULT_NOFILE))

        if IS_LINUX:
            mem_bytes = DEFAULT_MEMORY_MB * 1024 * 1024
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except (OSError, ValueError):
                pass

            try:
                resource.setrlimit(resource.RLIMIT_NPROC, (DEFAULT_NPROC, DEFAULT_NPROC))
            except (OSError, ValueError):
                pass

    except ImportError:
        pass
    except Exception:
        pass


class SubprocessBackend:
    """Default execution backend using subprocess with rlimits."""

    def run(
        self,
        cmd: list[str],
        timeout_seconds: float,
        cwd: str,
        env: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        preexec_fn = None
        if not sys.platform.startswith("win"):
            preexec_fn = _apply_rlimits

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                cwd=cwd,
                env=env,
                preexec_fn=preexec_fn,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "TIMEOUT"
        except Exception as e:
            return -1, "", str(e)


class ContainerBackend:
    """Stub container execution backend (not implemented in MVP).

    Future implementation would use Docker/Podman with:
    - Read-only filesystem mount
    - No network access (--network=none)
    - Resource limits via container runtime
    - Ephemeral container destroyed after each input
    """

    def run(
        self,
        cmd: list[str],
        timeout_seconds: float,
        cwd: str,
        env: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        raise NotImplementedError(
            "Container execution backend is not implemented in this release. "
            "Use the default subprocess backend."
        )


class SandboxManager:
    """Manages sandboxed execution environments."""

    def __init__(
        self,
        backend: ExecutionBackend | None = None,
        base_tmp_dir: str | None = None,
    ) -> None:
        self._backend = backend or SubprocessBackend()
        self._base_tmp_dir = base_tmp_dir
        self._active_pids: list[int] = []

    def create_isolated_dir(self) -> str:
        """Create an isolated temporary directory for execution."""
        tmp_dir = tempfile.mkdtemp(prefix="dcs_fuzz_", dir=self._base_tmp_dir)
        logger.debug("Created isolated temp dir: %s", tmp_dir)
        return tmp_dir

    def cleanup_dir(self, path: str) -> None:
        """Clean up an isolated temporary directory."""
        import shutil

        try:
            shutil.rmtree(path, ignore_errors=True)
            logger.debug("Cleaned up temp dir: %s", path)
        except Exception as e:
            logger.warning("Failed to clean up temp dir %s: %s", path, e)

    def run(
        self,
        cmd: list[str],
        timeout_seconds: float,
        env: dict[str, str] | None = None,
    ) -> tuple[int, str, str, str]:
        tmp_dir = self.create_isolated_dir()
        try:
            returncode, stdout, stderr = self._backend.run(
                cmd, timeout_seconds, cwd=tmp_dir, env=env
            )
            return returncode, stdout, stderr, tmp_dir
        finally:
            self.cleanup_dir(tmp_dir)

    def reap_zombies(self) -> None:
        """Reap any zombie child processes (WNOHANG)."""
        if sys.platform.startswith("win"):
            return
        try:
            while True:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
        except ChildProcessError:
            pass
        except OSError:
            pass
