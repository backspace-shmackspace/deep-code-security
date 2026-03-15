"""Execution isolation, rlimits, temp dirs, and process reaper.

Applies resource limits to sandboxed subprocess executions.
ContainerBackend uses Podman with full security policy (SD-01 resolved).
"""

from __future__ import annotations

import logging
import os
import platform
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Protocol

__all__ = [
    "ContainerBackend",
    "ExecutionBackend",
    "SandboxManager",
    "SubprocessBackend",
    "select_backend",
]

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
        cwd: str = "",
        env: dict[str, str] | None = None,
        **kwargs: Any,
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
        **kwargs: Any,
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
    """Podman-based container execution backend with full security policy.

    Resolves Security Deviation SD-01: MCP-triggered fuzz runs now use
    this container backend exclusively, providing proper sandboxing
    beyond what rlimits alone can offer.

    Security flags enforced on every run:
    - --network=none          (no outbound network)
    - --read-only             (immutable root filesystem)
    - --tmpfs /tmp            (noexec, nosuid writable scratch space)
    - --cap-drop=ALL          (no Linux capabilities)
    - --security-opt=no-new-privileges
    - --security-opt seccomp=<fuzzer-specific profile>
    - --pids-limit            (limit fork bomb potential)
    - --memory                (cgroup memory cap)
    - --cpus                  (CPU quota)
    - --user=65534:65534      (nobody:nogroup)
    - --rm                    (ephemeral container destroyed on exit)
    """

    # Env is fully isolated: host environment variables are never forwarded
    # to the container. The container image sets only PYTHONPATH,
    # PYTHONDONTWRITEBYTECODE, and PYTHONSAFEPATH.
    _ALLOWED_ENV_KEYS: frozenset[str] = frozenset()

    def __init__(
        self,
        runtime_cmd: list[str] | None = None,
        image: str | None = None,
        seccomp_profile: str | None = None,
        memory_limit: str = "512m",
        pids_limit: int = 64,
        cpus: float = 1.0,
        tmpfs_size: str = "64m",
    ) -> None:
        from deep_code_security.shared.config import get_config

        config = get_config()

        if runtime_cmd is not None:
            self._runtime_cmd = runtime_cmd
        else:
            self._runtime_cmd = ["podman"]

        self._image = image or config.fuzz_container_image
        self._memory_limit = memory_limit
        self._pids_limit = pids_limit
        self._cpus = cpus
        self._tmpfs_size = tmpfs_size

        # Resolve seccomp profile path relative to this source file
        if seccomp_profile is not None:
            self._seccomp_profile = seccomp_profile
        else:
            profile_path = (
                Path(__file__).resolve().parents[4] / "sandbox" / "seccomp-fuzz-python.json"
            )
            self._seccomp_profile = str(profile_path)

    @classmethod
    def is_available(cls) -> bool:
        """Return True if Podman is installed and the worker image exists.

        Checks both `podman version` (CLI available) and
        `podman image inspect <image>` (image built) so that the tool
        is not registered unless it's fully usable.
        """
        from deep_code_security.shared.config import get_config

        config = get_config()
        image = config.fuzz_container_image

        try:
            result = subprocess.run(
                ["podman", "version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return False
        except Exception:
            return False

        try:
            result = subprocess.run(
                ["podman", "image", "inspect", image],
                capture_output=True,
                text=True,
                timeout=15,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _build_podman_cmd(
        self,
        target_file: str,
        ipc_dir: str | None,
        timeout_seconds: float,
        run_id: str,
    ) -> list[str]:
        """Build the full podman run command with all required security flags.

        Args:
            target_file: Absolute host path to the Python file being fuzzed.
                Mounted read-only at /target/<basename> inside the container.
            ipc_dir: Host-side directory for JSON IPC. Mounted at /workspace
                inside the container with noexec,nosuid. May be None.
            timeout_seconds: Per-run wall-clock timeout passed to --timeout.
            run_id: UUID string used as the audit label for orphan cleanup.

        Returns:
            List of command tokens ready for subprocess.run().
        """
        target_path = Path(target_file).resolve()
        target_basename = target_path.name

        podman_cmd: list[str] = [
            *self._runtime_cmd,
            "run",
            "--rm",
            # Network isolation
            "--network=none",
            # Read-only root filesystem
            "--read-only",
            # Writable scratch space: noexec, nosuid
            f"--tmpfs=/tmp:rw,noexec,nosuid,size={self._tmpfs_size}",
            # Drop ALL capabilities
            "--cap-drop=ALL",
            # No privilege escalation via setuid/setgid
            "--security-opt=no-new-privileges",
            # Fuzzer-specific seccomp profile
            f"--security-opt=seccomp={self._seccomp_profile}",
            # PID limit (block fork bombs)
            f"--pids-limit={self._pids_limit}",
            # Memory cgroup limit
            f"--memory={self._memory_limit}",
            # CPU quota
            f"--cpus={self._cpus}",
            # Run as nobody:nogroup
            "--user=65534:65534",
            # Wall-clock timeout
            f"--timeout={int(timeout_seconds)}",
            # Audit label for cleanup
            f"--label=dcs.fuzz_run_id={run_id}",
            # Mount the target file read-only
            f"--volume={target_file}:/target/{target_basename}:ro",
        ]

        # Mount the IPC directory at /workspace inside the container.
        # noexec,nosuid prevent a malicious fuzz target from planting an
        # executable or setuid binary in the shared IPC directory.
        if ipc_dir:
            podman_cmd.append(f"--volume={ipc_dir}:/workspace:rw,noexec,nosuid")

        podman_cmd.append(self._image)

        return podman_cmd

    def run(
        self,
        cmd: list[str],
        timeout_seconds: float,
        cwd: str = "",
        env: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> tuple[int, str, str]:
        """Execute the worker in a Podman container with full security policy.

        Args:
            cmd: Ignored. The container image's ENTRYPOINT is used instead.
                 The input/output JSON paths are written into the container's
                 /workspace mount by this method via a temp dir mount.
            timeout_seconds: Per-run wall-clock timeout passed to --timeout.
            cwd: Ignored. The container has its own working directory.
            env: Ignored. The container runs with an isolated environment;
                 host env vars are never forwarded (see _ALLOWED_ENV_KEYS).
            **kwargs:
                target_file (str): Absolute host path to the Python file being
                    fuzzed. Mounted read-only at /target/<basename> inside the
                    container. Required.
                input_json (str): Host-side path to input.json in ipc_dir.
                output_json (str): Host-side path to output.json in ipc_dir.
                ipc_dir (str): Host-side IPC directory, mounted at /workspace.

        Returns:
            (returncode, stdout, stderr) tuple.
        """
        # cmd is ignored by ContainerBackend — the container image's fixed
        # ENTRYPOINT is used instead. This comment documents the intentional
        # deviation from the ExecutionBackend protocol for clarity.
        target_file: str | None = kwargs.get("target_file")
        input_json: str | None = kwargs.get("input_json")
        output_json: str | None = kwargs.get("output_json")
        ipc_dir: str | None = kwargs.get("ipc_dir")

        if not target_file:
            return -1, "", "ContainerBackend.run() requires target_file kwarg"

        # Build the unique run ID for audit tracing
        run_id = str(uuid.uuid4())

        podman_cmd = self._build_podman_cmd(
            target_file=target_file,
            ipc_dir=ipc_dir,
            timeout_seconds=timeout_seconds,
            run_id=run_id,
        )

        # Worker arguments: the fixed _worker.py entrypoint receives
        # <input_json_path> <output_json_path> as positional args.
        # The IPC dir is mounted at /workspace inside the container, so
        # we translate the host-side paths to container-side /workspace/ paths.
        if input_json and output_json:
            container_input_json = "/workspace/" + Path(input_json).name
            container_output_json = "/workspace/" + Path(output_json).name
            podman_cmd.extend([container_input_json, container_output_json])

        logger.debug("ContainerBackend: running %s", " ".join(podman_cmd))

        try:
            proc = subprocess.run(
                podman_cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 5,  # small buffer beyond container --timeout
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "TIMEOUT"
        except Exception as e:
            return -1, "", str(e)


def select_backend(require_container: bool = False) -> SubprocessBackend | ContainerBackend:
    """Return the best available execution backend.

    Args:
        require_container: If True, raise RuntimeError when the container
            backend is not available (Podman not found or image not built).
            CLI callers pass False (default); MCP callers pass True.

    Returns:
        ContainerBackend if Podman + image are available, else SubprocessBackend.

    Raises:
        RuntimeError: When require_container=True and ContainerBackend is not
            available.
    """
    if ContainerBackend.is_available():
        logger.debug("select_backend: ContainerBackend available — using it")
        return ContainerBackend()

    if require_container:
        raise RuntimeError(
            "ContainerBackend is required but not available. "
            "Ensure Podman is installed and run 'make build-fuzz-sandbox' to build the "
            "worker image (dcs-fuzz-python:latest)."
        )

    logger.debug("select_backend: ContainerBackend unavailable — falling back to SubprocessBackend")
    return SubprocessBackend()


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
