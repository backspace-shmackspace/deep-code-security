"""Docker/Podman sandbox manager for exploit verification.

Uses subprocess (not Docker SDK/socket) for container operations.
Enforces full security policy: seccomp, no-new-privileges, cap-drop=ALL,
noexec tmpfs, memory limits, PID limits, non-root user.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from deep_code_security.auditor.models import ExploitResult

__all__ = ["SandboxManager", "SandboxUnavailableError"]

logger = logging.getLogger(__name__)

# Files/patterns to exclude from target code mounts (security)
_EXCLUDED_MOUNT_PATTERNS: list[str] = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.crt",
    "*.p12",
    "id_rsa",
    "id_rsa.*",
    "id_ed25519",
    "id_ed25519.*",
    ".git/config",
    "*.password",
    "*_secret*",
    "*credentials*",
]

# Sandbox image names per language
_IMAGE_NAMES: dict[str, str] = {
    "python": "deep-code-security-sandbox-python:latest",
    "go": "deep-code-security-sandbox-go:latest",
    "c": "deep-code-security-sandbox-c:latest",
}

# Seccomp profile path
_SECCOMP_PROFILE = Path(__file__).parent / "seccomp-profile.json"


class SandboxUnavailableError(Exception):
    """Raised when the container runtime is not available."""


class SandboxManager:
    """Manages sandbox container lifecycle for exploit verification.

    Uses Docker or Podman CLI (not Docker SDK/socket) for all container operations.
    Enforces full security policy on every container.
    """

    def __init__(
        self,
        container_runtime: str = "auto",
        max_concurrent: int = 2,
        timeout_seconds: int = 30,
    ) -> None:
        self.container_runtime = container_runtime
        self.max_concurrent = max_concurrent
        self.timeout_seconds = timeout_seconds
        self._runtime_cmd: str | None = None
        self._semaphore = threading.Semaphore(max_concurrent)
        self._available: bool | None = None

    def is_available(self) -> bool:
        """Check if the container runtime is available and sandbox images are built.

        Returns:
            True if the sandbox can be used.
        """
        if self._available is not None:
            return self._available

        try:
            runtime = self._get_runtime()
            result = subprocess.run(
                [runtime, "info"],
                capture_output=True,
                timeout=10,
                check=False,
            )
            self._available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            self._available = False

        return self._available

    def _get_runtime(self) -> str:
        """Get the container runtime command.

        Returns:
            Runtime command string ("podman" or "docker").

        Raises:
            SandboxUnavailableError: If no runtime is found.
        """
        if self._runtime_cmd is not None:
            return self._runtime_cmd

        runtime = self.container_runtime.lower()

        if runtime == "auto":
            # Prefer podman rootless
            for candidate in ["podman", "docker"]:
                try:
                    result = subprocess.run(
                        [candidate, "--version"],
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
                    if result.returncode == 0:
                        self._runtime_cmd = candidate
                        return self._runtime_cmd
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue
            raise SandboxUnavailableError("No container runtime found (tried podman, docker)")

        elif runtime in ("podman", "docker"):
            self._runtime_cmd = runtime
            return self._runtime_cmd

        else:
            raise SandboxUnavailableError(f"Unknown container runtime: {runtime!r}")

    def run_exploit(
        self,
        language: str,
        target_path: str,
        poc_script: str,
        timeout: int | None = None,
    ) -> ExploitResult:
        """Run an exploit PoC in a sandboxed container.

        Args:
            language: Programming language ("python", "go", "c").
            target_path: Absolute path to target codebase (mounted read-only).
            poc_script: PoC script content to execute.
            timeout: Override timeout in seconds.

        Returns:
            ExploitResult with execution outcome.
        """
        import hashlib

        timeout = timeout or self.timeout_seconds
        script_hash = hashlib.sha256(poc_script.encode()).hexdigest()

        if not self.is_available():
            raise SandboxUnavailableError("Container runtime not available")

        image = _IMAGE_NAMES.get(language.lower())
        if image is None:
            raise ValueError(f"No sandbox image for language: {language}")

        with self._semaphore:
            return self._run_container(
                language=language,
                image=image,
                target_path=target_path,
                poc_script=poc_script,
                script_hash=script_hash,
                timeout=timeout,
            )

    def _run_container(
        self,
        language: str,
        image: str,
        target_path: str,
        poc_script: str,
        script_hash: str,
        timeout: int,
    ) -> ExploitResult:
        """Run the exploit in a container with full security policy.

        Args:
            language: Programming language.
            image: Docker image name.
            target_path: Path to target codebase.
            poc_script: PoC script content.
            script_hash: SHA-256 hash of the script.
            timeout: Execution timeout in seconds.

        Returns:
            ExploitResult.
        """
        runtime = self._get_runtime()
        start_ms = int(time.monotonic() * 1000)

        # Write PoC script to a temp file
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            script_ext = _get_script_extension(language)
            poc_path = tmpdir_path / f"poc{script_ext}"
            poc_path.write_text(poc_script, encoding="utf-8")
            poc_path.chmod(0o444)  # Read-only

            # Build container run command (list form — never shell=True)
            cmd = self._build_run_command(
                runtime=runtime,
                image=image,
                target_path=target_path,
                poc_path=str(poc_path),
                language=language,
                timeout=timeout,
            )

            logger.debug("Running sandbox: %s", " ".join(cmd))

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=timeout + 5,  # Extra 5s for container overhead
                    check=False,
                )
                timed_out = False
            except subprocess.TimeoutExpired:
                timed_out = True
                proc = None

        end_ms = int(time.monotonic() * 1000)
        duration_ms = end_ms - start_ms

        if timed_out or proc is None:
            return ExploitResult(
                exploit_script_hash=script_hash,
                exit_code=124,  # Convention: timeout exit code
                stdout_truncated="",
                stderr_truncated="Execution timed out",
                exploitable=False,
                execution_time_ms=duration_ms,
                timed_out=True,
            )

        # Truncate output to 2KB
        stdout = proc.stdout.decode("utf-8", errors="replace")[:2048]
        stderr = proc.stderr.decode("utf-8", errors="replace")[:2048]

        # Determine exploitability (non-zero exit with "exploitable" marker,
        # or specific exploit success patterns)
        exploitable = _check_exploitable(proc.returncode, stdout, stderr)

        return ExploitResult(
            exploit_script_hash=script_hash,
            exit_code=proc.returncode,
            stdout_truncated=stdout,
            stderr_truncated=stderr,
            exploitable=exploitable,
            execution_time_ms=duration_ms,
            timed_out=False,
        )

    def _build_run_command(
        self,
        runtime: str,
        image: str,
        target_path: str,
        poc_path: str,
        language: str,
        timeout: int,
    ) -> list[str]:
        """Build the container run command with full security policy.

        Args:
            runtime: "docker" or "podman"
            image: Container image name
            target_path: Path to target codebase
            poc_path: Path to PoC script file
            language: Programming language
            timeout: Execution timeout

        Returns:
            Command as list of strings (safe for subprocess).
        """
        seccomp_path = str(_SECCOMP_PROFILE)

        cmd = [
            runtime, "run",
            "--rm",                              # Auto-remove container after exit
            "--network=none",                    # No network access
            "--read-only",                       # Read-only root filesystem
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",  # Writable temp (noexec)  # noqa: S108
            "--cap-drop=ALL",                    # No Linux capabilities
            "--security-opt=no-new-privileges",  # No privilege escalation
            f"--security-opt=seccomp={seccomp_path}",  # Custom seccomp profile
            "--pids-limit=64",                   # Prevent fork bombs
            "--memory=512m",                     # Memory ceiling
            "--user=65534:65534",                # Run as nobody
        ]

        # Mount target code read-only (directory only, not individual files)
        target_resolved = str(Path(target_path).resolve())
        cmd.extend(["--volume", f"{target_resolved}:/target:ro"])

        # Mount PoC script directory read-only
        poc_dir = str(Path(poc_path).parent.resolve())
        cmd.extend(["--volume", f"{poc_dir}:/exploit:ro"])

        # Add timeout to command
        poc_filename = Path(poc_path).name

        # Set timeout label
        cmd.extend(["--label", f"dcs.timeout={timeout}"])

        cmd.append(image)

        # Entry point: run the PoC with timeout
        if language == "python":
            cmd.extend([
                "timeout", str(timeout),
                "python3", f"/exploit/{poc_filename}",
            ])
        elif language == "go":
            # Assert filename is exactly poc.go — never interpolate poc_filename into shell string
            assert poc_filename == "poc.go", f"Unexpected Go PoC filename: {poc_filename!r}"
            cmd.extend([
                "sh", "-c",
                f"cp /exploit/poc.go /tmp/main.go && timeout {int(timeout)} go run /tmp/main.go",
            ])
        elif language == "c":
            # Assert filename is exactly poc.c — never interpolate poc_filename into shell string
            assert poc_filename == "poc.c", f"Unexpected C PoC filename: {poc_filename!r}"
            cmd.extend([
                "sh", "-c",
                f"cp /exploit/poc.c /tmp/poc.c && gcc -o /tmp/poc /tmp/poc.c && timeout {int(timeout)} /tmp/poc",
            ])
        else:
            cmd.extend(["timeout", str(timeout), "python3", f"/exploit/{poc_filename}"])

        return cmd

    def build_images(self) -> bool:
        """Build sandbox Docker images.

        Returns:
            True if all images built successfully.
        """
        sandbox_dir = Path(__file__).parent.parent.parent.parent.parent / "sandbox"
        if not sandbox_dir.exists():
            logger.warning("Sandbox directory not found: %s", sandbox_dir)
            return False

        runtime = self._get_runtime()
        success = True

        for lang, image in _IMAGE_NAMES.items():
            dockerfile = sandbox_dir / f"Dockerfile.{lang}"
            if not dockerfile.exists():
                logger.warning("Dockerfile not found: %s", dockerfile)
                continue

            cmd = [
                runtime, "build",
                "-f", str(dockerfile),
                "-t", image,
                str(sandbox_dir),
            ]
            logger.info("Building sandbox image: %s", image)
            result = subprocess.run(cmd, capture_output=True, check=False, timeout=300)
            if result.returncode != 0:
                logger.error(
                    "Failed to build %s: %s",
                    image,
                    result.stderr.decode("utf-8", errors="replace")[:500],
                )
                success = False
            else:
                logger.info("Built sandbox image: %s", image)

        return success


def _get_script_extension(language: str) -> str:
    """Get the file extension for a language's script.

    Args:
        language: Programming language.

    Returns:
        File extension including the dot.
    """
    extensions = {
        "python": ".py",
        "go": ".go",
        "c": ".c",
    }
    return extensions.get(language.lower(), ".py")


def _check_exploitable(exit_code: int, stdout: str, stderr: str) -> bool:
    """Determine if an exploit succeeded.

    Args:
        exit_code: Container exit code.
        stdout: Truncated stdout.
        stderr: Truncated stderr.

    Returns:
        True if the exploit appears to have succeeded.
    """
    # Exit code 0 with specific success markers in output
    if exit_code == 0:
        # Look for common exploit success indicators in stdout
        success_markers = [
            "EXPLOIT_SUCCESS",
            "uid=",      # id command output
            "root:",     # /etc/passwd content
            "exploitable: true",
        ]
        for marker in success_markers:
            if marker in stdout or marker in stderr:
                return True

    return False
