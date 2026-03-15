"""Unit tests for ContainerBackend.

Tests all security flags are present in the podman command and that the
backend never uses shell=True or forwards host environment variables.
"""

from __future__ import annotations

import importlib
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from deep_code_security.fuzzer.exceptions import ExecutionError
from deep_code_security.fuzzer.execution.sandbox import ContainerBackend, SubprocessBackend


@pytest.fixture()
def backend() -> ContainerBackend:
    """Return a ContainerBackend with a known test image."""
    return ContainerBackend(
        runtime_cmd=["podman"],
        image="dcs-fuzz-python:latest",
        memory_limit="512m",
        pids_limit=64,
        cpus=1.0,
        tmpfs_size="64m",
    )


def _capture_podman_cmd(
    backend: ContainerBackend,
    target_file: str,
    ipc_dir: str | None = None,
) -> list[str]:
    """Run backend.run() with a mock subprocess and capture the built command."""
    captured: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs) -> MagicMock:
        captured.append(cmd)
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""
        return result

    run_kwargs: dict = dict(
        cmd=["python", "-m", "some.module"],
        timeout_seconds=10.0,
        cwd="/tmp",
        env={"SECRET": "should-not-appear"},
        target_file=target_file,
        input_json="/tmp/ipc/input.json",
        output_json="/tmp/ipc/output.json",
    )
    if ipc_dir is not None:
        run_kwargs["ipc_dir"] = ipc_dir

    with patch("subprocess.run", side_effect=fake_run):
        backend.run(**run_kwargs)

    assert len(captured) == 1, "Expected exactly one subprocess.run call"
    return captured[0]


def test_run_builds_correct_podman_command(backend: ContainerBackend, tmp_path: Path) -> None:
    """The podman command must include all required security flags."""
    target = str(tmp_path / "target.py")
    (tmp_path / "target.py").write_text("def f(): pass")
    cmd = _capture_podman_cmd(backend, target)

    assert cmd[0] == "podman"
    assert "run" in cmd
    assert "--network=none" in cmd
    assert "--read-only" in cmd
    assert "--cap-drop=ALL" in cmd
    assert "--security-opt=no-new-privileges" in cmd
    assert "--rm" in cmd
    assert "--user=65534:65534" in cmd


def test_run_includes_network_none(backend: ContainerBackend, tmp_path: Path) -> None:
    target = str(tmp_path / "target.py")
    (tmp_path / "target.py").write_text("")
    cmd = _capture_podman_cmd(backend, target)
    assert "--network=none" in cmd


def test_run_includes_read_only(backend: ContainerBackend, tmp_path: Path) -> None:
    target = str(tmp_path / "target.py")
    (tmp_path / "target.py").write_text("")
    cmd = _capture_podman_cmd(backend, target)
    assert "--read-only" in cmd


def test_run_includes_cap_drop_all(backend: ContainerBackend, tmp_path: Path) -> None:
    target = str(tmp_path / "target.py")
    (tmp_path / "target.py").write_text("")
    cmd = _capture_podman_cmd(backend, target)
    assert "--cap-drop=ALL" in cmd


def test_run_includes_no_new_privileges(backend: ContainerBackend, tmp_path: Path) -> None:
    target = str(tmp_path / "target.py")
    (tmp_path / "target.py").write_text("")
    cmd = _capture_podman_cmd(backend, target)
    assert "--security-opt=no-new-privileges" in cmd


def test_run_includes_pids_limit(backend: ContainerBackend, tmp_path: Path) -> None:
    target = str(tmp_path / "target.py")
    (tmp_path / "target.py").write_text("")
    cmd = _capture_podman_cmd(backend, target)
    assert "--pids-limit=64" in cmd


def test_run_includes_memory_limit(backend: ContainerBackend, tmp_path: Path) -> None:
    target = str(tmp_path / "target.py")
    (tmp_path / "target.py").write_text("")
    cmd = _capture_podman_cmd(backend, target)
    assert "--memory=512m" in cmd


def test_run_includes_cpus(backend: ContainerBackend, tmp_path: Path) -> None:
    target = str(tmp_path / "target.py")
    (tmp_path / "target.py").write_text("")
    cmd = _capture_podman_cmd(backend, target)
    assert "--cpus=1.0" in cmd


def test_run_includes_user_nobody(backend: ContainerBackend, tmp_path: Path) -> None:
    target = str(tmp_path / "target.py")
    (tmp_path / "target.py").write_text("")
    cmd = _capture_podman_cmd(backend, target)
    assert "--user=65534:65534" in cmd


def test_run_ignores_env_parameter(backend: ContainerBackend, tmp_path: Path) -> None:
    """Host env vars must NOT appear in the podman command as --env flags."""
    target = str(tmp_path / "target.py")
    (tmp_path / "target.py").write_text("")
    cmd = _capture_podman_cmd(backend, target)

    env_flags = [arg for arg in cmd if arg.startswith("--env") or arg.startswith("-e")]
    assert not env_flags, f"Found unexpected --env flags: {env_flags}"

    # Specifically check that SECRET doesn't leak
    full_cmd_str = " ".join(cmd)
    assert "should-not-appear" not in full_cmd_str


def test_run_ignores_cmd_parameter(backend: ContainerBackend, tmp_path: Path) -> None:
    """The cmd list passed to run() must NOT be forwarded as the container command."""
    target = str(tmp_path / "target.py")
    (tmp_path / "target.py").write_text("")
    cmd = _capture_podman_cmd(backend, target)

    # "some.module" comes from the cmd arg we passed, which should not appear
    # (the container uses its fixed ENTRYPOINT, not the cmd argument)
    assert "some.module" not in cmd


def test_run_mounts_single_file_only(backend: ContainerBackend, tmp_path: Path) -> None:
    """Only the target file is mounted; the parent directory is NOT mounted."""
    target_file = tmp_path / "target.py"
    target_file.write_text("")
    sibling = tmp_path / "sibling_secret.py"
    sibling.write_text("")

    cmd = _capture_podman_cmd(backend, str(target_file))

    volume_flags = [arg for arg in cmd if arg.startswith("--volume=")]
    # Ensure only target file is mounted (not the whole parent directory)
    for flag in volume_flags:
        source = flag.split("=", 1)[1].split(":")[0]
        # The source must be the exact target file, not the parent directory
        assert source != str(tmp_path), (
            f"Parent directory was mounted: {flag}. Only the target file should be mounted."
        )

    # Verify the target file IS in a volume mount
    target_str = str(target_file.resolve())
    assert any(target_str in flag for flag in volume_flags), (
        f"Target file {target_str} not found in volume mounts: {volume_flags}"
    )


def test_is_available_true() -> None:
    """is_available() returns True when both podman version and image inspect succeed."""
    mock_result = MagicMock()
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result):
        assert ContainerBackend.is_available() is True


def test_is_available_false_no_podman() -> None:
    """is_available() returns False when podman version fails (Podman not installed)."""

    def fail_on_version(cmd: list[str], **kwargs) -> MagicMock:
        if "version" in cmd:
            result = MagicMock()
            result.returncode = 1
            return result
        result = MagicMock()
        result.returncode = 0
        return result

    with patch("subprocess.run", side_effect=fail_on_version):
        assert ContainerBackend.is_available() is False


def test_is_available_false_no_image() -> None:
    """is_available() returns False when podman version works but image inspect fails."""
    call_count = [0]

    def version_ok_image_fail(cmd: list[str], **kwargs) -> MagicMock:
        call_count[0] += 1
        result = MagicMock()
        # First call: podman version -> success
        # Second call: podman image inspect -> failure
        result.returncode = 0 if call_count[0] == 1 else 1
        return result

    with patch("subprocess.run", side_effect=version_ok_image_fail):
        assert ContainerBackend.is_available() is False


def test_no_shell_true() -> None:
    """The sandbox module must never use shell=True in any subprocess call."""
    import deep_code_security.fuzzer.execution.sandbox as sandbox_module
    import inspect

    source = inspect.getsource(sandbox_module)
    # Look for shell=True patterns
    assert "shell=True" not in source, (
        "Found 'shell=True' in sandbox.py — all subprocess calls must use list-form args"
    )


def test_ipc_mount_uses_workspace_with_security_options(
    backend: ContainerBackend, tmp_path: Path
) -> None:
    """IPC dir must be mounted at /workspace with noexec,nosuid options."""
    target = str(tmp_path / "target.py")
    (tmp_path / "target.py").write_text("def f(): pass")
    ipc_dir = str(tmp_path / "ipc")

    cmd = _capture_podman_cmd(backend, target, ipc_dir=ipc_dir)

    volume_flags = [arg for arg in cmd if arg.startswith("--volume=")]
    ipc_flags = [f for f in volume_flags if "/workspace" in f]

    assert ipc_flags, "Expected an IPC volume mount at /workspace but found none"
    ipc_flag = ipc_flags[0]
    # Must use /workspace as the container-side mount point
    assert ":/workspace:" in ipc_flag, (
        f"IPC mount must use /workspace as container-side path, got: {ipc_flag}"
    )
    # Must include noexec and nosuid mount options
    assert "noexec" in ipc_flag, f"IPC mount missing noexec option: {ipc_flag}"
    assert "nosuid" in ipc_flag, f"IPC mount missing nosuid option: {ipc_flag}"
    # Must NOT use the old /ipc path
    assert ":/ipc:" not in ipc_flag, f"IPC mount must not use /ipc path: {ipc_flag}"


def test_ipc_worker_args_use_container_side_paths(
    backend: ContainerBackend, tmp_path: Path
) -> None:
    """Worker positional args must be /workspace/input.json and /workspace/output.json."""
    target = str(tmp_path / "target.py")
    (tmp_path / "target.py").write_text("def f(): pass")
    ipc_dir = str(tmp_path / "ipc")

    cmd = _capture_podman_cmd(backend, target, ipc_dir=ipc_dir)

    # The container args come after the image name
    image = "dcs-fuzz-python:latest"
    try:
        image_idx = cmd.index(image)
    except ValueError:
        pytest.fail(f"Image {image!r} not found in command: {cmd}")

    worker_args = cmd[image_idx + 1:]
    assert len(worker_args) == 2, (
        f"Expected 2 worker args after image, got {len(worker_args)}: {worker_args}"
    )
    assert worker_args[0] == "/workspace/input.json", (
        f"Expected /workspace/input.json, got {worker_args[0]!r}"
    )
    assert worker_args[1] == "/workspace/output.json", (
        f"Expected /workspace/output.json, got {worker_args[1]!r}"
    )
    # Confirm host-side paths do not appear as worker args
    assert not any("/tmp/ipc" in arg for arg in worker_args), (
        f"Host-side IPC path leaked into worker args: {worker_args}"
    )


def test_output_json_symlink_rejected(backend: ContainerBackend, tmp_path: Path) -> None:
    """FuzzRunner must reject output.json if it is a symlink (symlink attack prevention)."""
    from deep_code_security.fuzzer.execution.runner import FuzzRunner
    from deep_code_security.fuzzer.execution.sandbox import SandboxManager
    from deep_code_security.fuzzer.models import FuzzInput

    target_file = tmp_path / "target.py"
    target_file.write_text("def f(x): return x")

    fuzz_input = FuzzInput(
        target_function="f",
        args=["1"],
        kwargs={},
    )

    # Stub out the container backend's run() to write a symlink as output.json
    real_backend = ContainerBackend.__new__(ContainerBackend)
    real_backend._runtime_cmd = ["podman"]
    real_backend._image = "dcs-fuzz-python:latest"
    real_backend._memory_limit = "512m"
    real_backend._pids_limit = 64
    real_backend._cpus = 1.0
    real_backend._tmpfs_size = "64m"
    real_backend._seccomp_profile = "/nonexistent/seccomp.json"

    def _run_and_plant_symlink(cmd, timeout_seconds, cwd="", env=None, **kwargs):
        output_json_path = kwargs.get("output_json")
        if output_json_path:
            # Plant a symlink where output.json is expected
            symlink_target = tmp_path / "sensitive_file.txt"
            symlink_target.write_text("sensitive")
            Path(output_json_path).symlink_to(symlink_target)
        return 0, "", ""

    real_backend.run = _run_and_plant_symlink  # type: ignore[method-assign]

    sandbox = SandboxManager(backend=real_backend)
    runner = FuzzRunner(sandbox=sandbox)

    with pytest.raises(ExecutionError, match="symlink"):
        runner.run(
            fuzz_input=fuzz_input,
            module_path=str(target_file),
            timeout_ms=5000,
            collect_coverage=False,
        )
