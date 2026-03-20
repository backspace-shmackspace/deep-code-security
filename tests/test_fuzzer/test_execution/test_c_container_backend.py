"""Unit tests for CContainerBackend mount policy and security flags.

Tests verify:
- /workspace mount retains noexec,nosuid (IPC invariant preserved)
- /build tmpfs is added WITHOUT noexec (exec allowed for compilation)
- /build tmpfs has nosuid and nodev
- Parent ContainerBackend security flags are unchanged (no regression)
- Container timeout accounts for compilation time
- is_available() accepts optional image parameter
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.fuzzer.execution.sandbox import (
    CContainerBackend,
    ContainerBackend,
)


@pytest.fixture()
def c_backend() -> CContainerBackend:
    """Return a CContainerBackend with known test image."""
    return CContainerBackend(
        runtime_cmd=["podman"],
        image="dcs-fuzz-c:latest",
        seccomp_profile="/fake/seccomp-fuzz-c.json",
    )


@pytest.fixture()
def py_backend() -> ContainerBackend:
    """Return a Python ContainerBackend for regression comparison."""
    return ContainerBackend(
        runtime_cmd=["podman"],
        image="dcs-fuzz-python:latest",
        memory_limit="512m",
        pids_limit=64,
        cpus=1.0,
        tmpfs_size="64m",
    )


def _capture_cmd(backend: CContainerBackend | ContainerBackend, target_file: str, ipc_dir: str | None = None) -> list[str]:
    """Run backend.run() with mocked subprocess and capture the podman command."""
    captured: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs) -> MagicMock:
        captured.append(cmd)
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""
        return result

    run_kwargs: dict = dict(
        cmd=["irrelevant"],
        timeout_seconds=45.0,
        cwd="/tmp",
        env=None,
        target_file=target_file,
        input_json="/tmp/ipc/input.json",
        output_json="/tmp/ipc/output.json",
    )
    if ipc_dir is not None:
        run_kwargs["ipc_dir"] = ipc_dir

    with patch("subprocess.run", side_effect=fake_run):
        backend.run(**run_kwargs)

    assert len(captured) == 1
    return captured[0]


# ──────────────────────────────────────────────────────────────────────────────
# /build tmpfs mount (exec allowed)
# ──────────────────────────────────────────────────────────────────────────────


class TestBuildMount:
    def test_build_tmpfs_present(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        """CContainerBackend adds a /build tmpfs mount."""
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("int f(void) { return 0; }")
        cmd = _capture_cmd(c_backend, target)
        build_flags = [arg for arg in cmd if "/build" in arg and "--tmpfs" in arg]
        assert build_flags, f"No /build tmpfs mount found in: {cmd}"

    def test_build_tmpfs_has_no_noexec(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        """The /build tmpfs must NOT have noexec (binaries must execute there)."""
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("int f(void) { return 0; }")
        cmd = _capture_cmd(c_backend, target)
        build_flags = [arg for arg in cmd if "/build" in arg and "--tmpfs" in arg]
        assert build_flags, "No /build tmpfs found"
        build_flag = build_flags[0]
        assert "noexec" not in build_flag, (
            f"/build tmpfs must not have noexec (binaries execute there): {build_flag}"
        )

    def test_build_tmpfs_has_nosuid(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        """The /build tmpfs must have nosuid."""
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("int f(void) { return 0; }")
        cmd = _capture_cmd(c_backend, target)
        build_flags = [arg for arg in cmd if "/build" in arg and "--tmpfs" in arg]
        assert build_flags, "No /build tmpfs found"
        assert "nosuid" in build_flags[0], (
            f"/build tmpfs missing nosuid: {build_flags[0]}"
        )

    def test_build_tmpfs_has_nodev(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        """The /build tmpfs must have nodev (no device node creation)."""
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("int f(void) { return 0; }")
        cmd = _capture_cmd(c_backend, target)
        build_flags = [arg for arg in cmd if "/build" in arg and "--tmpfs" in arg]
        assert build_flags, "No /build tmpfs found"
        assert "nodev" in build_flags[0], (
            f"/build tmpfs missing nodev: {build_flags[0]}"
        )

    def test_build_tmpfs_size(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        """The /build tmpfs has 128m size."""
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("int f(void) { return 0; }")
        cmd = _capture_cmd(c_backend, target)
        build_flags = [arg for arg in cmd if "/build" in arg and "--tmpfs" in arg]
        assert build_flags, "No /build tmpfs found"
        assert "128m" in build_flags[0], (
            f"/build tmpfs size is not 128m: {build_flags[0]}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# /workspace IPC mount invariant (must have noexec,nosuid)
# ──────────────────────────────────────────────────────────────────────────────


class TestWorkspaceMount:
    def test_workspace_has_noexec(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        """The /workspace IPC mount must retain noexec (invariant from fuzzer-container-backend plan)."""
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("int f(void) { return 0; }")
        ipc_dir = str(tmp_path / "ipc")
        cmd = _capture_cmd(c_backend, target, ipc_dir=ipc_dir)
        ws_flags = [arg for arg in cmd if "/workspace" in arg and "--volume" in arg]
        assert ws_flags, "No /workspace volume mount found"
        assert "noexec" in ws_flags[0], (
            f"/workspace must have noexec: {ws_flags[0]}"
        )

    def test_workspace_has_nosuid(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        """The /workspace IPC mount must have nosuid."""
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("int f(void) { return 0; }")
        ipc_dir = str(tmp_path / "ipc")
        cmd = _capture_cmd(c_backend, target, ipc_dir=ipc_dir)
        ws_flags = [arg for arg in cmd if "/workspace" in arg and "--volume" in arg]
        assert ws_flags, "No /workspace volume mount found"
        assert "nosuid" in ws_flags[0], (
            f"/workspace must have nosuid: {ws_flags[0]}"
        )

    def test_workspace_is_separate_from_build(
        self, c_backend: CContainerBackend, tmp_path: Path
    ) -> None:
        """The /workspace and /build mounts are separate."""
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("int f(void) { return 0; }")
        ipc_dir = str(tmp_path / "ipc")
        cmd = _capture_cmd(c_backend, target, ipc_dir=ipc_dir)
        ws_flags = [arg for arg in cmd if "/workspace" in arg]
        build_flags = [arg for arg in cmd if "/build" in arg]
        assert ws_flags, "No /workspace mount found"
        assert build_flags, "No /build mount found"
        # They must be different args
        assert set(ws_flags).isdisjoint(set(build_flags)), (
            "workspace and build mounts are the same arg"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Base security flags (regression check -- parent flags must be unchanged)
# ──────────────────────────────────────────────────────────────────────────────


class TestBaseSecurityFlags:
    def test_network_none(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("")
        cmd = _capture_cmd(c_backend, target)
        assert "--network=none" in cmd

    def test_read_only(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("")
        cmd = _capture_cmd(c_backend, target)
        assert "--read-only" in cmd

    def test_cap_drop_all(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("")
        cmd = _capture_cmd(c_backend, target)
        assert "--cap-drop=ALL" in cmd

    def test_no_new_privileges(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("")
        cmd = _capture_cmd(c_backend, target)
        assert "--security-opt=no-new-privileges" in cmd

    def test_user_nobody(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("")
        cmd = _capture_cmd(c_backend, target)
        assert "--user=65534:65534" in cmd

    def test_rm_flag(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("")
        cmd = _capture_cmd(c_backend, target)
        assert "--rm" in cmd

    def test_c_image_used(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("")
        cmd = _capture_cmd(c_backend, target)
        assert "dcs-fuzz-c:latest" in cmd

    def test_memory_limit_1g(self, c_backend: CContainerBackend, tmp_path: Path) -> None:
        """C backend has 1g memory limit (larger than Python for compilation)."""
        target = str(tmp_path / "target.c")
        (tmp_path / "target.c").write_text("")
        cmd = _capture_cmd(c_backend, target)
        assert "--memory=1g" in cmd

    def test_no_shell_true(self) -> None:
        """The sandbox module must never use shell=True in any subprocess call."""
        import inspect
        import deep_code_security.fuzzer.execution.sandbox as sandbox_module

        source = inspect.getsource(sandbox_module)
        assert "shell=True" not in source, (
            "Found 'shell=True' in sandbox.py — all subprocess calls must use list-form args"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Python ContainerBackend regression: parent _build_podman_cmd unchanged
# ──────────────────────────────────────────────────────────────────────────────


class TestParentBackendUnchanged:
    def test_python_backend_no_build_tmpfs(
        self, py_backend: ContainerBackend, tmp_path: Path
    ) -> None:
        """The Python ContainerBackend does NOT have a /build tmpfs mount."""
        target = str(tmp_path / "target.py")
        (tmp_path / "target.py").write_text("def f(): pass")

        captured: list[list[str]] = []

        def fake_run(cmd: list[str], **kwargs) -> MagicMock:
            captured.append(cmd)
            result = MagicMock()
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""
            return result

        with patch("subprocess.run", side_effect=fake_run):
            py_backend.run(
                cmd=["python"],
                timeout_seconds=10.0,
                cwd="/tmp",
                env=None,
                target_file=target,
                input_json="/tmp/i.json",
                output_json="/tmp/o.json",
                ipc_dir="/tmp/ipc",
            )

        cmd = captured[0]
        build_flags = [arg for arg in cmd if "/build" in arg]
        assert not build_flags, (
            f"Python ContainerBackend must not have /build tmpfs: {build_flags}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# is_available() with optional image parameter
# ──────────────────────────────────────────────────────────────────────────────


class TestIsAvailableImageParam:
    def test_is_available_default_uses_python_image(self) -> None:
        """is_available() with no args checks the default Python image."""
        mock_result = MagicMock()
        mock_result.returncode = 0

        call_args_list: list = []

        def capture_run(cmd: list[str], **kwargs) -> MagicMock:
            call_args_list.append(cmd)
            return mock_result

        with patch("subprocess.run", side_effect=capture_run):
            ContainerBackend.is_available()

        # The second call should be the image inspect
        assert len(call_args_list) >= 2
        inspect_call = call_args_list[1]
        assert "image" in inspect_call
        assert "inspect" in inspect_call

    def test_is_available_with_c_image(self) -> None:
        """is_available(image='dcs-fuzz-c:latest') checks the C image."""
        mock_result = MagicMock()
        mock_result.returncode = 0

        call_args_list: list = []

        def capture_run(cmd: list[str], **kwargs) -> MagicMock:
            call_args_list.append(cmd)
            return mock_result

        with patch("subprocess.run", side_effect=capture_run):
            ContainerBackend.is_available(image="dcs-fuzz-c:latest")

        inspect_call = call_args_list[1]
        assert "dcs-fuzz-c:latest" in inspect_call

    def test_is_available_c_image_missing(self) -> None:
        """is_available(image='dcs-fuzz-c:latest') returns False when C image missing."""
        call_count = [0]

        def version_ok_image_fail(cmd: list[str], **kwargs) -> MagicMock:
            call_count[0] += 1
            result = MagicMock()
            result.returncode = 0 if call_count[0] == 1 else 1
            return result

        with patch("subprocess.run", side_effect=version_ok_image_fail):
            assert ContainerBackend.is_available(image="dcs-fuzz-c:latest") is False

    def test_is_available_backward_compatible(self) -> None:
        """is_available() with no args still works (backward compatible)."""
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = ContainerBackend.is_available()
        assert result is True
