"""Additional tests for path_validator.py to increase coverage."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from deep_code_security.mcp.path_validator import PathValidationError, validate_path


class TestPathValidatorEdgeCases:
    """Edge-case tests for validate_path."""

    def test_empty_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PathValidationError, match="Empty path"):
            validate_path("", [str(tmp_path)])

    def test_dotdot_before_resolution_raises(self, tmp_path: Path) -> None:
        # Build a path that literally contains ".." as a component
        traversal = str(tmp_path) + "/../other"
        with pytest.raises(PathValidationError):
            validate_path(traversal, [str(tmp_path)])

    def test_etc_blocked(self, tmp_path: Path) -> None:
        with pytest.raises(PathValidationError, match="special filesystem"):
            validate_path("/etc/passwd", [str(tmp_path), "/etc"])

    def test_dev_blocked(self, tmp_path: Path) -> None:
        with pytest.raises(PathValidationError, match="special filesystem"):
            validate_path("/dev/null", [str(tmp_path), "/dev"])

    def test_proc_blocked(self, tmp_path: Path) -> None:
        with pytest.raises(PathValidationError, match="special filesystem"):
            validate_path("/proc/self/environ", [str(tmp_path), "/proc"])

    def test_sys_blocked(self, tmp_path: Path) -> None:
        with pytest.raises(PathValidationError, match="special filesystem"):
            validate_path("/sys/kernel", [str(tmp_path), "/sys"])

    def test_path_outside_allowed_raises(self, tmp_path: Path) -> None:
        other = tmp_path.parent / "other_dir"
        with pytest.raises(PathValidationError, match="not within"):
            validate_path(str(other), [str(tmp_path)])

    def test_exact_allowed_path_accepted(self, tmp_path: Path) -> None:
        result = validate_path(str(tmp_path), [str(tmp_path)])
        assert result == str(tmp_path.resolve())

    def test_subdir_of_allowed_accepted(self, tmp_path: Path) -> None:
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        result = validate_path(str(subdir), [str(tmp_path)])
        assert result == str(subdir.resolve())

    def test_prefix_collision_rejected(self, tmp_path: Path) -> None:
        """'/var/proj' must not match '/var/project-secrets/file.py'."""
        # Create two sibling directories: proj and project-secrets
        proj = tmp_path / "proj"
        proj.mkdir()
        secrets = tmp_path / "proj-secrets"
        secrets.mkdir()
        secret_file = secrets / "file.py"
        secret_file.write_text("secret")
        with pytest.raises(PathValidationError, match="not within"):
            validate_path(str(secret_file), [str(proj)])

    def test_multiple_allowed_paths(self, tmp_path: Path) -> None:
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        file_b = dir_b / "test.py"
        file_b.write_text("x = 1")
        result = validate_path(str(file_b), [str(dir_a), str(dir_b)])
        assert result == str(file_b.resolve())

    def test_empty_allowed_list_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PathValidationError, match="No allowed paths"):
            validate_path(str(tmp_path), [])

    def test_named_pipe_rejected(self, tmp_path: Path) -> None:
        """Named pipes (FIFOs) are rejected."""
        fifo = tmp_path / "test.fifo"
        os.mkfifo(fifo)
        with pytest.raises(PathValidationError, match="named pipe"):
            validate_path(str(fifo), [str(tmp_path)])
