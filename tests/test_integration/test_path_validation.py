"""Integration tests for path validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from deep_code_security.mcp.path_validator import PathValidationError, validate_path


class TestPathValidationIntegration:
    """Integration tests for path validation rules."""

    def test_allowed_path_accepted(self, tmp_path: Path) -> None:
        """Paths within allowed directory are accepted."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        result = validate_path(str(subdir), [str(tmp_path)])
        assert result == str(subdir.resolve())

    def test_parent_traversal_rejected(self, tmp_path: Path) -> None:
        """Paths with .. are rejected."""
        traversal = str(tmp_path / ".." / "etc")
        with pytest.raises(PathValidationError, match="traversal"):
            validate_path(traversal, [str(tmp_path)])

    def test_outside_allowed_rejected(self, tmp_path: Path) -> None:
        """Paths outside the allowed list are rejected."""
        other_dir = tmp_path.parent / "other"
        other_dir.mkdir(exist_ok=True)
        with pytest.raises(PathValidationError, match="not within any allowed"):
            validate_path(str(other_dir), [str(tmp_path)])

    def test_proc_rejected(self, tmp_path: Path) -> None:
        """Access to /proc is rejected."""
        with pytest.raises(PathValidationError, match="special filesystem"):
            validate_path("/proc/self", ["/"])

    def test_sys_rejected(self, tmp_path: Path) -> None:
        """Access to /sys is rejected."""
        with pytest.raises(PathValidationError, match="special filesystem"):
            validate_path("/sys/kernel", ["/"])

    def test_dev_rejected(self, tmp_path: Path) -> None:
        """Access to /dev is rejected."""
        with pytest.raises(PathValidationError, match="special filesystem"):
            validate_path("/dev/null", ["/"])

    def test_empty_path_rejected(self, tmp_path: Path) -> None:
        """Empty path is rejected."""
        with pytest.raises(PathValidationError, match="Empty path"):
            validate_path("", [str(tmp_path)])

    def test_multiple_allowed_paths(self, tmp_path: Path) -> None:
        """Multiple allowed paths — path in any one of them is accepted."""
        other_tmp = tmp_path / "other"
        other_tmp.mkdir()
        allowed = ["/nonexistent1", str(other_tmp), "/nonexistent2"]
        result = validate_path(str(other_tmp), allowed)
        assert result == str(other_tmp.resolve())

    def test_symlink_outside_allowed_rejected(self, tmp_path: Path) -> None:
        """Symlinks pointing outside the allowed directory are rejected."""
        # Create a symlink in tmp_path that points to /etc
        link_path = tmp_path / "evil_link"
        try:
            link_path.symlink_to("/etc")
        except OSError:
            pytest.skip("Cannot create symlink in test environment")

        # The symlink resolves to /etc which is outside tmp_path
        with pytest.raises(PathValidationError, match="not within any allowed"):
            validate_path(str(link_path), [str(tmp_path)])

    def test_resolved_path_returned(self, tmp_path: Path) -> None:
        """Returns the resolved (real) path, not the original."""
        result = validate_path(str(tmp_path), [str(tmp_path)])
        assert result == str(tmp_path.resolve())
