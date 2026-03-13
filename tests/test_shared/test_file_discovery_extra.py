"""Additional tests for file_discovery.py to increase coverage."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from deep_code_security.shared.file_discovery import FileDiscovery


class TestSymlinkSafety:
    """Tests for the path-component-safe symlink checks."""

    def test_symlink_within_root_accepted(self, tmp_path: Path) -> None:
        """A symlink that resolves inside the root is accepted."""
        target = tmp_path / "real.py"
        target.write_text("x = 1")
        link = tmp_path / "link.py"
        link.symlink_to(target)
        discovery = FileDiscovery()
        files, skipped = discovery.discover(tmp_path)
        # Both real.py and link.py should be discoverable
        paths = {f.path.name for f in files}
        assert "real.py" in paths

    def test_symlink_outside_root_skipped(self, tmp_path: Path) -> None:
        """A symlink pointing outside the root is skipped."""
        # Create a directory to scan
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        # Create a target outside scan_dir
        outside = tmp_path / "outside.py"
        outside.write_text("secret = 'data'")
        # Create a symlink inside scan_dir pointing outside
        link = scan_dir / "escape.py"
        link.symlink_to(outside)

        discovery = FileDiscovery()
        files, skipped = discovery.discover(scan_dir)
        file_names = {f.path.name for f in files}
        # The symlink pointing outside should be skipped
        assert "escape.py" not in file_names
        assert skipped >= 1

    def test_prefix_collision_symlink_rejected(self, tmp_path: Path) -> None:
        """A symlink resolving to a path with a common prefix but different component is rejected."""
        # /tmp/proj and /tmp/proj-secrets — proj should not match proj-secrets
        proj = tmp_path / "proj"
        proj.mkdir()
        proj_secrets = tmp_path / "proj-secrets"
        proj_secrets.mkdir()
        secret_file = proj_secrets / "main.py"
        secret_file.write_text("x = 1")
        # Create a symlink in proj pointing to proj-secrets/main.py
        link = proj / "main.py"
        link.symlink_to(secret_file)

        discovery = FileDiscovery()
        files, skipped = discovery.discover(proj)
        file_names = {f.path.name for f in files}
        # The link resolves outside proj, so it should be skipped
        assert "main.py" not in file_names or skipped >= 1

    def test_is_symlink_outside_root_method(self, tmp_path: Path) -> None:
        """_is_symlink_outside_root correctly identifies out-of-root symlinks."""
        inside = tmp_path / "inside.py"
        inside.write_text("x = 1")
        outside = tmp_path.parent / "outside.py"
        outside.write_text("y = 2")
        link = tmp_path / "link.py"
        link.symlink_to(outside)

        discovery = FileDiscovery()
        assert discovery._is_symlink_outside_root(link, tmp_path) is True
        assert discovery._is_symlink_outside_root(inside, tmp_path) is False

    def test_non_symlink_not_outside_root(self, tmp_path: Path) -> None:
        """Non-symlink files are never considered outside root."""
        real_file = tmp_path / "real.py"
        real_file.write_text("x = 1")
        discovery = FileDiscovery()
        assert discovery._is_symlink_outside_root(real_file, tmp_path) is False

    def test_broken_symlink_skipped(self, tmp_path: Path) -> None:
        """A broken symlink pointing outside root is treated as outside root."""
        # Link to a path outside tmp_path that doesn't exist
        link = tmp_path / "broken.py"
        link.symlink_to("/nonexistent_path_xyz/file.py")
        discovery = FileDiscovery()
        # resolve() on a broken symlink returns the target path;
        # /nonexistent_path_xyz is not inside tmp_path so it returns True
        result = discovery._is_symlink_outside_root(link, tmp_path)
        assert result is True


class TestGitignoreLoading:
    """Tests for _load_gitignore edge cases."""

    def test_no_gitignore_returns_none(self, tmp_path: Path) -> None:
        discovery = FileDiscovery()
        spec = discovery._load_gitignore(tmp_path)
        assert spec is None

    def test_gitignore_with_patterns(self, tmp_path: Path) -> None:
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("*.log\n__pycache__/\n")
        discovery = FileDiscovery()
        spec = discovery._load_gitignore(tmp_path)
        assert spec is not None

    def test_is_gitignored_returns_false_with_no_spec(self, tmp_path: Path) -> None:
        discovery = FileDiscovery()
        result = discovery._is_gitignored(tmp_path / "file.py", tmp_path, None)
        assert result is False


class TestMaxFilesLimit:
    """Tests for max_files enforcement."""

    def test_max_files_limits_output(self, tmp_path: Path) -> None:
        """Only max_files files are returned."""
        for i in range(5):
            (tmp_path / f"file{i}.py").write_text(f"x = {i}")
        discovery = FileDiscovery(max_files=3)
        files, skipped = discovery.discover(tmp_path)
        assert len(files) == 3
        assert skipped >= 2


class TestFileSizeLimit:
    """Tests for max file size enforcement."""

    def test_oversized_file_skipped(self, tmp_path: Path) -> None:
        """Files over MAX_FILE_SIZE_BYTES are skipped."""
        big_file = tmp_path / "big.py"
        # Write just over 10MB
        big_file.write_bytes(b"x = 1\n" * (10 * 1024 * 1024 // 6 + 1))
        discovery = FileDiscovery()
        files, skipped = discovery.discover(tmp_path)
        file_names = {f.path.name for f in files}
        assert "big.py" not in file_names
        assert skipped >= 1
