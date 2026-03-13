"""Tests for FileDiscovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from deep_code_security.shared.file_discovery import FileDiscovery
from deep_code_security.shared.language import Language


class TestFileDiscovery:
    """Tests for FileDiscovery.discover."""

    def test_discovers_python_files(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1\n")
        discovery = FileDiscovery()
        files, skipped = discovery.discover(tmp_path)
        paths = [f.path for f in files]
        assert tmp_path / "app.py" in paths
        assert skipped == 0

    def test_discovers_go_files(self, tmp_path: Path) -> None:
        (tmp_path / "main.go").write_text("package main\n")
        discovery = FileDiscovery()
        files, _ = discovery.discover(tmp_path)
        langs = {f.language for f in files}
        assert Language.GO in langs

    def test_ignores_non_source_files(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("hello")
        (tmp_path / "config.json").write_text("{}")
        discovery = FileDiscovery()
        files, _ = discovery.discover(tmp_path)
        assert files == []

    def test_skips_pycache(self, tmp_path: Path) -> None:
        pycache = tmp_path / "__pycache__"
        pycache.mkdir()
        (pycache / "module.pyc").write_bytes(b"\x00\x00\x00\x00")
        (tmp_path / "real.py").write_text("x = 1\n")
        discovery = FileDiscovery()
        files, _ = discovery.discover(tmp_path)
        # Should only find real.py, not anything in __pycache__
        assert all("__pycache__" not in str(f.path) for f in files)

    def test_skips_dotgit(self, tmp_path: Path) -> None:
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config.py").write_text("x = 1\n")  # .py in .git — should skip
        (tmp_path / "app.py").write_text("y = 2\n")
        discovery = FileDiscovery()
        files, _ = discovery.discover(tmp_path)
        found_paths = [str(f.path) for f in files]
        assert not any(".git" in p for p in found_paths)

    def test_language_filter(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1\n")
        (tmp_path / "main.go").write_text("package main\n")
        discovery = FileDiscovery()
        files, _ = discovery.discover(tmp_path, languages=[Language.PYTHON])
        langs = {f.language for f in files}
        assert langs == {Language.PYTHON}

    def test_max_files_limit(self, tmp_path: Path) -> None:
        for i in range(5):
            (tmp_path / f"mod{i}.py").write_text(f"x = {i}\n")
        discovery = FileDiscovery(max_files=3)
        files, skipped = discovery.discover(tmp_path)
        assert len(files) == 3
        assert skipped == 2

    def test_respects_gitignore(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("ignored.py\n")
        (tmp_path / "ignored.py").write_text("x = 1\n")
        (tmp_path / "kept.py").write_text("y = 2\n")
        discovery = FileDiscovery()
        files, skipped = discovery.discover(tmp_path)
        names = [f.path.name for f in files]
        assert "kept.py" in names
        assert "ignored.py" not in names
        assert skipped >= 1

    def test_discovered_file_has_size(self, tmp_path: Path) -> None:
        content = "x = 1\n" * 100
        (tmp_path / "big.py").write_text(content)
        discovery = FileDiscovery()
        files, _ = discovery.discover(tmp_path)
        assert files[0].size_bytes > 0

    def test_discovered_file_repr(self, tmp_path: Path) -> None:
        (tmp_path / "x.py").write_text("pass\n")
        discovery = FileDiscovery()
        files, _ = discovery.discover(tmp_path)
        r = repr(files[0])
        assert "DiscoveredFile" in r

    def test_empty_directory_returns_empty(self, tmp_path: Path) -> None:
        discovery = FileDiscovery()
        files, skipped = discovery.discover(tmp_path)
        assert files == []
        assert skipped == 0

    def test_symlink_outside_root_skipped(self, tmp_path: Path) -> None:
        other = tmp_path.parent / "other_dir"
        other.mkdir(exist_ok=True)
        (other / "secret.py").write_text("pass\n")
        link = tmp_path / "evil.py"
        try:
            link.symlink_to(other / "secret.py")
        except OSError:
            pytest.skip("Cannot create symlinks in test environment")
        discovery = FileDiscovery()
        files, skipped = discovery.discover(tmp_path)
        found_paths = [f.path for f in files]
        assert link not in found_paths
        assert skipped >= 1

    def test_no_gitignore_file_does_not_crash(self, tmp_path: Path) -> None:
        """No .gitignore present — should work fine."""
        (tmp_path / "app.py").write_text("pass\n")
        discovery = FileDiscovery()
        files, _ = discovery.discover(tmp_path)
        assert len(files) == 1
