"""Recursive file discovery with .gitignore respect and symlink safety."""

from __future__ import annotations

import os
from pathlib import Path

import pathspec

from deep_code_security.shared.language import Language, detect_language

__all__ = ["FileDiscovery", "DiscoveredFile"]


class DiscoveredFile:
    """A discovered source file ready for analysis."""

    __slots__ = ("path", "language", "size_bytes")

    def __init__(self, path: Path, language: Language, size_bytes: int) -> None:
        self.path = path
        self.language = language
        self.size_bytes = size_bytes

    def __repr__(self) -> str:
        return f"DiscoveredFile(path={self.path}, language={self.language})"


class FileDiscovery:
    """Discovers source files in a directory tree.

    Features:
    - Respects .gitignore files via pathspec
    - Does not follow symlinks outside the target root
    - Enforces a maximum file count limit
    - Filters by language if requested
    """

    # Directories to always skip
    SKIP_DIRS: frozenset[str] = frozenset(
        {
            ".git",
            ".svn",
            ".hg",
            "__pycache__",
            "node_modules",
            ".tox",
            ".venv",
            "venv",
            "env",
            ".env",
            "dist",
            "build",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
        }
    )

    # File size limit (skip files larger than this)
    MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10MB

    def __init__(self, max_files: int = 10000) -> None:
        self.max_files = max_files

    def discover(
        self,
        root: Path,
        languages: list[Language] | None = None,
    ) -> tuple[list[DiscoveredFile], int]:
        """Discover source files in the given root directory.

        Args:
            root: The root directory to search.
            languages: Optional language filter. If None, all supported languages included.

        Returns:
            Tuple of (discovered_files, skipped_count).
        """
        root = root.resolve()
        gitignore_spec = self._load_gitignore(root)
        discovered: list[DiscoveredFile] = []
        skipped = 0

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dir_path = Path(dirpath)

            # Skip unwanted directories (modifying dirnames in-place prunes the walk)
            dirnames[:] = [
                d
                for d in dirnames
                if d not in self.SKIP_DIRS
                and not self._is_gitignored(dir_path / d, root, gitignore_spec)
                and not self._is_symlink_outside_root(dir_path / d, root)
            ]

            for filename in filenames:
                file_path = dir_path / filename

                # Skip symlinks outside root
                if file_path.is_symlink():
                    try:
                        resolved = file_path.resolve()
                        if not resolved.is_relative_to(root):
                            skipped += 1
                            continue
                    except OSError:
                        skipped += 1
                        continue

                # Detect language
                lang = detect_language(file_path)
                if lang is None:
                    continue
                if languages is not None and lang not in languages:
                    continue

                # Skip gitignored files
                if self._is_gitignored(file_path, root, gitignore_spec):
                    skipped += 1
                    continue

                # Check file size
                try:
                    size = file_path.stat().st_size
                except OSError:
                    skipped += 1
                    continue

                if size > self.MAX_FILE_SIZE_BYTES:
                    skipped += 1
                    continue

                # Enforce max files limit
                if len(discovered) >= self.max_files:
                    skipped += 1
                    continue

                discovered.append(DiscoveredFile(path=file_path, language=lang, size_bytes=size))

        return discovered, skipped

    def _load_gitignore(self, root: Path) -> pathspec.PathSpec | None:
        """Load .gitignore patterns from the root directory.

        Args:
            root: Root directory to search for .gitignore.

        Returns:
            Compiled pathspec or None if no .gitignore found.
        """
        gitignore = root / ".gitignore"
        if not gitignore.exists():
            return None
        try:
            patterns = gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
            return pathspec.PathSpec.from_lines("gitwildmatch", patterns)
        except OSError:
            return None

    def _is_gitignored(
        self,
        path: Path,
        root: Path,
        spec: pathspec.PathSpec | None,
    ) -> bool:
        """Check if a path matches .gitignore patterns.

        Args:
            path: Path to check.
            root: Root directory (for relative path calculation).
            spec: Compiled pathspec from .gitignore.

        Returns:
            True if the path should be ignored.
        """
        if spec is None:
            return False
        try:
            rel = path.relative_to(root)
            return spec.match_file(str(rel))
        except ValueError:
            return False

    def _is_symlink_outside_root(self, path: Path, root: Path) -> bool:
        """Check if a symlink points outside the root directory.

        Args:
            path: Path to check.
            root: Root directory.

        Returns:
            True if the path is a symlink pointing outside root.
        """
        if not path.is_symlink():
            return False
        try:
            resolved = path.resolve()
            return not resolved.is_relative_to(root)
        except OSError:
            return True
