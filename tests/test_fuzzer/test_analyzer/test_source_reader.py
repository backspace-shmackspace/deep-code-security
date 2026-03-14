"""Tests for source file reader."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from deep_code_security.fuzzer.analyzer.source_reader import (
    detect_side_effects,
    find_python_files,
    parse_source,
    read_source_file,
)


class TestSourceReader:
    def test_read_source_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text("x = 1\n")
        content = read_source_file(f)
        assert "x = 1" in content

    def test_read_nonexistent(self) -> None:
        with pytest.raises(FileNotFoundError):
            read_source_file("/nonexistent.py")

    def test_read_non_python(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        with pytest.raises(ValueError, match="Not a Python file"):
            read_source_file(f)


class TestDetectSideEffects:
    def test_no_side_effects(self) -> None:
        source = "def pure(x):\n    return x + 1\n"
        tree = parse_source(source)
        func = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)][0]
        has_effects, details = detect_side_effects(func)
        assert has_effects is False

    def test_print_detected(self) -> None:
        source = "def loud(x):\n    print(x)\n    return x\n"
        tree = parse_source(source)
        func = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)][0]
        has_effects, details = detect_side_effects(func)
        assert has_effects is True


class TestFindPythonFiles:
    def test_single_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text("")
        result = find_python_files(f)
        assert len(result) == 1

    def test_directory(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("")
        (tmp_path / "b.py").write_text("")
        result = find_python_files(tmp_path)
        assert len(result) == 2
