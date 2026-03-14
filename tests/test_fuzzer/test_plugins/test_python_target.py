"""Tests for PythonTargetPlugin."""

from __future__ import annotations

from pathlib import Path

from deep_code_security.fuzzer.plugins.python_target import PythonTargetPlugin


class TestPythonTargetPlugin:
    def test_name(self) -> None:
        plugin = PythonTargetPlugin()
        assert plugin.name == "python"

    def test_file_extensions(self) -> None:
        plugin = PythonTargetPlugin()
        assert plugin.file_extensions == [".py"]

    def test_validate_target_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text("def foo(): pass\n")
        plugin = PythonTargetPlugin()
        assert plugin.validate_target(str(f)) is True

    def test_validate_target_non_python(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        plugin = PythonTargetPlugin()
        assert plugin.validate_target(str(f)) is False

    def test_discover_targets(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def add(x, y):\n    return x + y\n")
        plugin = PythonTargetPlugin()
        targets = plugin.discover_targets(str(f))
        assert len(targets) >= 1
        assert targets[0].function_name == "add"
