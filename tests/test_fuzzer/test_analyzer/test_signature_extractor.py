"""Tests for function signature extraction."""

from __future__ import annotations

from deep_code_security.fuzzer.analyzer.signature_extractor import (
    extract_targets_from_source,
)


class TestSignatureExtractor:
    def test_extract_simple_function(self) -> None:
        source = "def add(x: int, y: int) -> int:\n    return x + y\n"
        targets = extract_targets_from_source(source, "/tmp/test.py")
        assert len(targets) == 1
        assert targets[0].function_name == "add"
        assert targets[0].qualified_name == "add"

    def test_skip_dunder(self) -> None:
        source = "def __init__(self):\n    pass\n"
        targets = extract_targets_from_source(source, "/tmp/test.py")
        assert len(targets) == 0

    def test_static_method_included(self) -> None:
        source = "class Foo:\n    @staticmethod\n    def bar(x):\n        return x\n"
        targets = extract_targets_from_source(source, "/tmp/test.py")
        assert len(targets) == 1
        assert targets[0].qualified_name == "Foo.bar"

    def test_instance_method_skipped(self) -> None:
        source = "class Foo:\n    def bar(self, x):\n        return x\n"
        targets = extract_targets_from_source(source, "/tmp/test.py")
        assert len(targets) == 0

    def test_syntax_error(self) -> None:
        source = "def broken(\n"
        targets = extract_targets_from_source(source, "/tmp/test.py")
        assert targets == []
