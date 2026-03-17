"""Tests for function signature extraction."""

from __future__ import annotations

from deep_code_security.fuzzer.analyzer.signature_extractor import (
    extract_targets_from_source,
)
from deep_code_security.fuzzer.models import TargetInfo


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

    def test_target_info_lineno_fields(self) -> None:
        """lineno and end_lineno are populated by extract_targets_from_source."""
        source = "def my_func(x: int) -> int:\n    return x + 1\n"
        targets = extract_targets_from_source(source, "/tmp/test.py")
        assert len(targets) == 1
        assert targets[0].lineno == 1
        assert targets[0].end_lineno == 2

    def test_target_info_lineno_defaults_none(self) -> None:
        """Default TargetInfo has lineno=None and end_lineno=None."""
        ti = TargetInfo(
            module_path="/tmp/t.py",
            function_name="f",
            qualified_name="f",
        )
        assert ti.lineno is None
        assert ti.end_lineno is None

    def test_extract_targets_include_instance_methods_false(self) -> None:
        """Default behavior unchanged -- instance methods are skipped."""
        source = "class Foo:\n    def bar(self, x):\n        return x\n"
        targets = extract_targets_from_source(source, "/tmp/test.py")
        assert len(targets) == 0

    def test_extract_targets_include_instance_methods_true(self) -> None:
        """With include_instance_methods=True, instance methods are included."""
        source = "class Foo:\n    def bar(self, x: int) -> int:\n        return x\n"
        targets = extract_targets_from_source(
            source, "/tmp/test.py", include_instance_methods=True
        )
        assert len(targets) == 1
        assert targets[0].qualified_name == "Foo.bar"
        assert targets[0].is_instance_method is True

    def test_extract_targets_classmethod_include_true(self) -> None:
        """With include_instance_methods=True, classmethods are included with is_instance_method=True."""
        source = (
            "class Foo:\n"
            "    @classmethod\n"
            "    def create(cls, data: str) -> None:\n"
            "        pass\n"
        )
        targets = extract_targets_from_source(
            source, "/tmp/test.py", include_instance_methods=True
        )
        assert len(targets) == 1
        assert targets[0].qualified_name == "Foo.create"
        assert targets[0].is_instance_method is True

    def test_extract_targets_static_method_not_instance(self) -> None:
        """Static methods always have is_instance_method=False regardless of flag."""
        source = (
            "class Foo:\n"
            "    @staticmethod\n"
            "    def helper(x: int) -> int:\n"
            "        return x\n"
        )
        # Test with flag=True
        targets = extract_targets_from_source(
            source, "/tmp/test.py", include_instance_methods=True
        )
        assert len(targets) == 1
        assert targets[0].is_instance_method is False

    def test_target_info_is_instance_method_default_false(self) -> None:
        """Default TargetInfo.is_instance_method is False."""
        ti = TargetInfo(module_path="/tmp/t.py", function_name="f", qualified_name="f")
        assert ti.is_instance_method is False

    def test_top_level_function_is_not_instance_method(self) -> None:
        """Top-level functions have is_instance_method=False."""
        source = "def standalone(x: int) -> int:\n    return x\n"
        targets = extract_targets_from_source(source, "/tmp/test.py")
        assert len(targets) == 1
        assert targets[0].is_instance_method is False

    def test_lineno_matches_multiline_function(self) -> None:
        """lineno/end_lineno cover the full function span."""
        source = (
            "def first_func(x: int) -> int:\n"
            "    return x + 1\n"
            "\n"
            "def second_func(y: str) -> str:\n"
            "    return y.upper()\n"
        )
        targets = extract_targets_from_source(source, "/tmp/test.py")
        assert len(targets) == 2
        by_name = {t.function_name: t for t in targets}
        assert by_name["first_func"].lineno == 1
        assert by_name["first_func"].end_lineno == 2
        assert by_name["second_func"].lineno == 4
        assert by_name["second_func"].end_lineno == 5
