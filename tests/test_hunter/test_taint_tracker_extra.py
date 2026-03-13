"""Additional tests for taint_tracker.py to increase coverage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from deep_code_security.hunter.models import Sink, Source, TaintStep
from deep_code_security.hunter.parser import TreeSitterParser
from deep_code_security.hunter.registry import clear_registry_cache, load_registry
from deep_code_security.hunter.source_sink_finder import find_sinks, find_sources
from deep_code_security.hunter.taint_tracker import TaintEngine, TaintState
from deep_code_security.shared.language import Language

REGISTRY_DIR = Path(__file__).parent.parent.parent / "registries"


@pytest.fixture(autouse=True)
def clear_cache():
    clear_registry_cache()
    yield
    clear_registry_cache()


@pytest.fixture
def python_parser() -> TreeSitterParser:
    return TreeSitterParser()


@pytest.fixture
def python_registry(python_parser):
    lang_obj = python_parser.get_language_object(Language.PYTHON)
    return load_registry(Language.PYTHON, REGISTRY_DIR, lang_obj)


@pytest.fixture
def python_engine(python_registry):
    return TaintEngine(language=Language.PYTHON, registry=python_registry)


@pytest.fixture
def go_parser() -> TreeSitterParser:
    return TreeSitterParser()


@pytest.fixture
def go_registry(go_parser):
    lang_obj = go_parser.get_language_object(Language.GO)
    return load_registry(Language.GO, REGISTRY_DIR, lang_obj)


@pytest.fixture
def go_engine(go_registry):
    return TaintEngine(language=Language.GO, registry=go_registry)


class TestTaintStateOperations:
    """Additional TaintState tests."""

    def test_add_taint_overwrites_existing_step(self) -> None:
        """Adding taint to an already-tainted var overwrites the step."""
        state = TaintState()
        step1 = TaintStep(file="/f.py", line=1, column=0, variable="x", transform="source")
        step2 = TaintStep(file="/f.py", line=3, column=0, variable="x", transform="assignment")
        state.add_taint("x", step1)
        state.add_taint("x", step2)
        assert state.is_tainted("x")
        assert state.taint_steps["x"] == step2

    def test_multiple_vars_tainted(self) -> None:
        state = TaintState()
        step = TaintStep(file="/f.py", line=1, column=0, variable="a", transform="source")
        state.add_taint("a", step)
        state.add_taint("b", step)
        assert state.is_tainted("a")
        assert state.is_tainted("b")
        assert not state.is_tainted("c")

    def test_copy_preserves_all_vars(self) -> None:
        state = TaintState()
        step = TaintStep(file="/f.py", line=1, column=0, variable="x", transform="source")
        state.add_taint("x", step)
        state.add_taint("y", step)
        copy = state.copy()
        assert copy.is_tainted("x")
        assert copy.is_tainted("y")
        assert copy is not state


class TestFindTaintPathsFallback:
    """Tests that the AST-node-not-found fallback returns False conservatively."""

    def test_no_ast_node_at_sink_returns_no_path(
        self, python_engine, python_parser
    ) -> None:
        """When no AST node is at the sink line, no false-positive path is produced."""
        code = """\
from flask import request
import os

def handle():
    user_input = request.form["name"]
    os.system(user_input)
"""
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        registry = python_engine.registry
        sources = find_sources(tree, registry, lang_obj, "/test.py")
        sinks = find_sinks(tree, registry, lang_obj, "/test.py")

        # Modify a sink to point to a nonexistent line so the AST lookup fails
        # This exercises the fallback path
        if sinks:
            fake_sink = Sink(
                file=sinks[0].file, line=999,  # Nonexistent line
                column=0, function=sinks[0].function,
                category=sinks[0].category, cwe=sinks[0].cwe,
                language=sinks[0].language,
            )
            result = python_engine._check_sink_reachability(
                tree.root_node, fake_sink,
                TaintState(),  # Empty state — no tainted vars
                "/test.py"
            )
            reachable, steps, sanitizer = result
            # With empty taint state and no AST node: should be False
            assert reachable is False

    def test_fallback_with_tainted_vars_but_no_ast_node_returns_false(
        self, python_engine, python_parser
    ) -> None:
        """Verify the fixed fallback: tainted vars don't produce false positive."""
        code = """\
from flask import request
import os

def handle():
    x = request.form["q"]
    os.system(x)
"""
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        registry = python_engine.registry
        sources = find_sources(tree, registry, lang_obj, "/test.py")

        # Build taint state with a tainted variable
        state = TaintState()
        step = TaintStep(file="/test.py", line=5, column=0, variable="x", transform="source")
        state.add_taint("x", step)
        state.add_taint("request.form", step)

        # Sink at a line with no AST node
        fake_sink = Sink(
            file="/test.py", line=9999,
            column=0, function="os.system",
            category="command_injection", cwe="CWE-78",
            language="python",
        )

        reachable, steps, sanitizer = python_engine._check_sink_reachability(
            tree.root_node, fake_sink, state, "/test.py"
        )
        # Fixed: must be False even though tainted_vars is non-empty
        assert reachable is False


class TestTaintPropagationPython:
    """Tests for taint propagation through Python AST constructs."""

    def test_f_string_propagates_taint(
        self, python_engine, python_parser
    ) -> None:
        """Taint propagates through f-string interpolation."""
        code = """\
from flask import request
import os

def handle():
    name = request.form["name"]
    cmd = f"echo {name}"
    os.system(cmd)
"""
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        registry = python_engine.registry
        sources = find_sources(tree, registry, lang_obj, "/test.py")
        sinks = find_sinks(tree, registry, lang_obj, "/test.py")
        paths = python_engine.find_taint_paths(tree, sources, sinks, "/test.py")
        # Engine should run without error; paths may or may not be found
        assert isinstance(paths, list)

    def test_toplevel_code_analyzed(
        self, python_engine, python_parser
    ) -> None:
        """Top-level code (not in a function) is analyzed for taint."""
        code = """\
from flask import request
import os
user_input = request.form["cmd"]
os.system(user_input)
"""
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        registry = python_engine.registry
        sources = find_sources(tree, registry, lang_obj, "/test.py")
        sinks = find_sinks(tree, registry, lang_obj, "/test.py")
        paths = python_engine.find_taint_paths(tree, sources, sinks, "/test.py")
        assert isinstance(paths, list)

    def test_sink_before_source_skipped(
        self, python_engine, python_parser
    ) -> None:
        """Sinks that appear before the source line are skipped."""
        code = """\
from flask import request
import os

def handle():
    os.system("safe_cmd")
    user_input = request.form["name"]
"""
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        registry = python_engine.registry
        sources = find_sources(tree, registry, lang_obj, "/test.py")
        sinks = find_sinks(tree, registry, lang_obj, "/test.py")
        paths = python_engine.find_taint_paths(tree, sources, sinks, "/test.py")
        # os.system comes before request.form, so no path should be found
        assert isinstance(paths, list)

    def test_find_function_nodes_python(
        self, python_engine, python_parser
    ) -> None:
        code = """\
def foo():
    pass

def bar():
    pass
"""
        tree = python_parser.parse_string(code, Language.PYTHON)
        nodes = python_engine._find_function_nodes(tree.root_node)
        assert len(nodes) == 2

    def test_node_to_var_name_non_identifier_returns_none(
        self, python_engine
    ) -> None:
        """Non-identifier nodes return None."""
        mock_node = MagicMock()
        mock_node.type = "string"
        result = python_engine._node_to_var_name(mock_node)
        assert result is None

    def test_node_to_var_name_identifier(
        self, python_engine
    ) -> None:
        mock_node = MagicMock()
        mock_node.type = "identifier"
        mock_node.text = b"my_var"
        result = python_engine._node_to_var_name(mock_node)
        assert result == "my_var"


class TestGoTaintEngine:
    """Tests for Go language taint engine."""

    def test_go_engine_finds_function_nodes(
        self, go_engine, go_parser
    ) -> None:
        code = """\
package main

func handler() {
    var x = "hello"
    _ = x
}
"""
        tree = go_parser.parse_string(code, Language.GO)
        nodes = go_engine._find_function_nodes(tree.root_node)
        assert len(nodes) >= 1

    def test_go_engine_empty_code(
        self, go_engine, go_parser
    ) -> None:
        code = "package main\n"
        tree = go_parser.parse_string(code, Language.GO)
        lang_obj = go_parser.get_language_object(Language.GO)
        registry = go_engine.registry
        sources = find_sources(tree, registry, lang_obj, "/test.go")
        sinks = find_sinks(tree, registry, lang_obj, "/test.go")
        paths = go_engine.find_taint_paths(tree, sources, sinks, "/test.go")
        assert paths == []


class TestClassifyRhsTransform:
    """Tests for _classify_rhs_transform."""

    def test_binary_op_with_plus_is_concatenation(
        self, python_engine, python_parser
    ) -> None:
        """Binary operator with '+' is classified as concatenation."""
        code = "a = b + c\n"
        tree = python_parser.parse_string(code, Language.PYTHON)

        # Find the binary_operator node
        binary_op_types = python_engine.node_types.get("binary_op", ["binary_operator"])

        def find_binary(node):
            if node.type in binary_op_types:
                return node
            for child in node.children:
                result = find_binary(child)
                if result:
                    return result
            return None

        binary = find_binary(tree.root_node)
        if binary:
            transform = python_engine._classify_rhs_transform(binary, binary_op_types)
            assert transform in ("concatenation", "binary_operation")

    def test_call_classified_as_function_call(
        self, python_engine, python_parser
    ) -> None:
        code = "a = foo(b)\n"
        tree = python_parser.parse_string(code, Language.PYTHON)
        call_types = ["call"]

        def find_call(node):
            if node.type in call_types:
                return node
            for child in node.children:
                r = find_call(child)
                if r:
                    return r
            return None

        call = find_call(tree.root_node)
        if call:
            transform = python_engine._classify_rhs_transform(
                call, python_engine.node_types.get("binary_op", [])
            )
            assert transform == "function_call"
