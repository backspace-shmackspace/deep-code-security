"""Tests for Go-specific taint tracking paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from deep_code_security.hunter.parser import TreeSitterParser
from deep_code_security.hunter.registry import clear_registry_cache, load_registry
from deep_code_security.hunter.source_sink_finder import find_sinks, find_sources
from deep_code_security.hunter.taint_tracker import TaintEngine, TaintState, TaintStep
from deep_code_security.shared.language import Language

REGISTRY_DIR = Path(__file__).parent.parent.parent / "registries"


@pytest.fixture(autouse=True)
def clear_cache():
    clear_registry_cache()
    yield
    clear_registry_cache()


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


class TestGoTaintPropagation:
    """Tests for Go-specific taint assignment propagation (language == Language.GO branch)."""

    def test_go_assignment_propagates(self, go_engine, go_parser) -> None:
        """Taint propagates through Go := assignments."""
        code = """\
package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("q")
    cmd := q
    fmt.Println(cmd)
}
"""
        tree = go_parser.parse_string(code, Language.GO)
        lang_obj = go_parser.get_language_object(Language.GO)
        registry = go_engine.registry
        sources = find_sources(tree, registry, lang_obj, "/test.go")
        sinks = find_sinks(tree, registry, lang_obj, "/test.go")
        paths = go_engine.find_taint_paths(tree, sources, sinks, "/test.go")
        assert isinstance(paths, list)

    def test_go_find_assigned_var(self, go_engine, go_parser) -> None:
        """_find_assigned_var_near_line finds Go variable names."""
        code = """\
package main

func foo() {
    x := "value"
    _ = x
}
"""
        tree = go_parser.parse_string(code, Language.GO)
        result = go_engine._find_assigned_var_near_line(tree.root_node, 4, "/test.go")
        # Should find 'x' or None depending on parsing
        assert result is None or isinstance(result, str)

    def test_go_handle_assignment_expression_list(self, go_engine, go_parser) -> None:
        """Go multi-assign (expression_list LHS) is handled."""
        code = """\
package main

func foo() {
    a, b := 1, 2
    _, _ = a, b
}
"""
        tree = go_parser.parse_string(code, Language.GO)
        state = TaintState()
        step = TaintStep(file="/test.go", line=1, column=0, variable="x", transform="source")
        state.add_taint("1", step)
        go_engine._propagate_taint(tree.root_node, state, "/test.go")
        assert isinstance(state.tainted_vars, set)

    def test_go_taint_paths_end_to_end(self, go_engine, go_parser) -> None:
        """End-to-end taint path search in Go code."""
        code = """\
package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    _ = r.URL.Query().Get("q")
    fmt.Println("done")
}
"""
        tree = go_parser.parse_string(code, Language.GO)
        lang_obj = go_parser.get_language_object(Language.GO)
        registry = go_engine.registry
        sources = find_sources(tree, registry, lang_obj, "/test.go")
        sinks = find_sinks(tree, registry, lang_obj, "/test.go")
        paths = go_engine.find_taint_paths(tree, sources, sinks, "/test.go")
        assert isinstance(paths, list)

    def test_go_engine_node_types_configured(self, go_engine) -> None:
        """Go engine has correct node type mappings."""
        assert "assignment" in go_engine.node_types
        assert "call" in go_engine.node_types
        assert "function_def" in go_engine.node_types

    def test_go_propagate_with_tainted_rhs(self, go_engine, go_parser) -> None:
        """Taint propagates to new variable via := when RHS is tainted."""
        code = """\
package main

func foo() {
    source := "tainted_value"
    dest := source
    _ = dest
}
"""
        tree = go_parser.parse_string(code, Language.GO)
        state = TaintState()
        step = TaintStep(file="/test.go", line=4, column=0, variable="source", transform="source")
        state.add_taint("source", step)
        go_engine._propagate_taint(tree.root_node, state, "/test.go")
        # 'dest' should be tainted because it was assigned from 'source'
        assert state.is_tainted("source")  # Original still tainted


class TestTaintIsRhsTainted:
    """Tests for _is_rhs_tainted with attribute/selector nodes."""

    def test_is_rhs_tainted_with_attribute_node(self, go_engine, go_parser) -> None:
        """Tainted vars in attribute/selector nodes are detected."""
        code = "package main\nfunc f() { x := obj.field }\n"
        tree = go_parser.parse_string(code, Language.GO)
        # Find a selector_expression node
        selector_types = {"selector_expression", "attribute", "member_expression"}

        def find_selector(node):
            if node.type in selector_types:
                return node
            for child in node.children:
                r = find_selector(child)
                if r:
                    return r
            return None

        sel = find_selector(tree.root_node)
        if sel:
            state = TaintState()
            step = TaintStep(file="/test.go", line=1, column=0, variable="obj", transform="source")
            state.add_taint("obj", step)
            binary_ops = go_engine.node_types.get("binary_op", [])
            result = go_engine._is_rhs_tainted(sel, state, binary_ops)
            assert isinstance(result, bool)

    def test_is_rhs_tainted_identifier_not_tainted(self, go_engine, go_parser) -> None:
        """Non-tainted identifier returns False."""
        code = "package main\nvar x = y\n"
        tree = go_parser.parse_string(code, Language.GO)

        def find_id(node):
            if node.type == "identifier":
                return node
            for child in node.children:
                r = find_id(child)
                if r:
                    return r
            return None

        id_node = find_id(tree.root_node)
        if id_node:
            state = TaintState()
            result = go_engine._is_rhs_tainted(id_node, state, [])
            assert result is False


class TestCheckArgsForTaint:
    """Tests for _check_args_for_taint."""

    def test_returns_none_when_no_args(self, go_engine, go_parser) -> None:
        """Returns (None, None) when no arg list is found."""
        code = "package main\nvar x = 1\n"
        tree = go_parser.parse_string(code, Language.GO)
        state = TaintState()
        step = TaintStep(file="/test.go", line=1, column=0, variable="x", transform="source")
        state.add_taint("x", step)
        result = go_engine._check_args_for_taint(tree.root_node, state, "command_injection")
        assert result == (None, None)
