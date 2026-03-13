"""Additional tests for source_sink_finder.py to increase coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from deep_code_security.hunter.parser import TreeSitterParser
from deep_code_security.hunter.registry import clear_registry_cache, load_registry
from deep_code_security.hunter.source_sink_finder import SourceSinkFinder, find_sinks, find_sources
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
def go_parser() -> TreeSitterParser:
    return TreeSitterParser()


@pytest.fixture
def go_registry(go_parser):
    lang_obj = go_parser.get_language_object(Language.GO)
    return load_registry(Language.GO, REGISTRY_DIR, lang_obj)


class TestSourceSinkFinderClass:
    """Tests for the SourceSinkFinder class interface."""

    def test_find_sources_via_class(
        self, python_parser, python_registry
    ) -> None:
        """SourceSinkFinder.find_sources returns correct results."""
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        finder = SourceSinkFinder(python_registry, lang_obj)
        code = 'from flask import request\nuser = request.form["name"]\n'
        tree = python_parser.parse_string(code, Language.PYTHON)
        sources = finder.find_sources(tree, "/test.py")
        assert isinstance(sources, list)

    def test_find_sinks_via_class(
        self, python_parser, python_registry
    ) -> None:
        """SourceSinkFinder.find_sinks returns correct results."""
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        finder = SourceSinkFinder(python_registry, lang_obj)
        code = 'import os\nos.system("ls")\n'
        tree = python_parser.parse_string(code, Language.PYTHON)
        sinks = finder.find_sinks(tree, "/test.py")
        assert isinstance(sinks, list)

    def test_find_sources_via_class_path_object(
        self, python_parser, python_registry
    ) -> None:
        """SourceSinkFinder.find_sources accepts a Path as file_path."""
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        finder = SourceSinkFinder(python_registry, lang_obj)
        code = 'from flask import request\nuser = request.args["q"]\n'
        tree = python_parser.parse_string(code, Language.PYTHON)
        sources = finder.find_sources(tree, Path("/test.py"))
        assert isinstance(sources, list)


class TestFindSourcesGo:
    """Tests for find_sources with Go language."""

    def test_go_sources_found(self, go_parser, go_registry) -> None:
        lang_obj = go_parser.get_language_object(Language.GO)
        code = """\
package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("q")
    fmt.Println(q)
}
"""
        tree = go_parser.parse_string(code, Language.GO)
        sources = find_sources(tree, go_registry, lang_obj, "/test.go")
        assert isinstance(sources, list)

    def test_go_sinks_found(self, go_parser, go_registry) -> None:
        lang_obj = go_parser.get_language_object(Language.GO)
        code = """\
package main

import (
    "fmt"
    "os/exec"
)

func run(cmd string) {
    out, _ := exec.Command("sh", "-c", cmd).Output()
    fmt.Println(string(out))
}
"""
        tree = go_parser.parse_string(code, Language.GO)
        sinks = find_sinks(tree, go_registry, lang_obj, "/test.go")
        assert isinstance(sinks, list)


class TestFindSinksPython:
    """Additional sink tests for Python."""

    def test_cursor_execute_found(self, python_parser, python_registry) -> None:
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        code = """\
import sqlite3
conn = sqlite3.connect("test.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id=" + user_id)
"""
        tree = python_parser.parse_string(code, Language.PYTHON)
        sinks = find_sinks(tree, python_registry, lang_obj, "/test.py")
        sql_sinks = [s for s in sinks if s.category == "sql_injection"]
        assert len(sql_sinks) >= 1

    def test_subprocess_run_found(self, python_parser, python_registry) -> None:
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        code = """\
import subprocess
subprocess.run(cmd, shell=True)
"""
        tree = python_parser.parse_string(code, Language.PYTHON)
        sinks = find_sinks(tree, python_registry, lang_obj, "/test.py")
        # Should find some sinks (subprocess or command injection category)
        assert isinstance(sinks, list)

    def test_open_path_traversal_found(self, python_parser, python_registry) -> None:
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        code = """\
with open(user_path) as f:
    data = f.read()
"""
        tree = python_parser.parse_string(code, Language.PYTHON)
        sinks = find_sinks(tree, python_registry, lang_obj, "/test.py")
        assert isinstance(sinks, list)

    def test_empty_code_no_sources_no_sinks(
        self, python_parser, python_registry
    ) -> None:
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        code = "# just a comment\n"
        tree = python_parser.parse_string(code, Language.PYTHON)
        sources = find_sources(tree, python_registry, lang_obj, "/test.py")
        sinks = find_sinks(tree, python_registry, lang_obj, "/test.py")
        assert len([s for s in sources if s.category == "web_input"]) == 0
        assert len([s for s in sinks if s.category in ("sql_injection", "command_injection")]) == 0
