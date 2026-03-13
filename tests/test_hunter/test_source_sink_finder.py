"""Tests for source/sink finder."""

from __future__ import annotations

from pathlib import Path

import pytest

from deep_code_security.hunter.parser import TreeSitterParser
from deep_code_security.hunter.registry import clear_registry_cache, load_registry
from deep_code_security.hunter.source_sink_finder import find_sinks, find_sources
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


class TestFindSources:
    """Tests for find_sources()."""

    def test_finds_request_form(self, python_parser, python_registry) -> None:
        """Finds request.form as a web_input source."""
        code = 'from flask import request\nuser = request.form["name"]\n'
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        sources = find_sources(tree, python_registry, lang_obj, "/test.py")
        assert len(sources) >= 1
        assert any(s.function == "request.form" for s in sources)
        assert all(s.category == "web_input" for s in sources)
        assert all(s.language == "python" for s in sources)

    def test_finds_request_args(self, python_parser, python_registry) -> None:
        """Finds request.args as a web_input source."""
        code = 'from flask import request\nq = request.args["query"]\n'
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        sources = find_sources(tree, python_registry, lang_obj, "/test.py")
        assert any(s.function == "request.args" for s in sources)

    def test_finds_sys_argv(self, python_parser, python_registry) -> None:
        """Finds sys.argv as a cli_input source."""
        code = "import sys\narg = sys.argv[1]\n"
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        sources = find_sources(tree, python_registry, lang_obj, "/test.py")
        assert any(s.function == "sys.argv" for s in sources)
        assert any(s.category == "cli_input" for s in sources)

    def test_finds_input_call(self, python_parser, python_registry) -> None:
        """Finds input() as a cli_input source."""
        code = 'user_data = input("Enter value: ")\n'
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        sources = find_sources(tree, python_registry, lang_obj, "/test.py")
        assert any(s.function == "input()" for s in sources)

    def test_source_has_correct_line(self, python_parser, python_registry) -> None:
        """Source has the correct line number (1-based)."""
        code = "# line 1\n# line 2\nfrom flask import request\nx = request.form\n"
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        sources = find_sources(tree, python_registry, lang_obj, "/test.py")
        form_sources = [s for s in sources if s.function == "request.form"]
        assert len(form_sources) >= 1
        assert form_sources[0].line == 4  # Line 4 (1-based)

    def test_no_sources_in_safe_code(self, python_parser, python_registry) -> None:
        """Safe code with no user input has no sources."""
        code = "x = 1 + 2\nprint(x)\n"
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        sources = find_sources(tree, python_registry, lang_obj, "/test.py")
        # May find 0 or some pattern matches — assert no web_input
        web_sources = [s for s in sources if s.category == "web_input"]
        assert len(web_sources) == 0


class TestFindSinks:
    """Tests for find_sinks()."""

    def test_finds_os_system(self, python_parser, python_registry) -> None:
        """Finds os.system as a command_injection sink."""
        code = "import os\nos.system('ls')\n"
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        sinks = find_sinks(tree, python_registry, lang_obj, "/test.py")
        assert any(s.function == "os.system" for s in sinks)
        assert any(s.category == "command_injection" for s in sinks)
        assert any(s.cwe == "CWE-78" for s in sinks)

    def test_finds_eval(self, python_parser, python_registry) -> None:
        """Finds eval() as a code_execution sink."""
        code = 'result = eval("1 + 2")\n'
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        sinks = find_sinks(tree, python_registry, lang_obj, "/test.py")
        assert any(s.function == "eval" for s in sinks)
        assert any(s.category == "code_execution" for s in sinks)
        assert any(s.cwe == "CWE-94" for s in sinks)

    def test_finds_exec(self, python_parser, python_registry) -> None:
        """Finds exec() as a code_execution sink."""
        code = 'exec("print(42)")\n'
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        sinks = find_sinks(tree, python_registry, lang_obj, "/test.py")
        assert any(s.function == "exec" for s in sinks)

    def test_sink_has_correct_line(self, python_parser, python_registry) -> None:
        """Sink has the correct line number (1-based)."""
        code = "# comment\nimport os\nos.system('ls')\n"
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        sinks = find_sinks(tree, python_registry, lang_obj, "/test.py")
        system_sinks = [s for s in sinks if s.function == "os.system"]
        assert len(system_sinks) >= 1
        assert system_sinks[0].line == 3

    def test_no_sinks_in_safe_code(self, python_parser, python_registry) -> None:
        """Safe code with no dangerous calls has no dangerous sinks."""
        code = "x = 1 + 2\nprint(x)\n"
        tree = python_parser.parse_string(code, Language.PYTHON)
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        sinks = find_sinks(tree, python_registry, lang_obj, "/test.py")
        dangerous = [s for s in sinks if s.category in ("command_injection", "sql_injection", "code_execution")]
        assert len(dangerous) == 0
