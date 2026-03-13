"""Tests for the tree-sitter parser adapter."""

from __future__ import annotations

import pytest

from deep_code_security.hunter.parser import ParseError, TreeSitterParser
from deep_code_security.shared.language import Language


class TestTreeSitterParser:
    """Tests for TreeSitterParser."""

    def test_parse_python_string(self) -> None:
        """Parse a simple Python code string."""
        parser = TreeSitterParser()
        code = "x = 1 + 2\nprint(x)\n"
        tree = parser.parse_string(code, Language.PYTHON)
        assert tree is not None
        assert tree.root_node is not None
        assert tree.root_node.type == "module"

    def test_parse_go_string(self) -> None:
        """Parse a simple Go code string."""
        parser = TreeSitterParser()
        code = 'package main\nimport "fmt"\nfunc main() { fmt.Println("hello") }\n'
        tree = parser.parse_string(code, Language.GO)
        assert tree is not None
        assert tree.root_node is not None
        assert tree.root_node.type == "source_file"

    def test_parse_c_string(self) -> None:
        """Parse a simple C code string."""
        parser = TreeSitterParser()
        code = '#include <stdio.h>\nint main() { printf("hello\\n"); return 0; }\n'
        tree = parser.parse_string(code, Language.C)
        assert tree is not None
        assert tree.root_node is not None

    def test_parse_file(self, tmp_path) -> None:
        """Parse a Python file from disk."""
        parser = TreeSitterParser()
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 42\n", encoding="utf-8")
        tree = parser.parse_file(test_file, Language.PYTHON)
        assert tree is not None
        assert tree.root_node.type == "module"

    def test_parse_file_not_found(self) -> None:
        """Parsing a non-existent file raises ParseError."""
        parser = TreeSitterParser()
        with pytest.raises(ParseError, match="Cannot read file"):
            parser.parse_file("/nonexistent/file.py", Language.PYTHON)

    def test_lazy_initialization(self) -> None:
        """Parsers are initialized lazily (on first use)."""
        parser = TreeSitterParser()
        assert Language.PYTHON not in parser._parsers
        parser.parse_string("x = 1", Language.PYTHON)
        assert Language.PYTHON in parser._parsers

    def test_grammar_caching(self) -> None:
        """Grammar objects are cached after first use."""
        parser = TreeSitterParser()
        parser.parse_string("x = 1", Language.PYTHON)
        parser.parse_string("y = 2", Language.PYTHON)
        # Only one parser instance should exist
        assert len([k for k in parser._parsers if k == Language.PYTHON]) == 1

    def test_get_language_object(self) -> None:
        """get_language_object returns the tree-sitter Language."""
        parser = TreeSitterParser()
        lang_obj = parser.get_language_object(Language.PYTHON)
        assert lang_obj is not None
        # Should be able to compile a query on it
        query = lang_obj.query("(identifier) @id")
        assert query is not None

    def test_python_ast_has_function_defs(self) -> None:
        """Python AST contains function_definition nodes."""
        parser = TreeSitterParser()
        code = "def foo(x):\n    return x + 1\n"
        tree = parser.parse_string(code, Language.PYTHON)
        # Walk and find function_definition
        found = False

        def visit(node):
            nonlocal found
            if node.type == "function_definition":
                found = True
            for child in node.children:
                visit(child)

        visit(tree.root_node)
        assert found, "Expected function_definition node in Python AST"

    def test_go_ast_has_function_decl(self) -> None:
        """Go AST contains function_declaration nodes."""
        parser = TreeSitterParser()
        code = "package main\nfunc foo(x int) int { return x + 1 }\n"
        tree = parser.parse_string(code, Language.GO)

        found = False

        def visit(node):
            nonlocal found
            if node.type == "function_declaration":
                found = True
            for child in node.children:
                visit(child)

        visit(tree.root_node)
        assert found, "Expected function_declaration node in Go AST"

    def test_parse_empty_file(self, tmp_path) -> None:
        """Parsing an empty file succeeds."""
        parser = TreeSitterParser()
        empty_file = tmp_path / "empty.py"
        empty_file.write_bytes(b"")
        tree = parser.parse_file(empty_file, Language.PYTHON)
        assert tree is not None
