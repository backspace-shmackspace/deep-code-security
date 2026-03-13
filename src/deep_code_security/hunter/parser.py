"""Tree-sitter AST parsing adapter for multiple languages."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from deep_code_security.shared.language import Language

__all__ = ["TreeSitterParser", "ParseError"]

logger = logging.getLogger(__name__)

# Maximum source size accepted by parse_bytes / parse_string.
# parse_file enforces this via file_discovery, but direct callers bypass that check.
MAX_PARSE_BYTES: int = 10 * 1024 * 1024  # 10 MB


class ParseError(Exception):
    """Raised when parsing fails."""


class TreeSitterParser:
    """Multi-language tree-sitter parser with lazy grammar initialization.

    Grammars are loaded on first use per language to avoid unnecessary
    overhead when only a subset of languages are needed.
    """

    def __init__(self) -> None:
        self._parsers: dict[Language, Any] = {}
        self._languages: dict[Language, Any] = {}

    def _get_parser(self, language: Language) -> Any:
        """Get (or initialize) the parser for the given language.

        Args:
            language: The programming language.

        Returns:
            tree_sitter.Parser instance.

        Raises:
            ParseError: If the grammar cannot be loaded.
        """
        if language not in self._parsers:
            try:
                from tree_sitter import Parser

                lang_obj = self._load_language(language)
                self._languages[language] = lang_obj
                self._parsers[language] = Parser(lang_obj)
            except ImportError as e:
                raise ParseError(f"tree-sitter not installed: {e}") from e
            except Exception as e:
                raise ParseError(f"Failed to load grammar for {language}: {e}") from e
        return self._parsers[language]

    def _load_language(self, language: Language) -> Any:
        """Load the tree-sitter Language object for the given language.

        Args:
            language: The programming language.

        Returns:
            tree_sitter.Language instance.

        Raises:
            ParseError: If the grammar package is not installed.
        """
        from tree_sitter import Language as TSLanguage

        if language == Language.PYTHON:
            try:
                import tree_sitter_python as tspython

                return TSLanguage(tspython.language())
            except ImportError as e:
                raise ParseError(f"tree-sitter-python not installed: {e}") from e

        elif language == Language.GO:
            try:
                import tree_sitter_go as tsgo

                return TSLanguage(tsgo.language())
            except ImportError as e:
                raise ParseError(f"tree-sitter-go not installed: {e}") from e

        elif language == Language.C:
            try:
                import tree_sitter_c as tsc

                return TSLanguage(tsc.language())
            except ImportError as e:
                raise ParseError(f"tree-sitter-c not installed: {e}") from e

        else:
            raise ParseError(f"Unsupported language: {language}")

    def get_language_object(self, language: Language) -> Any:
        """Get the tree-sitter Language object (for query compilation).

        Args:
            language: The programming language.

        Returns:
            tree_sitter.Language instance.
        """
        self._get_parser(language)  # Ensures language is loaded
        return self._languages[language]

    def parse_file(self, path: str | Path, language: Language) -> Any:
        """Parse a source file and return its AST.

        Args:
            path: Absolute path to the source file.
            language: Programming language of the file.

        Returns:
            tree_sitter.Tree (AST root).

        Raises:
            ParseError: If the file cannot be read or parsed.
        """
        path = Path(path)
        try:
            source = path.read_bytes()
        except OSError as e:
            raise ParseError(f"Cannot read file {path}: {e}") from e

        return self.parse_bytes(source, language)

    def parse_string(self, code: str, language: Language) -> Any:
        """Parse a source code string and return its AST.

        Args:
            code: Source code as a string.
            language: Programming language.

        Returns:
            tree_sitter.Tree (AST root).

        Raises:
            ParseError: If parsing fails.
        """
        return self.parse_bytes(code.encode("utf-8"), language)

    def parse_bytes(self, source: bytes, language: Language) -> Any:
        """Parse source bytes and return its AST.

        Args:
            source: Source code as bytes.
            language: Programming language.

        Returns:
            tree_sitter.Tree (AST root).

        Raises:
            ParseError: If parsing fails.
        """
        if len(source) > MAX_PARSE_BYTES:
            raise ParseError(
                f"Source too large to parse: {len(source)} bytes > {MAX_PARSE_BYTES}"
            )

        parser = self._get_parser(language)
        try:
            tree = parser.parse(source)
        except Exception as e:
            raise ParseError(f"Failed to parse {language} source: {e}") from e

        if tree is None:
            raise ParseError(f"Parser returned None for {language} source")

        return tree
