"""Additional tests for parser.py to increase coverage."""

from __future__ import annotations

import pytest

from deep_code_security.hunter.parser import MAX_PARSE_BYTES, ParseError, TreeSitterParser
from deep_code_security.shared.language import Language


class TestSizeGuard:
    """Tests for the MAX_PARSE_BYTES size guard in parse_bytes."""

    def test_parse_bytes_rejects_oversized_input(self) -> None:
        """parse_bytes raises ParseError when input exceeds MAX_PARSE_BYTES."""
        parser = TreeSitterParser()
        oversized = b"x = 1\n" * (MAX_PARSE_BYTES // 6 + 1)
        assert len(oversized) > MAX_PARSE_BYTES
        with pytest.raises(ParseError, match="too large"):
            parser.parse_bytes(oversized, Language.PYTHON)

    def test_parse_string_rejects_oversized_input(self) -> None:
        """parse_string (which calls parse_bytes) also rejects oversized input."""
        parser = TreeSitterParser()
        oversized_str = "x = 1\n" * (MAX_PARSE_BYTES // 6 + 1)
        with pytest.raises(ParseError, match="too large"):
            parser.parse_string(oversized_str, Language.PYTHON)

    def test_parse_bytes_accepts_exactly_max_bytes(self) -> None:
        """Exactly MAX_PARSE_BYTES should succeed (not raise)."""
        parser = TreeSitterParser()
        # Build bytes of exactly MAX_PARSE_BYTES filled with comment lines
        # A comment line is "# x\n" = 4 bytes; fill up then pad
        chunk = b"# x\n"
        count = MAX_PARSE_BYTES // len(chunk)
        source = chunk * count
        # Pad to exactly MAX_PARSE_BYTES
        source = source[: MAX_PARSE_BYTES]
        # Should not raise
        tree = parser.parse_bytes(source, Language.PYTHON)
        assert tree is not None

    def test_max_parse_bytes_is_ten_mb(self) -> None:
        assert MAX_PARSE_BYTES == 10 * 1024 * 1024


class TestUnsupportedLanguage:
    """Tests for unsupported language handling."""

    def test_load_language_unsupported_raises(self) -> None:
        """_load_language raises ParseError for unknown Language values.

        We inject a mock language object that doesn't equal PYTHON, GO, or C
        to trigger the else branch (Unsupported language).
        """
        from unittest.mock import MagicMock
        parser = TreeSitterParser()

        # Build a fake language enum member that doesn't match any known value
        fake_lang = MagicMock(spec=Language)
        fake_lang.value = "cobol"
        # Make == comparisons always return False vs real Language members
        fake_lang.__eq__ = lambda self, other: False

        with pytest.raises(ParseError, match="Unsupported language"):
            parser._load_language(fake_lang)

    def test_get_language_object_triggers_load(self) -> None:
        """get_language_object ensures language is loaded."""
        parser = TreeSitterParser()
        lang_obj = parser.get_language_object(Language.PYTHON)
        assert lang_obj is not None
        assert Language.PYTHON in parser._languages


class TestParseGoLanguage:
    """Tests for Go language parsing (should work in test environment)."""

    def test_parse_go_bytes(self) -> None:
        parser = TreeSitterParser()
        code = b'package main\nfunc main() {}\n'
        tree = parser.parse_bytes(code, Language.GO)
        assert tree is not None
        assert tree.root_node is not None

    def test_parse_go_string(self) -> None:
        parser = TreeSitterParser()
        code = 'package main\nfunc main() {}\n'
        tree = parser.parse_string(code, Language.GO)
        assert tree is not None


class TestParsePythonEdgeCases:
    """Additional Python parse tests."""

    def test_parse_bytes_valid_python(self) -> None:
        parser = TreeSitterParser()
        tree = parser.parse_bytes(b"x = 42\n", Language.PYTHON)
        assert tree.root_node.type == "module"

    def test_parse_string_valid_python(self) -> None:
        parser = TreeSitterParser()
        tree = parser.parse_string("y = 'hello'\n", Language.PYTHON)
        assert tree is not None

    def test_parse_file_large_but_under_limit(self, tmp_path) -> None:
        """A file under the size limit parses successfully."""
        parser = TreeSitterParser()
        small_file = tmp_path / "small.py"
        # Write 1MB of content — well under 10MB limit
        small_file.write_bytes(b"# comment\n" * (1024 * 100))
        tree = parser.parse_file(small_file, Language.PYTHON)
        assert tree is not None
