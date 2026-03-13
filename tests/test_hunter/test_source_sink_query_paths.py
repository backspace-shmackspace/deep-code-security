"""Tests for source_sink_finder.py query execution paths."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.hunter.parser import TreeSitterParser
from deep_code_security.hunter.registry import clear_registry_cache, load_registry
from deep_code_security.hunter.source_sink_finder import _run_query, find_sinks, find_sources
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


class TestRunQuery:
    """Tests for _run_query() in source_sink_finder."""

    def test_run_query_no_precompiled_query(self, python_parser, python_registry) -> None:
        """Query is compiled on-demand when entry.compiled_query is None."""
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        code = "import os\nos.system('ls')\n"
        tree = python_parser.parse_string(code, Language.PYTHON)

        # Get the first entry from any sink category
        all_sink_entries = python_registry.all_sinks()
        if all_sink_entries:
            _category, entry = all_sink_entries[0]
            original_query = entry.compiled_query
            entry.compiled_query = None  # Force on-demand compilation
            try:
                result = _run_query(entry, tree, lang_obj)
                assert isinstance(result, list)
            finally:
                entry.compiled_query = original_query

    def test_run_query_returns_empty_on_bad_query(self, python_parser, python_registry) -> None:
        """_run_query returns [] when query compilation fails."""
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        code = "x = 1\n"
        tree = python_parser.parse_string(code, Language.PYTHON)

        # Create an entry with invalid query
        mock_entry = MagicMock()
        mock_entry.compiled_query = None
        mock_entry.query_string = "((INVALID TREE-SITTER QUERY!!!))"
        mock_entry.pattern = "test_pattern"

        result = _run_query(mock_entry, tree, lang_obj)
        assert result == []

    def test_run_query_returns_empty_on_execution_failure(
        self, python_parser, python_registry
    ) -> None:
        """_run_query returns [] when query.captures() raises."""
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        code = "x = 1\n"
        tree = python_parser.parse_string(code, Language.PYTHON)

        mock_query = MagicMock()
        mock_query.captures.side_effect = RuntimeError("mock query failure")
        mock_entry = MagicMock()
        mock_entry.compiled_query = mock_query
        mock_entry.pattern = "test_pattern"

        result = _run_query(mock_entry, tree, lang_obj)
        assert result == []

    def test_run_query_handles_legacy_list_api(self, python_parser) -> None:
        """_run_query handles the legacy [(Node, name), ...] captures API."""
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        code = "x = 1\n"
        tree = python_parser.parse_string(code, Language.PYTHON)

        mock_node = MagicMock()
        mock_node.start_point = (0, 0)

        # Legacy API returns list of (node, name) tuples
        mock_query = MagicMock()
        mock_query.captures.return_value = [(mock_node, "capture_name")]

        mock_entry = MagicMock()
        mock_entry.compiled_query = mock_query
        mock_entry.pattern = "test_pattern"

        result = _run_query(mock_entry, tree, lang_obj)
        assert len(result) == 1
        assert result[0] is mock_node

    def test_run_query_deduplicates_by_position(self, python_parser) -> None:
        """Nodes at the same position are deduplicated."""
        lang_obj = python_parser.get_language_object(Language.PYTHON)
        code = "x = 1\n"
        tree = python_parser.parse_string(code, Language.PYTHON)

        mock_node1 = MagicMock()
        mock_node1.start_point = (0, 0)
        mock_node2 = MagicMock()
        mock_node2.start_point = (0, 0)  # Same position as node1

        # Dict API returns dict with same position node twice (different captures)
        mock_query = MagicMock()
        mock_query.captures.return_value = {
            "cap1": [mock_node1],
            "cap2": [mock_node2],
        }

        mock_entry = MagicMock()
        mock_entry.compiled_query = mock_query
        mock_entry.pattern = "test_pattern"

        result = _run_query(mock_entry, tree, lang_obj)
        # Should deduplicate to just 1 node
        assert len(result) == 1
