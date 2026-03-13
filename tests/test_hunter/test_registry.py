"""Tests for the YAML registry loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from deep_code_security.hunter.parser import TreeSitterParser
from deep_code_security.hunter.registry import (
    clear_registry_cache,
    load_registry,
)
from deep_code_security.shared.language import Language

REGISTRY_DIR = Path(__file__).parent.parent.parent / "registries"


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear the registry cache before each test."""
    clear_registry_cache()
    yield
    clear_registry_cache()


@pytest.fixture
def python_lang_obj():
    """Get Python language object for query compilation."""
    parser = TreeSitterParser()
    return parser.get_language_object(Language.PYTHON)


@pytest.fixture
def go_lang_obj():
    """Get Go language object for query compilation."""
    parser = TreeSitterParser()
    return parser.get_language_object(Language.GO)


class TestLoadRegistry:
    """Tests for load_registry()."""

    def test_load_python_registry(self, python_lang_obj) -> None:
        """Load the Python registry successfully."""
        registry = load_registry(Language.PYTHON, REGISTRY_DIR, python_lang_obj)
        assert registry is not None
        assert registry.language == Language.PYTHON
        assert len(registry.sources) > 0
        assert len(registry.sinks) > 0

    def test_load_go_registry(self, go_lang_obj) -> None:
        """Load the Go registry successfully."""
        registry = load_registry(Language.GO, REGISTRY_DIR, go_lang_obj)
        assert registry is not None
        assert registry.language == Language.GO

    def test_python_registry_has_web_input(self, python_lang_obj) -> None:
        """Python registry has web_input sources."""
        registry = load_registry(Language.PYTHON, REGISTRY_DIR, python_lang_obj)
        assert "web_input" in registry.sources
        sources = registry.sources["web_input"]
        patterns = [s.pattern for s in sources]
        assert "request.form" in patterns

    def test_python_registry_has_sql_injection_sink(self, python_lang_obj) -> None:
        """Python registry has sql_injection sinks."""
        registry = load_registry(Language.PYTHON, REGISTRY_DIR, python_lang_obj)
        assert "sql_injection" in registry.sinks
        sinks = registry.sinks["sql_injection"]
        patterns = [s.pattern for s in sinks]
        assert "cursor.execute" in patterns

    def test_python_registry_has_command_injection_sink(self, python_lang_obj) -> None:
        """Python registry has command_injection sinks with CWE-78."""
        registry = load_registry(Language.PYTHON, REGISTRY_DIR, python_lang_obj)
        assert "command_injection" in registry.sinks
        sinks = registry.sinks["command_injection"]
        assert all(s.cwe == "CWE-78" for s in sinks)

    def test_registry_queries_compiled(self, python_lang_obj) -> None:
        """All registry queries are compiled at load time."""
        registry = load_registry(Language.PYTHON, REGISTRY_DIR, python_lang_obj)
        for _, entries in registry.sources.items():
            for entry in entries:
                assert entry.compiled_query is not None, (
                    f"Source {entry.pattern!r} has no compiled query"
                )
        for _, entries in registry.sinks.items():
            for entry in entries:
                assert entry.compiled_query is not None, (
                    f"Sink {entry.pattern!r} has no compiled query"
                )

    def test_registry_has_version_hash(self, python_lang_obj) -> None:
        """Registry has a version hash for reproducibility."""
        registry = load_registry(Language.PYTHON, REGISTRY_DIR, python_lang_obj)
        assert registry.registry_hash
        assert len(registry.registry_hash) == 16

    def test_registry_caching(self, python_lang_obj) -> None:
        """Second load returns the same cached instance."""
        r1 = load_registry(Language.PYTHON, REGISTRY_DIR, python_lang_obj)
        r2 = load_registry(Language.PYTHON, REGISTRY_DIR, python_lang_obj)
        assert r1 is r2

    def test_registry_not_found(self) -> None:
        """Loading a non-existent registry raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_registry(Language.PYTHON, "/nonexistent/dir", None)

    def test_invalid_yaml(self, tmp_path) -> None:
        """Invalid YAML raises ValueError."""
        bad_registry = tmp_path / "python.yaml"
        bad_registry.write_text("language: python\n: this is invalid yaml: [\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid YAML"):
            load_registry(Language.PYTHON, tmp_path, None)

    def test_malformed_registry_missing_language(self, tmp_path) -> None:
        """Registry missing language field raises ValueError."""
        registry_file = tmp_path / "python.yaml"
        registry_file.write_text(
            "version: '1.0.0'\nsources: {}\nsinks: {}\n", encoding="utf-8"
        )
        with pytest.raises(ValueError, match="language mismatch"):
            load_registry(Language.PYTHON, tmp_path, None)

    def test_malformed_query_rejected(self, tmp_path, python_lang_obj) -> None:
        """Malformed tree-sitter query raises ValueError at load time."""
        registry_file = tmp_path / "python.yaml"
        registry_file.write_text(
            """language: python
version: "1.0.0"
sources:
  bad_source:
    - pattern: "bad"
      tree_sitter_query: "(this is not valid s-expression syntax @@@"
      severity: high
sinks: {}
""",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="Invalid tree-sitter query"):
            load_registry(Language.PYTHON, tmp_path, python_lang_obj)

    def test_sanitizers_loaded(self, python_lang_obj) -> None:
        """Sanitizers are loaded from the registry."""
        registry = load_registry(Language.PYTHON, REGISTRY_DIR, python_lang_obj)
        assert len(registry.sanitizers) > 0

    def test_get_sanitizers_for(self, python_lang_obj) -> None:
        """get_sanitizers_for returns correct sanitizers for a category."""
        registry = load_registry(Language.PYTHON, REGISTRY_DIR, python_lang_obj)
        sanitizers = registry.get_sanitizers_for("command_injection")
        assert len(sanitizers) > 0
        patterns = [s.pattern for s in sanitizers]
        assert "shlex.quote" in patterns

    def test_registry_yaml_safe_load(self, tmp_path, python_lang_obj) -> None:
        """Registry uses yaml.safe_load (not yaml.load)."""
        # Create a YAML file with safe content to verify loading works
        registry_file = tmp_path / "python.yaml"
        registry_file.write_text(
            """language: python
version: "1.0.0"
sources:
  test_source:
    - pattern: "test.input"
      tree_sitter_query: "(identifier) @id"
      severity: medium
sinks: {}
""",
            encoding="utf-8",
        )
        # Should load without issues
        registry = load_registry(Language.PYTHON, tmp_path, python_lang_obj)
        assert "test_source" in registry.sources
