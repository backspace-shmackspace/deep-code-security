"""YAML source/sink registry loader with query validation and caching."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

import yaml

from deep_code_security.shared.language import Language

__all__ = ["Registry", "RegistryEntry", "SinkEntry", "SourceEntry", "load_registry"]

logger = logging.getLogger(__name__)


class RegistryEntry(dict):
    """A single source or sink registry entry."""

    pass


class SourceEntry:
    """A validated source pattern with compiled tree-sitter query."""

    __slots__ = ("pattern", "query_string", "severity", "compiled_query")

    def __init__(
        self,
        pattern: str,
        query_string: str,
        severity: str,
        compiled_query: Any,
    ) -> None:
        self.pattern = pattern
        self.query_string = query_string
        self.severity = severity
        self.compiled_query = compiled_query

    def __repr__(self) -> str:
        return f"SourceEntry(pattern={self.pattern!r}, severity={self.severity})"


class SinkEntry:
    """A validated sink pattern with compiled tree-sitter query."""

    __slots__ = ("pattern", "query_string", "severity", "cwe", "compiled_query")

    def __init__(
        self,
        pattern: str,
        query_string: str,
        severity: str,
        cwe: str,
        compiled_query: Any,
    ) -> None:
        self.pattern = pattern
        self.query_string = query_string
        self.severity = severity
        self.cwe = cwe
        self.compiled_query = compiled_query

    def __repr__(self) -> str:
        return f"SinkEntry(pattern={self.pattern!r}, cwe={self.cwe}, severity={self.severity})"


class SanitizerEntry:
    """A sanitizer that neutralizes specific sink categories."""

    __slots__ = ("pattern", "neutralizes", "description")

    def __init__(
        self, pattern: str, neutralizes: list[str], description: str = ""
    ) -> None:
        self.pattern = pattern
        self.neutralizes = neutralizes
        self.description = description


class Registry:
    """Loaded and validated source/sink registry for a language."""

    def __init__(
        self,
        language: Language,
        version: str,
        sources: dict[str, list[SourceEntry]],
        sinks: dict[str, list[SinkEntry]],
        sanitizers: list[SanitizerEntry],
        registry_hash: str,
    ) -> None:
        self.language = language
        self.version = version
        self.sources = sources  # category -> [SourceEntry]
        self.sinks = sinks  # category -> [SinkEntry]
        self.sanitizers = sanitizers
        self.registry_hash = registry_hash

    def all_sources(self) -> list[tuple[str, SourceEntry]]:
        """Return all sources as (category, entry) pairs."""
        result = []
        for category, entries in self.sources.items():
            for entry in entries:
                result.append((category, entry))
        return result

    def all_sinks(self) -> list[tuple[str, SinkEntry]]:
        """Return all sinks as (category, entry) pairs."""
        result = []
        for category, entries in self.sinks.items():
            for entry in entries:
                result.append((category, entry))
        return result

    def get_sanitizers_for(self, category: str) -> list[SanitizerEntry]:
        """Return sanitizers that neutralize the given sink category."""
        return [s for s in self.sanitizers if category in s.neutralizes]


# Module-level registry cache
_registry_cache: dict[str, Registry] = {}


def load_registry(
    language: Language,
    registry_dir: str | Path,
    language_obj: Any = None,
) -> Registry:
    """Load and validate a YAML registry for the given language.

    Args:
        language: The programming language.
        registry_dir: Directory containing YAML registry files.
        language_obj: tree_sitter.Language object for query compilation.
                     If None, queries will not be pre-compiled.

    Returns:
        Registry instance with compiled queries.

    Raises:
        FileNotFoundError: If the registry file does not exist.
        ValueError: If the registry format is invalid or a query fails to compile.
    """
    registry_dir = Path(registry_dir)
    registry_file = registry_dir / f"{language.value}.yaml"

    if not registry_file.exists():
        raise FileNotFoundError(f"Registry not found: {registry_file}")

    # Compute hash for reproducibility
    content = registry_file.read_bytes()
    registry_hash = hashlib.sha256(content).hexdigest()[:16]

    # Check cache
    cache_key = f"{language.value}:{registry_hash}"
    if cache_key in _registry_cache:
        return _registry_cache[cache_key]

    # Parse YAML (always use safe_load)
    try:
        raw = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in {registry_file}: {e}") from e

    if not isinstance(raw, dict):
        raise ValueError(f"Registry {registry_file} must be a YAML mapping")

    # Validate required fields
    if raw.get("language") != language.value:
        raise ValueError(
            f"Registry language mismatch: expected {language.value}, "
            f"got {raw.get('language')}"
        )

    version = str(raw.get("version", "unknown"))

    # Parse sources
    sources: dict[str, list[SourceEntry]] = {}
    raw_sources = raw.get("sources", {})
    if not isinstance(raw_sources, dict):
        raise ValueError(f"Registry {registry_file}: 'sources' must be a mapping")

    for category, entries in raw_sources.items():
        if not isinstance(entries, list):
            raise ValueError(
                f"Registry {registry_file}: sources.{category} must be a list"
            )
        source_entries = []
        for entry in entries:
            source_entry = _parse_source_entry(
                entry, category, registry_file, language_obj
            )
            source_entries.append(source_entry)
        sources[category] = source_entries

    # Parse sinks
    sinks: dict[str, list[SinkEntry]] = {}
    raw_sinks = raw.get("sinks", {})
    if not isinstance(raw_sinks, dict):
        raise ValueError(f"Registry {registry_file}: 'sinks' must be a mapping")

    for category, sink_group in raw_sinks.items():
        if not isinstance(sink_group, dict):
            raise ValueError(
                f"Registry {registry_file}: sinks.{category} must be a mapping"
            )
        cwe = sink_group.get("cwe", "CWE-0")
        raw_entries = sink_group.get("entries", [])
        if not isinstance(raw_entries, list):
            raise ValueError(
                f"Registry {registry_file}: sinks.{category}.entries must be a list"
            )
        sink_entries = []
        for entry in raw_entries:
            sink_entry = _parse_sink_entry(
                entry, category, cwe, registry_file, language_obj
            )
            sink_entries.append(sink_entry)
        sinks[category] = sink_entries

    # Parse sanitizers
    sanitizers: list[SanitizerEntry] = []
    raw_sanitizers = raw.get("sanitizers", [])
    if isinstance(raw_sanitizers, list):
        for s in raw_sanitizers:
            if isinstance(s, dict):
                sanitizers.append(
                    SanitizerEntry(
                        pattern=str(s.get("pattern", "")),
                        neutralizes=list(s.get("neutralizes", [])),
                        description=str(s.get("description", "")),
                    )
                )

    registry = Registry(
        language=language,
        version=version,
        sources=sources,
        sinks=sinks,
        sanitizers=sanitizers,
        registry_hash=registry_hash,
    )
    _registry_cache[cache_key] = registry
    logger.debug(
        "Loaded registry for %s (v%s, hash=%s): %d source categories, %d sink categories",
        language.value,
        version,
        registry_hash,
        len(sources),
        len(sinks),
    )
    return registry


def _parse_source_entry(
    entry: dict[str, Any],
    category: str,
    registry_file: Path,
    language_obj: Any,
) -> SourceEntry:
    """Parse and validate a single source entry.

    Args:
        entry: Raw entry dict from YAML.
        category: Source category name.
        registry_file: Registry file path (for error messages).
        language_obj: tree_sitter.Language for query compilation.

    Returns:
        Validated SourceEntry.

    Raises:
        ValueError: If the entry is invalid or the query fails to compile.
    """
    if not isinstance(entry, dict):
        raise ValueError(f"Source entry in {registry_file}.{category} must be a dict")

    pattern = entry.get("pattern")
    query_string = entry.get("tree_sitter_query")
    severity = entry.get("severity", "medium")

    if not pattern:
        raise ValueError(f"Source entry in {registry_file}.{category} missing 'pattern'")
    if not query_string:
        raise ValueError(
            f"Source entry '{pattern}' in {registry_file}.{category} missing 'tree_sitter_query'"
        )

    compiled_query = None
    if language_obj is not None:
        compiled_query = _compile_query(query_string, registry_file, category, pattern, language_obj)

    return SourceEntry(
        pattern=str(pattern),
        query_string=str(query_string),
        severity=str(severity),
        compiled_query=compiled_query,
    )


def _parse_sink_entry(
    entry: dict[str, Any],
    category: str,
    cwe: str,
    registry_file: Path,
    language_obj: Any,
) -> SinkEntry:
    """Parse and validate a single sink entry.

    Args:
        entry: Raw entry dict from YAML.
        category: Sink category name.
        cwe: CWE identifier for this sink category.
        registry_file: Registry file path (for error messages).
        language_obj: tree_sitter.Language for query compilation.

    Returns:
        Validated SinkEntry.

    Raises:
        ValueError: If the entry is invalid or the query fails to compile.
    """
    if not isinstance(entry, dict):
        raise ValueError(f"Sink entry in {registry_file}.{category} must be a dict")

    pattern = entry.get("pattern")
    query_string = entry.get("tree_sitter_query")
    severity = entry.get("severity", "high")

    if not pattern:
        raise ValueError(f"Sink entry in {registry_file}.{category} missing 'pattern'")
    if not query_string:
        raise ValueError(
            f"Sink entry '{pattern}' in {registry_file}.{category} missing 'tree_sitter_query'"
        )

    compiled_query = None
    if language_obj is not None:
        compiled_query = _compile_query(query_string, registry_file, category, pattern, language_obj)

    return SinkEntry(
        pattern=str(pattern),
        query_string=str(query_string),
        severity=str(severity),
        cwe=str(cwe),
        compiled_query=compiled_query,
    )


def _compile_query(
    query_string: str,
    registry_file: Path,
    category: str,
    pattern: str,
    language_obj: Any,
) -> Any:
    """Compile a tree-sitter query and validate it at load time.

    Args:
        query_string: S-expression query string.
        registry_file: Registry file (for error messages).
        category: Category name (for error messages).
        pattern: Pattern name (for error messages).
        language_obj: tree_sitter.Language for compilation.

    Returns:
        Compiled tree_sitter.Query.

    Raises:
        ValueError: If the query is syntactically invalid.
    """
    try:
        return language_obj.query(query_string)
    except Exception as e:
        raise ValueError(
            f"Invalid tree-sitter query in {registry_file}.{category}.{pattern!r}: {e}"
        ) from e


def clear_registry_cache() -> None:
    """Clear the registry cache (for testing)."""
    _registry_cache.clear()
