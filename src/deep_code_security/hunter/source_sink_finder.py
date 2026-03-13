"""AST walker that matches sources and sinks using tree-sitter queries."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from deep_code_security.hunter.models import Sink, Source
from deep_code_security.hunter.registry import Registry, SinkEntry, SourceEntry

__all__ = ["SourceSinkFinder", "find_sources", "find_sinks"]

logger = logging.getLogger(__name__)


class SourceSinkFinder:
    """Runs tree-sitter queries to find sources and sinks in an AST."""

    def __init__(self, registry: Registry, language_obj: Any) -> None:
        self.registry = registry
        self.language_obj = language_obj

    def find_sources(self, tree: Any, file_path: str | Path) -> list[Source]:
        """Find all source patterns in the given AST.

        Args:
            tree: tree_sitter.Tree to search.
            file_path: Path to the source file (for Source model).

        Returns:
            List of Source instances.
        """
        return find_sources(tree, self.registry, self.language_obj, str(file_path))

    def find_sinks(self, tree: Any, file_path: str | Path) -> list[Sink]:
        """Find all sink patterns in the given AST.

        Args:
            tree: tree_sitter.Tree to search.
            file_path: Path to the source file (for Sink model).

        Returns:
            List of Sink instances.
        """
        return find_sinks(tree, self.registry, self.language_obj, str(file_path))


def find_sources(
    tree: Any,
    registry: Registry,
    language_obj: Any,
    file_path: str,
) -> list[Source]:
    """Find all source patterns in an AST.

    Args:
        tree: tree_sitter.Tree to search.
        registry: Registry containing source patterns.
        language_obj: tree_sitter.Language for query compilation (if needed).
        file_path: Path to the source file.

    Returns:
        List of Source instances.
    """
    sources: list[Source] = []

    for category, entry in registry.all_sources():
        matches = _run_query(entry, tree, language_obj, primary_capture="source")
        for node in matches:
            source = Source(
                file=file_path,
                line=node.start_point[0] + 1,  # tree-sitter uses 0-based lines
                column=node.start_point[1],
                function=entry.pattern,
                category=category,
                language=registry.language.value,
            )
            sources.append(source)
            logger.debug(
                "Found source %s at %s:%d", entry.pattern, file_path, source.line
            )

    return sources


def find_sinks(
    tree: Any,
    registry: Registry,
    language_obj: Any,
    file_path: str,
) -> list[Sink]:
    """Find all sink patterns in an AST.

    Args:
        tree: tree_sitter.Tree to search.
        registry: Registry containing sink patterns.
        language_obj: tree_sitter.Language for query compilation (if needed).
        file_path: Path to the source file.

    Returns:
        List of Sink instances.
    """
    sinks: list[Sink] = []

    for category, entry in registry.all_sinks():
        matches = _run_query(entry, tree, language_obj, primary_capture="sink")
        for node in matches:
            sink = Sink(
                file=file_path,
                line=node.start_point[0] + 1,
                column=node.start_point[1],
                function=entry.pattern,
                category=category,
                cwe=entry.cwe,
                language=registry.language.value,
            )
            sinks.append(sink)
            logger.debug(
                "Found sink %s at %s:%d", entry.pattern, file_path, sink.line
            )

    return sinks


def _run_query(
    entry: SourceEntry | SinkEntry,
    tree: Any,
    language_obj: Any,
    primary_capture: str | None = None,
) -> list[Any]:
    """Run a tree-sitter query and return matching nodes.

    Args:
        entry: Source or sink entry with query.
        tree: tree_sitter.Tree to search.
        language_obj: tree_sitter.Language for fallback compilation.
        primary_capture: If set, only return nodes from this capture name
            (e.g., "source" or "sink"). Auxiliary captures like "obj" and
            "attr" are used for predicates but should not produce matches.

    Returns:
        List of matching tree_sitter.Node objects.
    """
    # Use pre-compiled query if available
    query = entry.compiled_query
    if query is None:
        # Compile on-demand (fallback)
        try:
            query = language_obj.query(entry.query_string)
            entry.compiled_query = query
        except Exception as e:
            logger.warning(
                "Failed to compile query for %s: %s", entry.pattern, e
            )
            return []

    try:
        # tree-sitter 0.23+: captures() returns dict[str, list[Node]]
        # Earlier versions returned [(Node, capture_name), ...].
        captures = query.captures(tree.root_node)

        seen_positions: set[tuple[int, int]] = set()
        result_nodes: list[Any] = []

        if isinstance(captures, dict):
            # New API: {capture_name: [Node, ...], ...}
            if primary_capture and primary_capture in captures:
                nodes = captures[primary_capture]
            else:
                # Flatten all captures (fallback)
                nodes = [n for group in captures.values() for n in group]
            for node in nodes:
                pos = (node.start_point[0], node.start_point[1])
                if pos not in seen_positions:
                    seen_positions.add(pos)
                    result_nodes.append(node)
        else:
            # Legacy API: [(Node, capture_name), ...]
            for node, capture_name in captures:
                if primary_capture and capture_name != primary_capture:
                    continue
                pos = (node.start_point[0], node.start_point[1])
                if pos not in seen_positions:
                    seen_positions.add(pos)
                    result_nodes.append(node)

        return result_nodes

    except Exception as e:
        logger.warning(
            "Query execution failed for %s: %s", entry.pattern, e
        )
        return []
