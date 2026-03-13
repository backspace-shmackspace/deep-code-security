"""Interprocedural call graph builder — v1.1 stub.

This module is a placeholder for interprocedural taint tracking, which is
deferred to v1.1. In v1, taint tracking is intraprocedural only.

See: https://github.com/your-org/deep-code-security/issues/1
"""

from __future__ import annotations

import logging
from typing import Any

__all__ = ["CallGraph", "CallGraphBuilder", "CallSite"]

logger = logging.getLogger(__name__)


class CallSite:
    """A single function call site.

    Stub for v1.1 interprocedural analysis.
    """

    __slots__ = ("caller", "callee", "file", "line", "column")

    def __init__(
        self,
        caller: str,
        callee: str,
        file: str,
        line: int,
        column: int,
    ) -> None:
        self.caller = caller
        self.callee = callee
        self.file = file
        self.line = line
        self.column = column

    def __repr__(self) -> str:
        return f"CallSite({self.caller!r} -> {self.callee!r} at {self.file}:{self.line})"


class CallGraph:
    """Interprocedural call graph (v1.1 stub).

    In v1, this is always empty. The taint engine uses only intraprocedural
    analysis (within single functions).
    """

    def __init__(self) -> None:
        self._edges: dict[str, list[CallSite]] = {}

    def get_callees(self, function_name: str) -> list[CallSite]:
        """Get all functions called by the given function.

        Args:
            function_name: The caller function name.

        Returns:
            Empty list in v1 (stub).
        """
        return self._edges.get(function_name, [])

    def get_callers(self, function_name: str) -> list[CallSite]:
        """Get all functions that call the given function.

        Args:
            function_name: The callee function name.

        Returns:
            Empty list in v1 (stub).
        """
        return [
            site
            for sites in self._edges.values()
            for site in sites
            if site.callee == function_name
        ]

    @property
    def is_empty(self) -> bool:
        """True if no call graph edges have been added."""
        return not self._edges


class CallGraphBuilder:
    """Builds a call graph from ASTs (v1.1 stub).

    In v1, this builder is a no-op. It exists to define the interface
    for future implementation.
    """

    def __init__(self) -> None:
        self._graph = CallGraph()

    def add_file(self, tree: Any, file_path: str, language: str) -> None:
        """Add a parsed file to the call graph.

        Args:
            tree: tree_sitter.Tree for the file.
            file_path: Path to the source file.
            language: Programming language.

        Note:
            v1 stub — no-op. Call graph construction deferred to v1.1.
        """
        logger.debug(
            "CallGraphBuilder.add_file: v1.1 stub, skipping %s", file_path
        )

    def build(self) -> CallGraph:
        """Build and return the call graph.

        Returns:
            Empty CallGraph in v1 (stub).
        """
        return self._graph
