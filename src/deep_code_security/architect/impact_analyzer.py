"""Cross-file impact analysis — find call sites of affected functions."""

from __future__ import annotations

import logging
from pathlib import Path

from deep_code_security.shared.file_discovery import FileDiscovery
from deep_code_security.shared.language import Language

__all__ = ["ImpactAnalyzer", "CallSiteInfo"]

logger = logging.getLogger(__name__)


class CallSiteInfo:
    """Information about a call site where an affected function is used."""

    __slots__ = ("file", "line", "column", "context_line")

    def __init__(self, file: str, line: int, column: int, context_line: str) -> None:
        self.file = file
        self.line = line
        self.column = column
        self.context_line = context_line

    def __repr__(self) -> str:
        return f"CallSiteInfo({self.file}:{self.line})"


class ImpactAnalyzer:
    """Analyzes cross-file impact of a vulnerability fix.

    Uses tree-sitter to find all call sites of the affected function
    across the target codebase.
    """

    def __init__(self, max_files: int = 1000) -> None:
        self.max_files = max_files

    def analyze_impact(
        self,
        target_path: str | Path,
        affected_function: str,
        language: str,
    ) -> list[CallSiteInfo]:
        """Find all call sites of the affected function.

        Args:
            target_path: Root of the target codebase.
            affected_function: Function name to search for.
            language: Programming language.

        Returns:
            List of CallSiteInfo for each occurrence.
        """
        target_path = Path(target_path)

        try:
            lang = Language(language.lower())
        except ValueError:
            logger.warning("Unknown language for impact analysis: %s", language)
            return []

        # Discover files
        discovery = FileDiscovery(max_files=self.max_files)
        discovered, _ = discovery.discover(target_path, languages=[lang])

        call_sites: list[CallSiteInfo] = []

        # Simple text-based search for function references (v1 fallback)
        # Tree-sitter AST-based search is more accurate but expensive for cross-file analysis
        func_name = affected_function.split(".")[-1]  # Use simple name

        for disc_file in discovered:
            try:
                content = disc_file.path.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()
                for i, line_text in enumerate(lines, start=1):
                    if func_name in line_text:
                        col = line_text.index(func_name)
                        call_sites.append(CallSiteInfo(
                            file=str(disc_file.path),
                            line=i,
                            column=col,
                            context_line=line_text.strip()[:200],  # Truncate long lines
                        ))
            except OSError as e:
                logger.debug("Cannot read %s: %s", disc_file.path, e)

        logger.debug(
            "Impact analysis for %r: %d call sites in %d files",
            affected_function, len(call_sites), len(discovered),
        )

        return call_sites
