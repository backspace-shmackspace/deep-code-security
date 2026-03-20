"""TreeSitter scanner backend adapter.

Wraps the existing parse -> find_sources -> find_sinks -> taint_track pipeline
as a ``ScannerBackend`` implementation.  This is the fallback backend used when
Semgrep is not installed, and is always available because tree-sitter is a core
project dependency.

The adapter does NOT modify any of the underlying modules (``parser.py``,
``registry.py``, ``source_sink_finder.py``, ``taint_tracker.py``).  It simply
calls them in the same order and with the same arguments that the pre-refactor
``HunterOrchestrator.scan()`` method used, then packages the results into a
``BackendResult``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from deep_code_security.hunter.models import RawFinding
from deep_code_security.hunter.parser import ParseError, TreeSitterParser
from deep_code_security.hunter.registry import Registry, load_registry
from deep_code_security.hunter.scanner_backend import BackendResult
from deep_code_security.hunter.source_sink_finder import find_sinks, find_sources
from deep_code_security.hunter.taint_tracker import TaintEngine
from deep_code_security.shared.config import get_config
from deep_code_security.shared.language import Language

if TYPE_CHECKING:
    from deep_code_security.shared.file_discovery import DiscoveredFile

# ``BackendResult`` uses ``RawFinding`` as a forward reference (TYPE_CHECKING
# import in scanner_backend.py).  Calling model_rebuild() here ensures Pydantic
# can resolve the annotation now that ``RawFinding`` is in scope.
BackendResult.model_rebuild()

__all__ = ["TreeSitterBackend"]

logger = logging.getLogger(__name__)

# Severity ordering for threshold filtering (mirrors the orchestrator constant)
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def _sink_severity(category: str, registry: Registry) -> str:
    """Return the highest severity for a sink category from the registry.

    Args:
        category: Sink category name.
        registry: Language registry containing sink entries.

    Returns:
        Severity string (``"critical"``, ``"high"``, ``"medium"``, or
        ``"low"``).
    """
    sink_entries = registry.sinks.get(category, [])
    if not sink_entries:
        return "medium"
    order: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return max((e.severity for e in sink_entries), key=lambda s: order.get(s, 0))


def _cwe_name(cwe: str) -> str:
    """Return a human-readable name for a CWE identifier.

    Args:
        cwe: CWE identifier (e.g. ``"CWE-78"``).

    Returns:
        Human-readable name, or ``"Unknown Vulnerability"`` if not found.
    """
    _names: dict[str, str] = {
        "CWE-78": "OS Command Injection",
        "CWE-89": "SQL Injection",
        "CWE-94": "Code Injection",
        "CWE-22": "Path Traversal",
        "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "CWE-134": "Uncontrolled Format String",
        "CWE-120": "Buffer Copy without Checking Size",
        "CWE-190": "Integer Overflow or Wraparound",
        "CWE-676": "Use of Potentially Dangerous Function",
        "CWE-79": "Cross-site Scripting",
    }
    return _names.get(cwe, "Unknown Vulnerability")


def _compute_raw_confidence(taint_path: Any) -> float:
    """Compute a heuristic confidence score for a finding.

    Mirrors ``HunterOrchestrator._compute_raw_confidence()`` so that both
    backends produce consistent confidence values.

    Args:
        taint_path: ``TaintPath`` instance with ``steps`` and ``sanitized``.

    Returns:
        Float confidence in [0.0, 1.0].
    """
    if taint_path.sanitized:
        return 0.3  # Sanitized paths have low confidence

    step_count = len(taint_path.steps)
    if step_count >= 3:
        return 0.8
    elif step_count >= 2:
        return 0.6
    else:
        return 0.4


class TreeSitterBackend:
    """Scanner backend that wraps the existing tree-sitter pipeline.

    This is a thin adapter: it calls the existing ``parser``, ``registry``,
    ``source_sink_finder``, and ``taint_tracker`` modules in the same order
    that the pre-refactor ``HunterOrchestrator`` did, then returns the results
    as a ``BackendResult``.

    ``is_available()`` always returns ``True`` because tree-sitter is a core
    dependency of the project.
    """

    #: Backend identifier reported in ``BackendResult.backend_name`` and
    #: ``ScanStats.scanner_backend``.
    name: str = "treesitter"

    def __init__(self) -> None:
        self._parser = TreeSitterParser()
        self._registries: dict[Language, Registry] = {}

    @classmethod
    def is_available(cls) -> bool:
        """Return ``True`` — tree-sitter is always available.

        Tree-sitter is a core project dependency; there is no optional binary
        to locate.  This method exists solely to satisfy the ``ScannerBackend``
        protocol.

        Returns:
            Always ``True``.
        """
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_registry(self, language: Language) -> Registry | None:
        """Load (and cache) the registry for *language*.

        Args:
            language: Target programming language.

        Returns:
            ``Registry`` instance, or ``None`` if no registry file exists.
        """
        if language in self._registries:
            return self._registries[language]

        config = get_config()
        try:
            lang_obj = self._parser.get_language_object(language)
            registry = load_registry(language, config.registry_path, lang_obj)
            self._registries[language] = registry
            return registry
        except FileNotFoundError:
            logger.debug("No registry found for %s", language.value)
            return None
        except Exception as exc:
            logger.warning("Failed to load registry for %s: %s", language.value, exc)
            return None

    # ------------------------------------------------------------------
    # Public interface (ScannerBackend protocol)
    # ------------------------------------------------------------------

    def scan_files(
        self,
        target_path: Path,
        discovered_files: list[DiscoveredFile],
        severity_threshold: str,
    ) -> BackendResult:
        """Scan *discovered_files* using the tree-sitter pipeline.

        For each file the adapter:

        1. Loads the language registry (cached across calls).
        2. Parses the file with ``TreeSitterParser``.
        3. Finds sources and sinks via ``find_sources`` / ``find_sinks``.
        4. Runs ``TaintEngine.find_taint_paths()``.
        5. Converts each ``(source, sink, taint_path)`` triple into a
           ``RawFinding``, applying the severity threshold.

        Args:
            target_path: Root directory of the target codebase (used for
                logging only — file paths come from *discovered_files*).
            discovered_files: Pre-filtered list of files to scan.  Each entry
                carries an absolute ``Path`` and a ``Language``.
            severity_threshold: Minimum severity to include
                (``"critical"``, ``"high"``, ``"medium"``, ``"low"``).

        Returns:
            ``BackendResult`` with all findings, source/sink/path counts, and
            any diagnostic messages produced during the scan.
        """
        threshold_level = _SEVERITY_ORDER.get(severity_threshold.lower(), 2)

        all_findings: list[RawFinding] = []
        total_sources = 0
        total_sinks = 0
        total_paths = 0
        diagnostics: list[str] = []
        registry_hashes: list[str] = []

        for discovered_file in discovered_files:
            lang = discovered_file.language

            # Load registry (skip files for which no registry exists)
            registry = self._get_registry(lang)
            if registry is None:
                continue

            if registry.registry_hash not in registry_hashes:
                registry_hashes.append(registry.registry_hash)

            # Parse the file
            try:
                tree = self._parser.parse_file(discovered_file.path, lang)
            except ParseError as exc:
                msg = f"Failed to parse {discovered_file.path}: {exc}"
                logger.warning(msg)
                diagnostics.append(msg)
                continue

            # Get the compiled Language object (needed for on-demand query compilation)
            lang_obj = self._parser.get_language_object(lang)
            file_path_str = str(discovered_file.path)

            # Find sources and sinks
            sources = find_sources(tree, registry, lang_obj, file_path_str)
            sinks = find_sinks(tree, registry, lang_obj, file_path_str)

            total_sources += len(sources)
            total_sinks += len(sinks)

            if not sources or not sinks:
                continue

            # Run taint tracking
            engine = TaintEngine(language=lang, registry=registry)
            taint_paths = engine.find_taint_paths(tree, sources, sinks, file_path_str)
            total_paths += len(taint_paths)

            # Convert taint paths to RawFindings
            for source, sink, taint_path in taint_paths:
                # Apply severity threshold
                severity = _sink_severity(sink.category, registry)
                if _SEVERITY_ORDER.get(severity, 0) < threshold_level:
                    continue

                raw_confidence = _compute_raw_confidence(taint_path)

                finding = RawFinding(
                    source=source,
                    sink=sink,
                    taint_path=taint_path,
                    vulnerability_class=f"{sink.cwe}: {_cwe_name(sink.cwe)}",
                    severity=severity,  # type: ignore[arg-type]
                    language=lang.value,
                    raw_confidence=raw_confidence,
                )
                all_findings.append(finding)

        logger.info(
            "TreeSitterBackend scan complete for %s: %d files, "
            "%d sources, %d sinks, %d taint paths, %d findings",
            target_path,
            len(discovered_files),
            total_sources,
            total_sinks,
            total_paths,
            len(all_findings),
        )

        return BackendResult(
            findings=all_findings,
            sources_found=total_sources,
            sinks_found=total_sinks,
            taint_paths_found=total_paths,
            backend_name=self.name,
            diagnostics=diagnostics,
        )
