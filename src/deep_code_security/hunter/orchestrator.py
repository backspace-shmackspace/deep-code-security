"""Hunter phase orchestration — coordinates parsing, source/sink finding, and taint tracking."""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from deep_code_security.hunter.models import RawFinding, ScanStats
from deep_code_security.hunter.parser import ParseError, TreeSitterParser
from deep_code_security.hunter.registry import Registry, load_registry
from deep_code_security.hunter.source_sink_finder import find_sinks, find_sources
from deep_code_security.hunter.taint_tracker import TaintEngine
from deep_code_security.shared.config import Config, get_config
from deep_code_security.shared.file_discovery import FileDiscovery
from deep_code_security.shared.language import Language

__all__ = ["HunterOrchestrator"]

logger = logging.getLogger(__name__)

# Severity ordering for filtering and sorting
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


class HunterOrchestrator:
    """Orchestrates the Hunter (Discovery) phase.

    Coordinates: path validation -> file discovery -> parse -> find sources/sinks
    -> taint track -> aggregate findings -> paginate
    """

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or get_config()
        self.parser = TreeSitterParser()
        self._registries: dict[Language, Registry] = {}
        # Session store for findings (keyed by scan_id, used by Auditor)
        self._session_findings: dict[str, list[RawFinding]] = {}

    def scan(
        self,
        target_path: str | Path,
        languages: list[str] | None = None,
        severity_threshold: str = "medium",
        max_results: int = 100,
        offset: int = 0,
    ) -> tuple[list[RawFinding], ScanStats, int, bool]:
        """Run a full Hunter scan.

        Args:
            target_path: Path to the target codebase.
            languages: Optional language filter (e.g., ['python', 'go']).
            severity_threshold: Minimum severity to include ('critical', 'high', 'medium', 'low').
            max_results: Maximum findings to return per page.
            offset: Pagination offset.

        Returns:
            Tuple of (findings_page, stats, total_count, has_more).
        """
        start_ms = time.monotonic() * 1000
        target_path = Path(target_path)

        # Parse language filter
        lang_filter: list[Language] | None = None
        if languages:
            lang_filter = []
            for lang_str in languages:
                try:
                    lang_filter.append(Language(lang_str.lower()))
                except ValueError:
                    logger.warning("Unknown language filter: %s", lang_str)

        # File discovery
        discovery = FileDiscovery(max_files=self.config.max_files)
        discovered_files, skipped = discovery.discover(target_path, languages=lang_filter)

        stats = ScanStats(
            files_scanned=len(discovered_files),
            files_skipped=skipped,
            languages_detected=list(
                {f.language.value for f in discovered_files}
            ),
        )

        # Load registries for detected languages
        threshold_level = _SEVERITY_ORDER.get(severity_threshold.lower(), 2)

        all_findings: list[RawFinding] = []
        registry_hashes: list[str] = []

        for discovered_file in discovered_files:
            lang = discovered_file.language

            # Load registry for this language (cached)
            registry = self._get_registry(lang)
            if registry is None:
                continue

            if registry.registry_hash not in registry_hashes:
                registry_hashes.append(registry.registry_hash)

            # Parse the file
            try:
                tree = self.parser.parse_file(discovered_file.path, lang)
            except ParseError as e:
                logger.warning("Failed to parse %s: %s", discovered_file.path, e)
                stats.files_skipped += 1
                stats.files_scanned -= 1
                continue

            # Get language object for query compilation
            lang_obj = self.parser.get_language_object(lang)
            file_path_str = str(discovered_file.path)

            # Find sources and sinks
            sources = find_sources(tree, registry, lang_obj, file_path_str)
            sinks = find_sinks(tree, registry, lang_obj, file_path_str)

            stats.sources_found += len(sources)
            stats.sinks_found += len(sinks)

            if not sources or not sinks:
                continue

            # Run taint tracking
            engine = TaintEngine(language=lang, registry=registry)
            taint_paths = engine.find_taint_paths(tree, sources, sinks, file_path_str)
            stats.taint_paths_found += len(taint_paths)

            # Build RawFindings from taint paths
            for source, sink, taint_path in taint_paths:
                # Apply severity threshold
                sink_severity = sink_finding_severity(sink.category, registry)
                if _SEVERITY_ORDER.get(sink_severity, 0) < threshold_level:
                    continue

                # Compute raw confidence heuristic
                raw_confidence = self._compute_raw_confidence(taint_path)

                finding = RawFinding(
                    source=source,
                    sink=sink,
                    taint_path=taint_path,
                    vulnerability_class=f"{sink.cwe}: {_cwe_name(sink.cwe)}",
                    severity=sink_severity,  # type: ignore[arg-type]
                    language=lang.value,
                    raw_confidence=raw_confidence,
                )
                all_findings.append(finding)

        # Sort by severity (critical first) and confidence
        all_findings.sort(
            key=lambda f: (
                -_SEVERITY_ORDER.get(f.severity, 0),
                -f.raw_confidence,
            )
        )

        # Compute registry version hash
        combined_hash = hashlib.sha256(
            ":".join(sorted(registry_hashes)).encode()
        ).hexdigest()[:16]
        stats.registry_version_hash = combined_hash

        # Compute duration
        duration_ms = int(time.monotonic() * 1000 - start_ms)
        stats.scan_duration_ms = duration_ms

        # Store in session
        scan_id = str(uuid.uuid4())
        self._session_findings[scan_id] = all_findings

        # Paginate
        total_count = len(all_findings)
        page = all_findings[offset : offset + max_results]
        has_more = (offset + max_results) < total_count

        logger.info(
            "Hunter scan complete: %d files, %d findings (%d total), %dms",
            stats.files_scanned, len(page), total_count, duration_ms,
        )

        return page, stats, total_count, has_more

    def _get_registry(self, language: Language) -> Registry | None:
        """Get (or load) the registry for a language.

        Args:
            language: Programming language.

        Returns:
            Registry or None if registry file not found.
        """
        if language in self._registries:
            return self._registries[language]

        try:
            lang_obj = self.parser.get_language_object(language)
            registry = load_registry(language, self.config.registry_path, lang_obj)
            self._registries[language] = registry
            return registry
        except FileNotFoundError:
            logger.debug("No registry found for %s", language.value)
            return None
        except Exception as e:
            logger.warning("Failed to load registry for %s: %s", language.value, e)
            return None

    def _compute_raw_confidence(self, taint_path: Any) -> float:
        """Compute a heuristic confidence score for a finding.

        Args:
            taint_path: TaintPath with steps and sanitizer info.

        Returns:
            Float confidence between 0.0 and 1.0.
        """
        if taint_path.sanitized:
            return 0.3  # Sanitized paths have low confidence

        # More taint steps = more confidence (up to a point)
        step_count = len(taint_path.steps)
        if step_count >= 3:
            return 0.8
        elif step_count >= 2:
            return 0.6
        else:
            return 0.4

    def get_findings_for_ids(self, finding_ids: list[str]) -> list[RawFinding]:
        """Retrieve findings from session store by ID.

        Args:
            finding_ids: List of finding UUIDs from a previous scan.

        Returns:
            List of matching RawFinding instances.
        """
        result: list[RawFinding] = []
        for session_findings in self._session_findings.values():
            for finding in session_findings:
                if finding.id in finding_ids:
                    result.append(finding)
        return result

    def store_findings(self, findings: list[RawFinding], scan_id: str | None = None) -> str:
        """Store findings in the session store.

        Args:
            findings: Findings to store.
            scan_id: Optional session ID; auto-generated if not provided.

        Returns:
            The scan session ID.
        """
        sid = scan_id or str(uuid.uuid4())
        self._session_findings[sid] = findings
        return sid


def sink_finding_severity(category: str, registry: Registry) -> str:
    """Get the severity for a sink category from the registry.

    Args:
        category: Sink category name.
        sink_entries: Sink entries from the registry.

    Returns:
        Severity string.
    """
    sink_entries = registry.sinks.get(category, [])
    if not sink_entries:
        return "medium"
    # Use the highest severity of any entry in the category
    severities = [e.severity for e in sink_entries]
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return max(severities, key=lambda s: order.get(s, 0))


def _cwe_name(cwe: str) -> str:
    """Get a human-readable name for a CWE identifier.

    Args:
        cwe: CWE identifier (e.g., 'CWE-78').

    Returns:
        Human-readable name.
    """
    _cwe_names = {
        "CWE-78": "OS Command Injection",
        "CWE-89": "SQL Injection",
        "CWE-94": "Code Injection",
        "CWE-22": "Path Traversal",
        "CWE-134": "Uncontrolled Format String",
        "CWE-120": "Buffer Copy without Checking Size",
        "CWE-676": "Use of Potentially Dangerous Function",
        "CWE-79": "Cross-site Scripting",
    }
    return _cwe_names.get(cwe, "Unknown Vulnerability")
