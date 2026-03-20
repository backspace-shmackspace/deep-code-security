"""Hunter phase orchestration — coordinates parsing, source/sink finding, and taint tracking."""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from pathlib import Path

from deep_code_security.hunter.models import RawFinding, ScanStats
from deep_code_security.hunter.parser import TreeSitterParser
from deep_code_security.hunter.registry import Registry, load_registry
from deep_code_security.shared.config import Config, get_config
from deep_code_security.shared.file_discovery import FileDiscovery
from deep_code_security.shared.language import Language
from deep_code_security.shared.suppressions import (
    SuppressionResult,
    apply_suppressions,
    load_suppressions,
)

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

    Coordinates: path validation -> file discovery -> backend.scan_files()
    -> suppressions -> dedup -> sort -> paginate
    """

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or get_config()
        self.parser = TreeSitterParser()
        self._registries: dict[Language, Registry] = {}
        # Session store for findings (keyed by scan_id, used by Auditor)
        self._session_findings: dict[str, list[RawFinding]] = {}
        # Most recent suppression result (populated by scan() when a suppression file exists)
        self._last_suppression_result: SuppressionResult | None = None

        # Select scanner backend based on DCS_SCANNER_BACKEND config.
        # RuntimeError propagates if DCS_SCANNER_BACKEND=semgrep but the binary is missing.
        from deep_code_security.hunter.scanner_backend import select_backend  # noqa: PLC0415
        self._backend = select_backend(self.config.scanner_backend)

    @property
    def last_suppression_result(self) -> SuppressionResult | None:
        """Return the SuppressionResult from the most recent scan, or None.

        Populated when a `.dcs-suppress.yaml` file is found and suppressions
        are applied. Callers (e.g., SARIF formatter, CLI) can use this to
        access suppressed finding objects and per-finding reasons.
        """
        return self._last_suppression_result

    def scan(
        self,
        target_path: str | Path,
        languages: list[str] | None = None,
        severity_threshold: str = "medium",
        max_results: int = 100,
        offset: int = 0,
        ignore_suppressions: bool = False,
    ) -> tuple[list[RawFinding], ScanStats, int, bool]:
        """Run a full Hunter scan.

        Args:
            target_path: Path to the target codebase.
            languages: Optional language filter (e.g., ['python', 'go']).
            severity_threshold: Minimum severity to include ('critical', 'high', 'medium', 'low').
            max_results: Maximum findings to return per page.
            offset: Pagination offset.
            ignore_suppressions: When True, skip loading .dcs-suppress.yaml and
                return all findings. Useful for periodic full-pipeline verification
                of suppressed findings.

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

        # Delegate scanning to the selected backend
        backend_result = self._backend.scan_files(
            target_path, discovered_files, severity_threshold
        )
        raw_findings = backend_result.findings
        stats.sources_found = backend_result.sources_found
        stats.sinks_found = backend_result.sinks_found
        stats.taint_paths_found = backend_result.taint_paths_found
        stats.scanner_backend = self._backend.name

        if backend_result.diagnostics:
            for diag in backend_result.diagnostics:
                logger.warning("Scanner backend diagnostic: %s", diag)

        all_findings: list[RawFinding] = list(raw_findings)

        # Deduplicate: multiple sources flowing to the same sink are one vulnerability.
        # Key on (file, sink_line, cwe) and keep the highest-confidence finding.
        all_findings = _deduplicate_findings(all_findings)

        # Apply suppressions (after deduplication, before sorting and pagination)
        suppression_result: SuppressionResult | None = None
        self._last_suppression_result = None
        if not ignore_suppressions:
            try:
                suppress_config = load_suppressions(target_path)
                if suppress_config is not None:
                    suppression_result = apply_suppressions(
                        all_findings, suppress_config, target_path
                    )
                    all_findings = suppression_result.active_findings
                    self._last_suppression_result = suppression_result
                    logger.info(
                        "Suppressions applied: %d suppressed, %d active (%d rules, %d expired)",
                        len(suppression_result.suppressed_findings),
                        len(suppression_result.active_findings),
                        suppression_result.total_rules,
                        suppression_result.expired_rules,
                    )
            except (ValueError, OSError) as e:
                # Re-raise so CLI/MCP can report a clear error to the user
                logger.error("Failed to load suppressions file: %s", e)
                raise

        # Populate ScanStats suppression fields
        stats.findings_suppressed = (
            len(suppression_result.suppressed_findings) if suppression_result else 0
        )
        stats.suppression_rules_loaded = (
            suppression_result.total_rules if suppression_result else 0
        )
        stats.suppression_rules_expired = (
            suppression_result.expired_rules if suppression_result else 0
        )
        stats.suppressed_finding_ids = (
            list(suppression_result.suppression_reasons.keys())
            if suppression_result else []
        )

        # Sort by severity (critical first) and confidence
        all_findings.sort(
            key=lambda f: (
                -_SEVERITY_ORDER.get(f.severity, 0),
                -f.raw_confidence,
            )
        )

        # Compute registry version hash.
        # The backend provides a hash of the registry/rule files it consumed.
        # Fall back to a hash of backend name + detected languages when the backend
        # does not expose per-file hashes (e.g., Semgrep backend).
        _hash_input = ":".join(
            sorted([self._backend.name] + stats.languages_detected)
        )
        combined_hash = hashlib.sha256(_hash_input.encode()).hexdigest()[:16]
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


def _deduplicate_findings(findings: list[RawFinding]) -> list[RawFinding]:
    """Collapse findings that share the same sink into a single finding.

    Multiple sources flowing to the same sink represent one vulnerability
    (the fix is at the sink). We group by (file, sink_line, cwe) and keep
    the finding with the highest confidence and most complete taint path.

    Args:
        findings: List of raw findings, possibly with duplicates.

    Returns:
        Deduplicated list of findings.
    """
    best: dict[tuple[str, int, str], RawFinding] = {}
    for finding in findings:
        key = (finding.sink.file, finding.sink.line, finding.sink.cwe)
        existing = best.get(key)
        if existing is None:
            best[key] = finding
        else:
            # Prefer: higher confidence, then more taint steps (richer path)
            new_better = (
                finding.raw_confidence > existing.raw_confidence
                or (
                    finding.raw_confidence == existing.raw_confidence
                    and len(finding.taint_path.steps) > len(existing.taint_path.steps)
                )
            )
            if new_better:
                best[key] = finding
    return list(best.values())


