"""Semgrep scanner backend for the Hunter phase.

Wraps the ``semgrep`` CLI as a subprocess, parses its JSON output, and
normalises each result into a ``RawFinding`` using rule metadata and
metavariable bindings from Semgrep OSS output.

**Important OSS limitation:** The ``extra.dataflow_trace`` field (containing
``taint_source``, ``intermediate_vars``, and ``taint_sink``) is a Semgrep Pro
feature and is NOT emitted by Semgrep OSS.  The normaliser constructs synthetic
two-step ``TaintPath`` objects entirely from rule metadata and the optional
``$SOURCE`` metavar binding.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from deep_code_security.hunter.models import (
    RawFinding,
    Severity,
    Sink,
    Source,
    TaintPath,
    TaintStep,
)
from deep_code_security.hunter.scanner_backend import BackendResult
from deep_code_security.shared.config import get_config
from deep_code_security.shared.file_discovery import DiscoveredFile

__all__ = ["SemgrepBackend"]

# RawFinding was only a TYPE_CHECKING import in scanner_backend.py, so
# BackendResult's generic list[RawFinding] field was unresolved at definition
# time.  Now that RawFinding is imported at runtime here, we rebuild the model
# so Pydantic can validate findings: list[RawFinding] correctly.
BackendResult.model_rebuild()

logger = logging.getLogger(__name__)

# Semgrep version bounds (warn if outside range, do not block)
_MIN_VERSION = (1, 50, 0)
_MAX_VERSION = (2, 0, 0)  # exclusive

# Semgrep exit codes that indicate "scan completed with findings" vs "error"
# Exit code 0: clean, 1: findings found, 2+: error
_OK_EXIT_CODES = frozenset({0, 1})

# Semgrep severity -> DCS severity mapping
_SEMGREP_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": "critical",
    "WARNING": "high",
    "INFO": "medium",
}

# Regex to extract "CWE-NNN" from strings like "CWE-89: SQL Injection"
_CWE_ID_RE = re.compile(r"^(CWE-\d+)")

# Maximum bytes of Semgrep stderr to log (avoid flooding logs with huge output)
_MAX_STDERR_BYTES = 4096


def _parse_semgrep_version(version_output: str) -> tuple[int, ...] | None:
    """Parse ``semgrep --version`` output into a tuple of ints.

    Args:
        version_output: Raw stdout from ``semgrep --version``.

    Returns:
        Version tuple (e.g. ``(1, 78, 0)``) or ``None`` if unparseable.
    """
    # semgrep --version outputs e.g. "1.78.0" on its own line
    stripped = version_output.strip().split("\n")[0].strip()
    # Strip any leading "v"
    stripped = stripped.lstrip("v")
    parts = stripped.split(".")
    try:
        return tuple(int(p) for p in parts[:3])
    except (ValueError, IndexError):
        return None


def _check_version(binary: str) -> str | None:
    """Run ``semgrep --version``, warn if outside the tested range, and return the version string.

    Args:
        binary: Absolute path to the semgrep binary.

    Returns:
        The raw version string (e.g. ``"1.78.0"``) or ``None`` if the version
        could not be determined.
    """
    try:
        result = subprocess.run(  # noqa: S603
            [binary, "--version"],
            capture_output=True,
            timeout=10,
            text=True,
        )
        raw_version_str = result.stdout.strip().split("\n")[0].strip()
        version = _parse_semgrep_version(result.stdout)
        if version is None:
            logger.warning(
                "Could not parse semgrep version from output %r; "
                "proceeding but version compatibility is unverified.",
                result.stdout.strip()[:200],
            )
            return raw_version_str or None
        if version < _MIN_VERSION or version >= _MAX_VERSION:
            logger.warning(
                "Semgrep version %s is outside the tested range [%s, %s). "
                "The backend will proceed but behaviour may differ from expectations.",
                ".".join(str(p) for p in version),
                ".".join(str(p) for p in _MIN_VERSION),
                ".".join(str(p) for p in _MAX_VERSION),
            )
        else:
            logger.debug(
                "Semgrep version %s is within the tested range.",
                ".".join(str(p) for p in version),
            )
        return ".".join(str(p) for p in version)
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("Could not run 'semgrep --version': %s", exc)
        return None


def _extract_cwe_id(cwe_entry: str) -> str:
    """Extract the bare CWE identifier from a Semgrep metadata cwe string.

    Args:
        cwe_entry: Full string such as ``"CWE-89: SQL Injection"``.

    Returns:
        Short identifier such as ``"CWE-89"``.
    """
    match = _CWE_ID_RE.match(cwe_entry.strip())
    if match:
        return match.group(1)
    return cwe_entry.strip()


def _detect_language_from_path(path: Path) -> str:
    """Detect a language name from file extension.

    Returns a lowercase language name suitable for ``Source.language`` /
    ``Sink.language`` / ``RawFinding.language``.

    Args:
        path: Path to the source file.

    Returns:
        Language name (e.g. ``"python"``, ``"go"``, ``"c"``).
    """
    suffix = path.suffix.lower()
    if suffix in {".py", ".pyw"}:
        return "python"
    if suffix in {".go"}:
        return "go"
    if suffix in {".c", ".h"}:
        return "c"
    if suffix in {".cpp", ".cc", ".cxx", ".hpp"}:
        return "cpp"
    if suffix in {".js", ".mjs", ".cjs"}:
        return "javascript"
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    if suffix in {".java"}:
        return "java"
    if suffix in {".rb"}:
        return "ruby"
    if suffix in {".php"}:
        return "php"
    # Fall back to a generic non-empty name so ``_LANGUAGE_RE`` still passes
    return "unknown"


class SemgrepBackend:
    """Scanner backend that delegates to the ``semgrep`` CLI.

    This backend:

    1. Invokes ``semgrep --config <rules_dir> --json --metrics=off
       --no-git-ignore --timeout <t> --max-target-bytes 1048576
       <target_path>`` as a subprocess (list-form args, never ``shell=True``).
    2. Parses the JSON output from stdout.
    3. Post-filters results to only files present in ``discovered_files``.
    4. Normalises each result into a ``RawFinding`` via ``_normalize_result()``.
    5. Returns a ``BackendResult`` with all findings and diagnostics.

    The normaliser constructs Source, Sink, and TaintPath from Semgrep OSS
    output fields (rule metadata + metavar bindings).  It does NOT use
    ``extra.dataflow_trace`` because that is a Semgrep Pro feature absent from
    OSS output.
    """

    name: str = "semgrep"

    # Class-level cache for the binary check (reset between tests via _available_cache = None).
    # The binary presence check is cached; the rules-dir check is NOT cached because
    # DCS_SEMGREP_RULES_PATH can change between calls (e.g., during tests).
    _available_cache: bool | None = None
    _binary_cache: str | None = None

    # Cached version string from ``semgrep --version`` (set when is_available() succeeds).
    _cached_version: str | None = None

    @classmethod
    def is_available(cls) -> bool:
        """Return True if the semgrep binary is found and the rules dir has rules.

        Checks:
        - ``shutil.which("semgrep")`` is not None (result cached class-wide).
        - ``DCS_SEMGREP_RULES_PATH`` directory exists and contains at least one
          ``.yaml`` file (recursively, checked every call because the path can
          change between tests or config reloads).

        The version range check is informational only and does not block
        availability.  The version string is cached in ``_cached_version``.

        Returns:
            True if all prerequisites are satisfied.
        """
        # Cache only the binary lookup — it is expensive and stable within a process.
        if cls._binary_cache is None:
            cls._binary_cache = shutil.which("semgrep") or ""
        binary = cls._binary_cache or None

        if binary is None:
            logger.debug("SemgrepBackend.is_available(): 'semgrep' not found on $PATH.")
            return False

        # Rules-dir check is NOT cached — DCS_SEMGREP_RULES_PATH can change between
        # calls in tests or when the config is reloaded via reset_config().
        config = get_config()
        rules_path = config.semgrep_rules_path

        if not rules_path.is_dir():
            logger.warning(
                "SemgrepBackend.is_available(): rules directory does not exist: %s",
                rules_path,
            )
            return False

        yaml_files = list(rules_path.rglob("*.yaml"))
        if not yaml_files:
            logger.warning(
                "SemgrepBackend.is_available(): rules directory %s contains no .yaml files.",
                rules_path,
            )
            return False

        # Non-blocking version check — only run once and cache the result.
        if cls._cached_version is None:
            cls._cached_version = _check_version(binary) or ""

        logger.debug(
            "SemgrepBackend.is_available(): binary=%s, rules=%s (%d yaml files).",
            binary,
            rules_path,
            len(yaml_files),
        )
        return True

    @property
    def version(self) -> str | None:
        """Return the cached semgrep version string, or None if unavailable."""
        return self._cached_version or None

    def scan_files(
        self,
        target_path: Path,
        discovered_files: list[DiscoveredFile],
        severity_threshold: str,
    ) -> BackendResult:
        """Scan the target using Semgrep and return normalised findings.

        Args:
            target_path: Root of the target codebase.
            discovered_files: Pre-filtered list of files DCS has approved for
                scanning.  Results from files outside this list are discarded.
            severity_threshold: Minimum severity to include (currently unused
                at the subprocess level -- filtering happens post-normalisation
                in the orchestrator).

        Returns:
            ``BackendResult`` with findings, counts, and diagnostics.
        """
        config = get_config()
        rules_path = config.semgrep_rules_path
        timeout = config.semgrep_timeout
        diagnostics: list[str] = []

        # Build the set of approved absolute paths for post-filtering
        approved_paths: set[Path] = {f.path.resolve() for f in discovered_files}

        binary = shutil.which("semgrep")
        if binary is None:
            diagnostics.append(
                "Semgrep binary not found on $PATH; returning empty result."
            )
            return BackendResult(
                findings=[],
                backend_name=self.name,
                diagnostics=diagnostics,
            )

        cmd = [
            binary,
            "--config",
            str(rules_path),
            "--json",
            "--metrics=off",
            "--no-git-ignore",
            "--timeout",
            str(timeout),
            "--max-target-bytes",
            "1048576",
            str(target_path),
        ]

        logger.debug("Running semgrep command: %s", cmd)

        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                timeout=timeout + 5,
            )
        except subprocess.TimeoutExpired:
            msg = (
                f"Semgrep subprocess timed out after {timeout + 5}s. "
                "Returning empty result. Consider increasing DCS_SEMGREP_TIMEOUT."
            )
            logger.warning(msg)
            diagnostics.append(msg)
            return BackendResult(
                findings=[],
                backend_name=self.name,
                diagnostics=diagnostics,
            )
        except OSError as exc:
            msg = f"Failed to launch semgrep subprocess: {exc}"
            logger.warning(msg)
            diagnostics.append(msg)
            return BackendResult(
                findings=[],
                backend_name=self.name,
                diagnostics=diagnostics,
            )

        # Semgrep uses exit code 1 to signal "findings found" (not an error)
        if proc.returncode not in _OK_EXIT_CODES:
            stderr_snippet = proc.stderr[:_MAX_STDERR_BYTES].decode("utf-8", errors="replace")
            msg = (
                f"Semgrep exited with code {proc.returncode}. "
                f"stderr: {stderr_snippet!r}"
            )
            logger.warning(msg)
            diagnostics.append(msg)
            return BackendResult(
                findings=[],
                backend_name=self.name,
                diagnostics=diagnostics,
            )

        # Log any stderr output as a warning (even on success)
        if proc.stderr:
            stderr_snippet = proc.stderr[:_MAX_STDERR_BYTES].decode("utf-8", errors="replace")
            logger.debug("Semgrep stderr: %s", stderr_snippet)

        try:
            output = json.loads(proc.stdout)
        except (json.JSONDecodeError, ValueError) as exc:
            msg = f"Failed to parse Semgrep JSON output: {exc}"
            logger.warning(msg)
            diagnostics.append(msg)
            return BackendResult(
                findings=[],
                backend_name=self.name,
                diagnostics=diagnostics,
            )

        results_list: list[dict[str, Any]] = output.get("results", [])

        # Warn if rules exist but no results at all
        yaml_files = list(rules_path.rglob("*.yaml"))
        if not results_list and yaml_files:
            logger.debug(
                "Semgrep returned no results despite %d rule file(s) in %s. "
                "This may indicate a clean codebase or misconfigured rules.",
                len(yaml_files),
                rules_path,
            )

        findings: list[RawFinding] = []
        filtered_out = 0

        for raw_result in results_list:
            # Resolve file path and post-filter against discovered_files
            raw_path_str = raw_result.get("path", "")
            if not raw_path_str:
                logger.debug("Skipping result with empty path: %s", raw_result.get("check_id"))
                continue

            resolved_file = (target_path / raw_path_str).resolve()

            if resolved_file not in approved_paths:
                filtered_out += 1
                logger.debug(
                    "Filtered out finding for %s (not in discovered_files).",
                    resolved_file,
                )
                continue

            finding = self._normalize_result(raw_result, target_path)
            if finding is not None:
                findings.append(finding)

        if filtered_out > 0:
            msg = (
                f"Semgrep post-filter: {filtered_out} finding(s) excluded because "
                "their file was not in the discovered_files list "
                "(possibly matched by Semgrep but outside DCS_MAX_FILES scope or "
                "excluded by language filter)."
            )
            logger.info(msg)
            diagnostics.append(msg)

        count = len(findings)
        logger.info(
            "SemgrepBackend.scan_files(): %d finding(s) after post-filtering.", count
        )

        # Semgrep OSS does not expose discrete source/sink counts in its output.
        # Setting sources_found and sinks_found to 0 honestly reflects this
        # limitation.  taint_paths_found is the number of matched taint paths,
        # which equals the number of accepted findings after post-filtering.
        return BackendResult(
            findings=findings,
            sources_found=0,
            sinks_found=0,
            taint_paths_found=count,
            backend_name=self.name,
            diagnostics=diagnostics,
        )

    def _normalize_result(
        self,
        result: dict[str, Any],
        target_path: Path,
    ) -> RawFinding | None:
        """Normalise a single Semgrep OSS result into a ``RawFinding``.

        Required fields (result is skipped with a log message if any are absent):
        - ``check_id``
        - ``path``
        - ``start`` (with ``line`` and ``col``)
        - ``extra.metadata.cwe`` (non-empty list)

        Args:
            result: A single entry from Semgrep's ``results`` array.
            target_path: Root path used to resolve relative ``path`` values.

        Returns:
            A ``RawFinding`` on success, or ``None`` if required fields are missing.
        """
        check_id: str | None = result.get("check_id")
        if not check_id:
            logger.debug("Skipping result: missing check_id.")
            return None

        raw_path: str | None = result.get("path")
        if not raw_path:
            logger.debug("Skipping result %r: missing path.", check_id)
            return None

        start: dict[str, Any] | None = result.get("start")
        if not start:
            logger.debug("Skipping result %r: missing start.", check_id)
            return None

        extra: dict[str, Any] = result.get("extra", {})
        metadata: dict[str, Any] = extra.get("metadata", {})

        cwe_list: list[str] = metadata.get("cwe", [])
        if not cwe_list:
            logger.debug(
                "Skipping result %r: missing or empty extra.metadata.cwe.", check_id
            )
            return None

        # --- Resolve the absolute file path ---
        resolved_file = (target_path / raw_path).resolve()
        file_str = str(resolved_file)

        # --- Detect language from file extension ---
        language = _detect_language_from_path(resolved_file)

        # --- Parse CWE ---
        cwe_id = _extract_cwe_id(cwe_list[0])
        vulnerability_class = cwe_list[0].strip()  # full string e.g. "CWE-89: SQL Injection"

        # --- Match location (used for sink and fallback source) ---
        match_line: int = start.get("line", 1)
        match_col: int = start.get("col", 0)

        # --- Source location: prefer $SOURCE metavar, fall back to match location ---
        metavars: dict[str, Any] = extra.get("metavars", {})
        source_metavar: dict[str, Any] | None = metavars.get("$SOURCE")

        if source_metavar and isinstance(source_metavar, dict):
            sv_start = source_metavar.get("start", {})
            source_line: int = sv_start.get("line", match_line)
            source_col: int = sv_start.get("col", match_col)
        else:
            source_line = match_line
            source_col = match_col

        # --- Metadata-driven Source / Sink attributes ---
        source_function: str = metadata.get("source_function", "unknown")
        source_category: str = metadata.get("source_category", "unknown")
        sink_function: str = metadata.get("sink_function", "unknown")
        sink_category: str = metadata.get("sink_category", "unknown")

        # --- Severity ---
        # Valid DCS severity values (matches the Severity Literal type)
        _VALID_DCS_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
        dcs_severity_raw: str | None = metadata.get("dcs_severity")
        if dcs_severity_raw and dcs_severity_raw.lower() in _VALID_DCS_SEVERITIES:
            severity: Severity = dcs_severity_raw.lower()  # type: ignore[assignment]
        else:
            semgrep_severity: str = extra.get("severity", "INFO").upper()
            severity = _SEMGREP_SEVERITY_MAP.get(semgrep_severity, "medium")

        # --- Construct Source ---
        source = Source(
            file=file_str,
            line=source_line,
            column=source_col,
            function=source_function,
            category=source_category,
            language=language,
        )

        # --- Construct Sink ---
        sink = Sink(
            file=file_str,
            line=match_line,
            column=match_col,
            function=sink_function,
            category=sink_category,
            cwe=cwe_id,
            language=language,
        )

        # --- Construct synthetic two-step TaintPath ---
        # Semgrep OSS does not emit dataflow_trace; we always produce a
        # synthetic path with source_step + sink_step.  TaintPath.sanitized
        # is always False because Semgrep taint mode filters sanitized paths
        # internally and does not report them.
        source_step = TaintStep(
            file=file_str,
            line=source_line,
            column=source_col,
            variable="source",
            transform="assignment",
        )
        sink_step = TaintStep(
            file=file_str,
            line=match_line,
            column=match_col,
            variable="sink",
            transform="assignment",
        )
        taint_path = TaintPath(
            steps=[source_step, sink_step],
            sanitized=False,
        )

        # --- Raw confidence: 0.6 for a synthetic two-step path ---
        # This reflects partial taint completeness (Semgrep OSS = 2-step path,
        # same as the tree-sitter partial path case in the scoring model).
        raw_confidence = 0.6

        return RawFinding(
            source=source,
            sink=sink,
            taint_path=taint_path,
            vulnerability_class=vulnerability_class,
            severity=severity,
            language=language,
            raw_confidence=raw_confidence,
        )
