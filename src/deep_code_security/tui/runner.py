"""Async subprocess runner for dcs CLI commands.

Wraps ``asyncio.create_subprocess_exec()`` to launch ``dcs`` CLI commands,
stream stderr output in real time, and produce :class:`RunMeta` metadata on
completion.  Format conversion (JSON to SARIF/HTML) is performed in-process
using the ``shared.formatters`` registry -- see Deviation D-3 in the plan.

This module has **no** dependency on ``textual``.  It is safe to import and
test without the optional TUI dependency installed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from deep_code_security import __version__
from deep_code_security.tui.models import RunMeta, ScanConfig

__all__ = [
    "PATTERN_ERROR",
    "PATTERN_FINDINGS_COUNT",
    "PATTERN_PHASE_TRANSITION",
    "PATTERN_SCANNING",
    "ScanRunner",
    "parse_stderr_line",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Stderr pattern constants (named regexes for maintainability)
# ---------------------------------------------------------------------------

#: Matches: ``Scanning /path/to/target...``
PATTERN_SCANNING = re.compile(r"^Scanning\s+(?P<path>.+?)\.\.\.\s*$")

#: Matches: ``[1/3] Scanning...``, ``[2/3] Verifying 47 findings...``
PATTERN_PHASE_TRANSITION = re.compile(
    r"^\[(?P<current>\d+)/(?P<total>\d+)\]\s+(?P<description>.+)$"
)

#: Matches: ``Found 12 findings in 34 files``
#: Also handles leading whitespace: ``  Found 12 findings in 34 files``
PATTERN_FINDINGS_COUNT = re.compile(
    r"^\s*Found\s+(?P<findings>\d+)\s+findings?\s+in\s+(?P<files>\d+)\s+files?\s*$"
)

#: Matches: ``Error: something went wrong``
PATTERN_ERROR = re.compile(r"^Error:\s*(?P<message>.+)$")

# Graceful-termination timeout before SIGKILL (seconds).
_CANCEL_GRACE_SECONDS = 5

# ---------------------------------------------------------------------------
# Scan-type -> CLI command mapping
# ---------------------------------------------------------------------------

_SCAN_TYPE_TO_COMMAND: dict[str, str] = {
    "hunt": "hunt",
    "full-scan": "full-scan",
    "hunt-fuzz": "hunt-fuzz",
    "fuzz": "fuzz",
}

# Report-file prefix per scan type.
_SCAN_TYPE_TO_PREFIX: dict[str, str] = {
    "hunt": "hunt",
    "full-scan": "full",
    "hunt-fuzz": "hunt-fuzz",
    "fuzz": "fuzz",
}

# Formatter method name per scan type.
_SCAN_TYPE_TO_FORMAT_METHOD: dict[str, str] = {
    "hunt": "format_hunt",
    "full-scan": "format_full_scan",
    "hunt-fuzz": "format_hunt_fuzz",
    "fuzz": "format_fuzz",
}


# ---------------------------------------------------------------------------
# Stderr line parser
# ---------------------------------------------------------------------------


def parse_stderr_line(line: str) -> dict[str, Any]:
    """Parse a single stderr line and return a structured dict.

    Returns a dict with at minimum ``{"type": ..., "raw": line}``.

    Possible ``type`` values:

    * ``"scanning"`` -- scan started, includes ``path``
    * ``"phase"`` -- phase transition, includes ``current``, ``total``,
      ``description``
    * ``"findings"`` -- intermediate result count, includes ``findings``,
      ``files``
    * ``"error"`` -- error line, includes ``message``
    * ``"other"`` -- unrecognized, ``raw`` is the original line
    """
    m = PATTERN_SCANNING.match(line)
    if m:
        return {"type": "scanning", "path": m.group("path"), "raw": line}

    m = PATTERN_PHASE_TRANSITION.match(line)
    if m:
        return {
            "type": "phase",
            "current": int(m.group("current")),
            "total": int(m.group("total")),
            "description": m.group("description"),
            "raw": line,
        }

    m = PATTERN_FINDINGS_COUNT.match(line)
    if m:
        return {
            "type": "findings",
            "findings": int(m.group("findings")),
            "files": int(m.group("files")),
            "raw": line,
        }

    m = PATTERN_ERROR.match(line)
    if m:
        return {"type": "error", "message": m.group("message"), "raw": line}

    return {"type": "other", "raw": line}


# ---------------------------------------------------------------------------
# ScanRunner
# ---------------------------------------------------------------------------


class ScanRunner:
    """Async subprocess runner for dcs CLI commands.

    Launches a ``dcs`` CLI command via ``asyncio.create_subprocess_exec()``,
    streams stderr to an optional callback, captures JSON output, and
    produces derived SARIF/HTML reports in-process.
    """

    def __init__(
        self,
        scan_config: ScanConfig,
        run_dir: Path,
        on_stderr_line: Callable[[str], None] | None = None,
        on_complete: Callable[[int], None] | None = None,
    ) -> None:
        """Initialize the runner.

        Args:
            scan_config: Configuration for the scan to run.
            run_dir: Directory to write report files to.
            on_stderr_line: Callback invoked for each line of stderr output
                (progress updates, phase transitions).
            on_complete: Callback invoked when the subprocess exits with its
                exit code.
        """
        self._config = scan_config
        self._run_dir = run_dir
        self._on_stderr_line = on_stderr_line
        self._on_complete = on_complete
        self._process: asyncio.subprocess.Process | None = None
        self._cancelled = False

    def build_command(self) -> list[str]:
        """Build the dcs CLI command as a list of arguments.

        Returns a list suitable for ``asyncio.create_subprocess_exec()``.
        Never uses ``shell=True``.  All scan options are derived from
        explicitly-typed :class:`ScanConfig` fields -- no free-form
        arguments.
        """
        scan_type = self._config.scan_type
        prefix = _SCAN_TYPE_TO_PREFIX[scan_type]
        json_output_file = str(self._run_dir / f"{prefix}.json")

        cmd: list[str] = [
            sys.executable,
            "-m",
            "deep_code_security.cli",
            _SCAN_TYPE_TO_COMMAND[scan_type],
            self._config.target_path,
            "--format",
            "json",
            "--output-file",
            json_output_file,
            "--force",
        ]

        # Language filters
        for lang in self._config.languages:
            cmd.extend(["-l", lang])

        # Severity threshold
        if self._config.severity_threshold != "medium":
            cmd.extend(["--severity", self._config.severity_threshold])

        # Scan-type-specific flags
        if scan_type == "full-scan" and self._config.skip_verify:
            cmd.append("--skip-verify")

        if scan_type in ("hunt", "full-scan", "hunt-fuzz") and self._config.ignore_suppressions:
            cmd.append("--ignore-suppressions")

        if scan_type in ("fuzz", "hunt-fuzz"):
            cmd.append("--consent")
            if self._config.plugin != "python":
                cmd.extend(["--plugin", self._config.plugin])

        return cmd

    async def run(self) -> RunMeta:
        """Execute the scan and return the run metadata.

        Launches the subprocess, streams stderr to the callback, captures
        stdout, and writes report files to ``run_dir``.

        The scan runs ONCE with ``--format json``.  After completion, SARIF
        and HTML are derived from the JSON output using the shared formatter
        registry (in-process, no additional subprocess).

        Returns:
            A populated :class:`RunMeta`.
        """
        cmd = self.build_command()
        start_time = time.monotonic()
        error_message = ""

        # Build subprocess environment: add the report output directory to
        # DCS_ALLOWED_PATHS so the CLI can write report files there.
        env = os.environ.copy()
        run_dir_str = str(self._run_dir.resolve())
        existing = env.get("DCS_ALLOWED_PATHS", "")
        if existing:
            env["DCS_ALLOWED_PATHS"] = f"{existing},{run_dir_str}"
        else:
            env["DCS_ALLOWED_PATHS"] = run_dir_str

        self._process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        # Stream stderr line-by-line
        stderr_lines: list[str] = []
        assert self._process.stderr is not None  # noqa: S101 -- guarded by PIPE
        while True:
            raw = await self._process.stderr.readline()
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").rstrip("\n").rstrip("\r")
            stderr_lines.append(line)
            if self._on_stderr_line is not None:
                self._on_stderr_line(line)

            # Capture the last error message for meta
            parsed = parse_stderr_line(line)
            if parsed["type"] == "error":
                error_message = parsed["message"]

        exit_code = await self._process.wait()
        duration = time.monotonic() - start_time

        if self._on_complete is not None:
            self._on_complete(exit_code)

        # Determine prefix and output paths
        scan_type = self._config.scan_type
        prefix = _SCAN_TYPE_TO_PREFIX[scan_type]
        json_path = self._run_dir / f"{prefix}.json"

        # Extract findings_count and backend_used from JSON output
        findings_count = 0
        backend_used = "unknown"
        json_data: dict[str, Any] | None = None

        if json_path.exists():
            try:
                raw_json = json_path.read_text(encoding="utf-8")
                json_data = json.loads(raw_json)
                findings_count = self._extract_findings_count(json_data, scan_type)
                backend_used = self._extract_backend_used(json_data, scan_type)
            except (json.JSONDecodeError, OSError, KeyError, TypeError) as exc:
                logger.warning(
                    "Failed to parse JSON output at %s: %s", json_path, exc
                )

        # Build report file list
        report_files: list[str] = []
        if json_path.exists():
            report_files.append(f"{prefix}.json")

        # In-process format conversion: JSON -> SARIF, HTML
        if json_data is not None:
            for fmt_name, ext in [("sarif", ".sarif"), ("html", ".html")]:
                converted = self._convert_format(
                    json_data, scan_type, fmt_name, ext, prefix
                )
                if converted:
                    report_files.append(f"{prefix}{ext}")

        # Build RunMeta
        from datetime import UTC, datetime

        meta = RunMeta(
            timestamp=datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            target_path=self._config.target_path,
            project_name=self._derive_project_name(self._config.target_path),
            scan_type=scan_type,
            duration_seconds=round(duration, 2),
            findings_count=findings_count,
            backend_used=backend_used,
            exit_code=exit_code,
            languages=list(self._config.languages),
            severity_threshold=self._config.severity_threshold,
            report_files=report_files,
            error_message=error_message,
            dcs_version=__version__,
        )

        return meta

    async def cancel(self) -> None:
        """Cancel the running scan by sending SIGTERM to the subprocess.

        Waits up to 5 seconds for graceful termination, then sends SIGKILL.
        """
        if self._process is None or self._process.returncode is not None:
            return

        self._cancelled = True
        self._process.terminate()

        try:
            await asyncio.wait_for(
                self._process.wait(), timeout=_CANCEL_GRACE_SECONDS
            )
        except TimeoutError:
            self._process.kill()
            await self._process.wait()

    # -------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------

    @staticmethod
    def _extract_findings_count(
        output: dict[str, Any], scan_type: str
    ) -> int:
        """Extract findings count from parsed JSON output.

        Extraction paths per scan type:
        - hunt:      output["total_count"]
        - full-scan: output["total_count"]
        - hunt-fuzz: output["hunt_result"]["total_count"]
        - fuzz:      output["summary"]["unique_crash_count"]
        """
        try:
            if scan_type in ("hunt", "full-scan"):
                return int(output["total_count"])
            elif scan_type == "hunt-fuzz":
                return int(output["hunt_result"]["total_count"])
            elif scan_type == "fuzz":
                return int(output["summary"]["unique_crash_count"])
        except (KeyError, TypeError, ValueError):
            pass
        return 0

    @staticmethod
    def _extract_backend_used(
        output: dict[str, Any], scan_type: str
    ) -> str:
        """Extract backend used from parsed JSON output.

        Extraction paths per scan type:
        - hunt:      output["stats"]["scanner_backend"]
        - full-scan: output["hunt_stats"]["scanner_backend"]
        - hunt-fuzz: output["hunt_result"]["stats"]["scanner_backend"]
        - fuzz:      not applicable (defaults to "unknown")
        """
        try:
            if scan_type == "hunt":
                return str(output["stats"]["scanner_backend"])
            elif scan_type == "full-scan":
                return str(output["hunt_stats"]["scanner_backend"])
            elif scan_type == "hunt-fuzz":
                return str(output["hunt_result"]["stats"]["scanner_backend"])
        except (KeyError, TypeError, ValueError):
            pass
        return "unknown"

    def _convert_format(
        self,
        json_data: dict[str, Any],
        scan_type: str,
        fmt_name: str,
        ext: str,
        prefix: str,
    ) -> bool:
        """Attempt in-process format conversion from JSON data.

        Returns True on success, False on failure (non-fatal).
        """
        try:
            from deep_code_security.shared.formatters import (
                get_formatter,
                supports_fuzz,
                supports_hybrid,
            )

            formatter = get_formatter(fmt_name)
            method_name = _SCAN_TYPE_TO_FORMAT_METHOD.get(scan_type)
            if method_name is None:
                return False

            # Check protocol support for fuzz/hybrid methods
            if method_name == "format_fuzz" and not supports_fuzz(formatter):
                return False
            if method_name == "format_hunt_fuzz" and not supports_hybrid(formatter):
                return False

            # Build the protocol DTO from the raw JSON data
            result_obj = self._build_result_dto(json_data, scan_type)
            if result_obj is None:
                return False

            format_fn = getattr(formatter, method_name, None)
            if format_fn is None:
                return False

            output_str = format_fn(
                result_obj, target_path=self._config.target_path
            )
            output_path = self._run_dir / f"{prefix}{ext}"
            output_path.write_text(output_str, encoding="utf-8")
            return True

        except Exception as exc:  # noqa: BLE001 -- non-fatal conversion
            logger.warning(
                "Format conversion to %s failed: %s", fmt_name, exc
            )
            return False

    @staticmethod
    def _build_result_dto(
        json_data: dict[str, Any], scan_type: str
    ) -> Any:
        """Build the formatter DTO from parsed JSON data.

        Returns the appropriate Pydantic model instance, or None on failure.
        """
        try:
            from deep_code_security.shared.formatters.protocol import (
                FullScanResult,
                FuzzReportResult,
                HuntFuzzResult,
                HuntResult,
            )

            if scan_type == "hunt":
                return HuntResult.model_validate(json_data)
            elif scan_type == "full-scan":
                return FullScanResult.model_validate(json_data)
            elif scan_type == "fuzz":
                return FuzzReportResult.model_validate(json_data)
            elif scan_type == "hunt-fuzz":
                return HuntFuzzResult.model_validate(json_data)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to build result DTO for %s: %s", scan_type, exc)
        return None

    @staticmethod
    def _derive_project_name(target_path: str) -> str:
        """Derive a filesystem-safe project name from a target path.

        Delegates to ``ReportStorage.derive_project_name`` if available,
        otherwise falls back to a simple basename extraction.
        """
        try:
            from deep_code_security.tui.storage import ReportStorage

            return ReportStorage.derive_project_name(target_path)
        except ImportError:
            # Fallback: simple basename
            p = Path(target_path)
            name = p.name if p.name else p.parent.name
            return name if name else "unnamed"
