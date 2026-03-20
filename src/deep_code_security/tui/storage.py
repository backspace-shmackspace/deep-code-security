"""Report storage layout manager for the TUI frontend.

Manages the ``DCS_OUTPUT_DIR`` directory structure:

.. code-block:: text

    {DCS_OUTPUT_DIR}/
        {project-name}/
            YYYY-MM-DD-HH-MM-SS-ffffff/
                meta.json
                hunt.json
                hunt.sarif
                hunt.html
                ...

The ``DCS_OUTPUT_DIR`` environment variable is read directly via
``os.environ.get()`` -- it is NOT imported from ``shared.config``.
This keeps TUI-only configuration out of the shared Config class.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from deep_code_security.tui.models import RunMeta

__all__ = [
    "ReportStorage",
]

logger = logging.getLogger(__name__)

_DEFAULT_OUTPUT_DIR = "~/.dcs/reports/"

# Characters allowed in sanitized project names.
_PROJECT_NAME_PATTERN = re.compile(r"[^a-zA-Z0-9._-]")

# Maximum length for a sanitized project name.
_PROJECT_NAME_MAX_LENGTH = 64

# Timestamp format for run directory names (microsecond precision).
_TIMESTAMP_FORMAT = "%Y-%m-%d-%H-%M-%S-%f"


class ReportStorage:
    """Manages the report storage layout under DCS_OUTPUT_DIR.

    Reads ``DCS_OUTPUT_DIR`` from the environment directly (not from shared
    Config).  Write paths are constructed programmatically from sanitized
    project names and microsecond-precision timestamps -- no user-controlled
    path components are used beyond the target path basename.
    """

    def __init__(self, output_dir: Path | None = None) -> None:
        """Initialize storage with the output directory.

        Args:
            output_dir: Override for ``DCS_OUTPUT_DIR``.  If ``None``, reads
                        from the environment or uses the default
                        (``~/.dcs/reports/``).
        """
        if output_dir is not None:
            self._output_dir = output_dir.expanduser().resolve()
        else:
            env_val = os.environ.get("DCS_OUTPUT_DIR", _DEFAULT_OUTPUT_DIR)
            self._output_dir = Path(env_val).expanduser().resolve()

    def create_run_dir(self, project_name: str) -> Path:
        """Create a timestamped run directory for a project.

        Uses ``YYYY-MM-DD-HH-MM-SS-ffffff`` format (microsecond precision)
        to prevent collisions from concurrent scans.

        Returns:
            The absolute path to the newly created directory.
        """
        now = datetime.now(timezone.utc)
        timestamp_dir = now.strftime(_TIMESTAMP_FORMAT)
        run_dir = self._output_dir / project_name / timestamp_dir
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir

    def write_meta(self, run_dir: Path, meta: RunMeta) -> Path:
        """Write ``meta.json`` to a run directory.

        Args:
            run_dir: The run directory to write to.
            meta: The run metadata to serialize.

        Returns:
            The absolute path to the written ``meta.json`` file.
        """
        meta_path = run_dir / "meta.json"
        meta_path.write_text(
            json.dumps(meta.model_dump(), indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        return meta_path

    def read_meta(self, run_dir: Path) -> RunMeta | None:
        """Read ``meta.json`` from a run directory.

        Args:
            run_dir: The run directory to read from.

        Returns:
            The parsed ``RunMeta`` or ``None`` if the file is missing,
            contains invalid JSON, or fails schema validation.
        """
        meta_path = run_dir / "meta.json"
        if not meta_path.is_file():
            return None
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            return RunMeta.model_validate(data)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning("Failed to read meta.json from %s: %s", run_dir, exc)
            return None

    def list_projects(self) -> list[str]:
        """List all project names that have at least one run.

        Returns:
            Sorted list of project name strings.
        """
        if not self._output_dir.is_dir():
            return []
        projects = []
        for entry in self._output_dir.iterdir():
            if entry.is_dir() and not entry.name.startswith("."):
                # A project directory must contain at least one run subdirectory
                # with a meta.json.
                has_run = any(
                    (sub / "meta.json").is_file()
                    for sub in entry.iterdir()
                    if sub.is_dir()
                )
                if has_run:
                    projects.append(entry.name)
        return sorted(projects)

    def list_runs(self, project_name: str) -> list[RunMeta]:
        """List all runs for a project, sorted by timestamp descending.

        Runs whose ``meta.json`` is missing or invalid are silently skipped.

        Args:
            project_name: The sanitized project name.

        Returns:
            List of ``RunMeta`` objects, most recent first.
        """
        project_dir = self._output_dir / project_name
        if not project_dir.is_dir():
            return []
        runs: list[RunMeta] = []
        for entry in project_dir.iterdir():
            if entry.is_dir():
                meta = self.read_meta(entry)
                if meta is not None:
                    runs.append(meta)
        # Sort by timestamp descending (most recent first).
        runs.sort(key=lambda m: m.timestamp, reverse=True)
        return runs

    def get_output_dir(self) -> Path:
        """Return the resolved output directory path."""
        return self._output_dir

    @staticmethod
    def derive_project_name(target_path: str) -> str:
        """Derive a filesystem-safe project name from a target path.

        Uses the basename of the target path for directories, or the parent
        directory basename for files.  Strips characters not in
        ``[a-zA-Z0-9._-]``.  Rejects any component containing ``..`` or
        ``/``.  Falls back to ``unnamed`` if the result is empty.  Truncates
        to 64 characters.

        Args:
            target_path: The original target path (absolute or relative).

        Returns:
            A sanitized project name string.
        """
        p = Path(target_path)

        # For files, use the parent directory basename.
        if p.is_file():
            name = p.parent.name
        else:
            # For directories (or non-existent paths), use the basename.
            # Handle trailing slashes by resolving the path.
            name = p.name
            # If name is empty (e.g., root path "/"), try the resolved path.
            if not name:
                name = p.resolve().name

        # Strip disallowed characters.
        sanitized = _PROJECT_NAME_PATTERN.sub("", name)

        # Reject path traversal.
        if ".." in sanitized or "/" in sanitized:
            sanitized = sanitized.replace("..", "").replace("/", "")

        # Truncate to max length.
        sanitized = sanitized[:_PROJECT_NAME_MAX_LENGTH]

        # Fall back to "unnamed" if empty.
        if not sanitized:
            return "unnamed"

        return sanitized
