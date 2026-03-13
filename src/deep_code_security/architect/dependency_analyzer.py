"""Dependency manifest parser for fix impact analysis."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from deep_code_security.architect.models import DependencyImpact
from deep_code_security.auditor.models import VerifiedFinding

__all__ = ["DependencyAnalyzer"]

logger = logging.getLogger(__name__)

# Map from vulnerability class to recommended new dependencies per language
_DEPENDENCY_RECOMMENDATIONS: dict[tuple[str, str], dict[str, Any]] = {
    ("CWE-89", "python"): {
        "changes": ["# Use parameterized queries — no new deps needed for sqlite3/psycopg2/pymysql"],
        "breaking_risk": "none",
    },
    ("CWE-78", "python"): {
        "changes": ["# Use subprocess list form — no new deps needed"],
        "breaking_risk": "none",
    },
    ("CWE-94", "python"): {
        "changes": [
            "simpleeval>=0.9.13  # Safe math expression evaluator (if eval replacement needed)"
        ],
        "breaking_risk": "none",
    },
    ("CWE-22", "python"): {
        "changes": ["# Use pathlib.Path.resolve() — no new deps needed"],
        "breaking_risk": "none",
    },
    ("CWE-89", "go"): {
        "changes": ["# Use parameterized queries — database/sql supports this natively"],
        "breaking_risk": "none",
    },
    ("CWE-78", "go"): {
        "changes": ["# Use os/exec with separate arguments — no new deps needed"],
        "breaking_risk": "none",
    },
}


class DependencyAnalyzer:
    """Parses dependency manifests and analyzes fix impact."""

    def analyze(
        self,
        target_path: str | Path,
        finding: VerifiedFinding,
    ) -> DependencyImpact | None:
        """Analyze dependency impact for a finding fix.

        Args:
            target_path: Root of the target codebase.
            finding: The verified finding to analyze.

        Returns:
            DependencyImpact if a manifest file is found, None otherwise.
        """
        target_path = Path(target_path)
        language = finding.finding.language.lower()
        cwe = _extract_cwe(finding.finding.vulnerability_class)

        # Find manifest file
        manifest_path, manifest_type = self._find_manifest(target_path, language)
        if manifest_path is None:
            return None

        # Parse current dependencies
        current_deps = self._parse_deps(manifest_path, manifest_type)

        # Get recommended changes
        rec = _DEPENDENCY_RECOMMENDATIONS.get((cwe, language), {})
        required_changes = rec.get("changes", [])
        breaking_risk = rec.get("breaking_risk", "none")

        return DependencyImpact(
            manifest_file=str(manifest_path.relative_to(target_path)),
            current_deps=current_deps[:20],  # Cap at 20 deps for output size
            required_changes=required_changes,
            breaking_risk=breaking_risk,
        )

    def _find_manifest(
        self, target_path: Path, language: str
    ) -> tuple[Path | None, str]:
        """Find the primary dependency manifest for the language.

        Args:
            target_path: Root directory.
            language: Programming language.

        Returns:
            Tuple of (manifest_path, manifest_type) or (None, "").
        """
        candidates: list[tuple[str, str]] = []

        if language == "python":
            candidates = [
                ("pyproject.toml", "pyproject"),
                ("requirements.txt", "requirements"),
                ("setup.cfg", "setup_cfg"),
                ("setup.py", "setup_py"),
                ("Pipfile", "pipfile"),
            ]
        elif language == "go":
            candidates = [
                ("go.mod", "go_mod"),
            ]
        elif language == "c":
            candidates = [
                ("Makefile", "makefile"),
                ("CMakeLists.txt", "cmake"),
            ]

        for filename, manifest_type in candidates:
            path = target_path / filename
            if path.exists():
                return path, manifest_type

        return None, ""

    def _parse_deps(self, manifest_path: Path, manifest_type: str) -> list[str]:
        """Parse dependencies from a manifest file.

        Args:
            manifest_path: Path to the manifest file.
            manifest_type: Type of manifest.

        Returns:
            List of dependency strings.
        """
        try:
            content = manifest_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning("Cannot read manifest %s: %s", manifest_path, e)
            return []

        if manifest_type == "requirements":
            return self._parse_requirements_txt(content)
        elif manifest_type == "pyproject":
            return self._parse_pyproject_toml(content)
        elif manifest_type == "go_mod":
            return self._parse_go_mod(content)
        else:
            return []

    def _parse_requirements_txt(self, content: str) -> list[str]:
        """Parse requirements.txt format.

        Args:
            content: File content.

        Returns:
            List of dependency lines.
        """
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                # Remove version extras and comments
                dep = re.split(r"[;#]", line)[0].strip()
                if dep:
                    deps.append(dep)
        return deps

    def _parse_pyproject_toml(self, content: str) -> list[str]:
        """Parse pyproject.toml dependencies section.

        Args:
            content: File content.

        Returns:
            List of dependency strings.
        """
        deps = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[project.dependencies]", "dependencies = ["):
                in_deps = True
                continue
            if in_deps:
                if stripped.startswith("[") or stripped == "]":
                    in_deps = False
                    continue
                # Extract quoted dependency
                match = re.search(r'"([^"]+)"', stripped)
                if match:
                    deps.append(match.group(1))
        return deps

    def _parse_go_mod(self, content: str) -> list[str]:
        """Parse go.mod require section.

        Args:
            content: File content.

        Returns:
            List of module path + version strings.
        """
        deps = []
        in_require = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            if stripped == ")":
                in_require = False
                continue
            if in_require or stripped.startswith("require "):
                # Extract "module version" pairs
                parts = stripped.replace("require ", "").split()
                if len(parts) >= 2:
                    deps.append(f"{parts[0]} {parts[1]}")
        return deps


def _extract_cwe(vulnerability_class: str) -> str:
    """Extract CWE identifier from vulnerability class string.

    Args:
        vulnerability_class: e.g., "CWE-78: OS Command Injection"

    Returns:
        CWE identifier (e.g., "CWE-78") or "DEFAULT".
    """
    match = re.match(r"(CWE-\d+)", vulnerability_class)
    if match:
        return match.group(1)
    return "DEFAULT"
