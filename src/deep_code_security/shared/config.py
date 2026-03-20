"""Global configuration loaded from environment variables."""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = ["Config", "get_config", "reset_config"]


class Config:
    """Global configuration for deep-code-security.

    All settings are read from environment variables with safe defaults.
    """

    def __init__(self) -> None:
        # Registry path: where YAML source/sink registries live
        registry_path_env = os.environ.get("DCS_REGISTRY_PATH", "")
        if registry_path_env:
            self.registry_path = Path(registry_path_env)
        else:
            # Default: registries/ relative to project root
            self.registry_path = Path(__file__).parent.parent.parent.parent / "registries"

        # Allowed paths for filesystem access (comma-separated)
        allowed_env = os.environ.get("DCS_ALLOWED_PATHS", "")
        if allowed_env:
            self.allowed_paths: list[Path] = [
                Path(p.strip()) for p in allowed_env.split(",") if p.strip()
            ]
        else:
            self.allowed_paths = [Path.cwd()]

        # Sandbox configuration
        self.sandbox_timeout: int = int(os.environ.get("DCS_SANDBOX_TIMEOUT", "30"))
        self.container_runtime: str = os.environ.get("DCS_CONTAINER_RUNTIME", "auto")
        self.max_concurrent_sandboxes: int = int(
            os.environ.get("DCS_MAX_CONCURRENT_SANDBOXES", "2")
        )

        # Scanning limits
        self.max_files: int = int(os.environ.get("DCS_MAX_FILES", "10000"))
        self.max_results: int = int(os.environ.get("DCS_MAX_RESULTS", "100"))
        self.max_verifications: int = int(os.environ.get("DCS_MAX_VERIFICATIONS", "50"))

        # Query limits
        self.query_timeout_seconds: float = float(
            os.environ.get("DCS_QUERY_TIMEOUT", "5.0")
        )
        self.query_max_results: int = int(os.environ.get("DCS_QUERY_MAX_RESULTS", "1000"))

        # Scanner backend selection
        self.scanner_backend: str = os.environ.get("DCS_SCANNER_BACKEND", "auto")

        # Semgrep backend configuration
        self.semgrep_timeout: int = self._parse_semgrep_timeout(
            os.environ.get("DCS_SEMGREP_TIMEOUT", "120")
        )
        self.semgrep_rules_path: Path = self._resolve_semgrep_rules_path(
            os.environ.get("DCS_SEMGREP_RULES_PATH", ""),
            self.registry_path,
        )

        # Fuzzer configuration (DCS_FUZZ_* environment variables)
        self.fuzz_model: str = os.environ.get("DCS_FUZZ_MODEL", "claude-sonnet-4-6")
        self.fuzz_max_iterations: int = int(os.environ.get("DCS_FUZZ_MAX_ITERATIONS", "10"))
        self.fuzz_inputs_per_iteration: int = int(
            os.environ.get("DCS_FUZZ_INPUTS_PER_ITER", "10")
        )
        self.fuzz_timeout_ms: int = int(os.environ.get("DCS_FUZZ_TIMEOUT_MS", "5000"))
        self.fuzz_max_cost_usd: float = float(
            os.environ.get("DCS_FUZZ_MAX_COST_USD", "5.0")
        )
        self.fuzz_output_dir: str = os.environ.get("DCS_FUZZ_OUTPUT_DIR", "./fuzzy-output")
        self.fuzz_consent: bool = os.environ.get(
            "DCS_FUZZ_CONSENT", ""
        ).lower() in ("1", "true", "yes")
        if self.fuzz_consent:
            logger.warning(
                "Consent granted via DCS_FUZZ_CONSENT environment variable. "
                "Source code will be transmitted to the Anthropic API."
            )
        self.fuzz_use_vertex: bool = bool(
            os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("CLOUD_ML_PROJECT_NUMBER")
            or os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID")
        )
        self.fuzz_gcp_project: str = (
            os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("CLOUD_ML_PROJECT_NUMBER")
            or ""
        )
        self.fuzz_gcp_region: str = os.environ.get("DCS_FUZZ_GCP_REGION", "us-east5")
        self.fuzz_allowed_plugins: str = os.environ.get(
            "DCS_FUZZ_ALLOWED_PLUGINS", "python"
        )
        self.fuzz_mcp_timeout: int = int(os.environ.get("DCS_FUZZ_MCP_TIMEOUT", "120"))
        self.fuzz_container_image: str = os.environ.get(
            "DCS_FUZZ_CONTAINER_IMAGE", "dcs-fuzz-python:latest"
        )
        self.fuzz_c_container_image: str = os.environ.get(
            "DCS_FUZZ_C_CONTAINER_IMAGE", "dcs-fuzz-c:latest"
        )
        self.fuzz_c_compile_flags: list[str] = [
            f.strip()
            for f in os.environ.get("DCS_FUZZ_C_COMPILE_FLAGS", "").split(",")
            if f.strip()
        ]
        self.fuzz_c_include_paths: list[str] = [
            p.strip()
            for p in os.environ.get("DCS_FUZZ_C_INCLUDE_PATHS", "").split(",")
            if p.strip()
        ]

    # ------------------------------------------------------------------
    # Helper methods for environment-variable parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_semgrep_timeout(raw: str) -> int:
        """Parse and clamp ``DCS_SEMGREP_TIMEOUT``.

        Rules:
        - Must be a valid integer.
        - Clamped to the range [10, 600].
        - Invalid values fall back to the default (120) with a WARNING.

        Args:
            raw: The raw string value from the environment.

        Returns:
            Validated timeout in seconds.
        """
        try:
            value = int(raw)
        except (ValueError, TypeError):
            logger.warning(
                "DCS_SEMGREP_TIMEOUT=%r is not a valid integer; using default (120s).", raw
            )
            return 120
        clamped = max(10, min(600, value))
        if clamped != value:
            logger.warning(
                "DCS_SEMGREP_TIMEOUT=%d is outside the allowed range [10, 600]; "
                "clamped to %d.",
                value,
                clamped,
            )
        return clamped

    @staticmethod
    def _resolve_semgrep_rules_path(raw: str, registry_path: Path) -> Path:
        """Resolve and validate ``DCS_SEMGREP_RULES_PATH``.

        Validation steps (in order):
        1. Parse the raw string as a ``Path``.
        2. Resolve symlinks via ``Path.resolve()``.
        3. Reject if any component of the resolved path is ``".."``.
        4. Fall back to the default (``registry_path / "semgrep"``) on any
           validation failure, logging a WARNING.

        A WARNING is also logged when the resolved path does not exist or does
        not contain at least one ``.yaml`` file (useful diagnostics, but not a
        validation failure — ``SemgrepBackend.is_available()`` performs the
        authoritative file-presence check).

        Args:
            raw: The raw string value from the environment (empty string means
                "use the default").
            registry_path: The already-resolved ``DCS_REGISTRY_PATH`` used to
                compute the default.

        Returns:
            Resolved ``Path`` for the Semgrep rules directory.
        """
        default = registry_path / "semgrep"

        if not raw:
            return default

        try:
            candidate = Path(raw).resolve()
        except (TypeError, ValueError) as exc:
            logger.warning(
                "DCS_SEMGREP_RULES_PATH=%r could not be resolved: %s; "
                "falling back to default (%s).",
                raw,
                exc,
                default,
            )
            return default

        # Note: Path.resolve() already eliminates all ".." components and symlinks,
        # so candidate.parts can never contain ".." at this point.
        # The authoritative safety checks are the exists() and is_dir() guards below.

        if not candidate.exists():
            logger.warning(
                "DCS_SEMGREP_RULES_PATH resolved to %s, which does not exist; "
                "falling back to default (%s).",
                candidate,
                default,
            )
            return default

        if not candidate.is_dir():
            logger.warning(
                "DCS_SEMGREP_RULES_PATH resolved to %s, which is not a directory; "
                "falling back to default (%s).",
                candidate,
                default,
            )
            return default

        # Informational warning: resolved path is not under the project root.
        # This is legitimate (e.g., shared rules directory) but worth noting.
        try:
            candidate.relative_to(registry_path.parent)
        except ValueError:
            logger.warning(
                "DCS_SEMGREP_RULES_PATH (%s) is not under the project root (%s). "
                "This is allowed but unusual.",
                candidate,
                registry_path.parent,
            )

        return candidate

    @property
    def allowed_paths_str(self) -> list[str]:
        """Return allowed paths as strings."""
        return [str(p) for p in self.allowed_paths]


_config: Config | None = None


def get_config() -> Config:
    """Get the global configuration singleton.

    Returns:
        Config instance initialized from environment variables.
    """
    global _config
    if _config is None:
        _config = Config()
    return _config


def reset_config() -> None:
    """Reset the global config (for testing)."""
    global _config
    _config = None
