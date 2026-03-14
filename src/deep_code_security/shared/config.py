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
