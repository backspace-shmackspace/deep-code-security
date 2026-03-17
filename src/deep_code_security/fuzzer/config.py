"""FuzzerConfig as Pydantic model.

Uses @model_validator(mode='after') to replicate __post_init__ behavior.
API key uses Field(default="", repr=False, exclude=True).
"""

from __future__ import annotations

import logging
import os
import stat
import tomllib
import warnings
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

from deep_code_security.bridge.models import SASTContext

__all__ = ["FuzzerConfig"]

logger = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / ".config" / "deep-code-security"
CONFIG_FILE = CONFIG_DIR / "config.toml"

_OLD_CONFIG_DIR = Path.home() / ".config" / "fuzzy-wuzzy"
_OLD_CONFIG_FILE = _OLD_CONFIG_DIR / "config.toml"


class FuzzerConfig(BaseModel):
    """Configuration for a fuzzing run.

    API key is loaded from environment or config file; never from CLI flags.
    """

    # Target settings
    target_path: str = ""
    target_functions: list[str] = Field(default_factory=list)

    # Run settings
    max_iterations: int = 10
    inputs_per_iteration: int = 10
    timeout_ms: int = 5000
    max_cost_usd: float = 5.00

    # AI settings
    model: str = "claude-sonnet-4-6"

    # Output settings
    output_dir: str = "./fuzzy-output"
    report_format: str = "text"
    verbose: bool = False

    # Plugin settings
    plugin_name: str = "python"

    # API key (loaded from env or config file, never CLI)
    api_key: str = Field(default="", repr=False, exclude=True)

    # Vertex AI settings
    use_vertex: bool = False
    gcp_project: str = ""
    gcp_region: str = "us-east5"

    # Consent / data protection
    consent: bool = False
    dry_run: bool = False
    redact_strings: bool = False

    # Side-effect control
    allow_side_effects: bool = False

    # Corpus
    seed_corpus_path: str | None = None

    # SAST context (bridge internal -- not CLI-configurable)
    sast_contexts: dict[str, SASTContext] | None = Field(
        default=None,
        exclude=True,
        description=(
            "SAST context per function (keyed by qualified name). "
            "Bridge internal -- not CLI-configurable. "
            "Injected programmatically by the BridgeOrchestrator."
        ),
    )

    @model_validator(mode="after")
    def _post_init_validation(self) -> FuzzerConfig:
        """Replicate dataclass __post_init__ behavior.

        Loads API key, detects Vertex AI, detects GCP project.
        """
        if not self.api_key:
            self.api_key = self._load_api_key()
        if not self.use_vertex:
            self.use_vertex = self._detect_vertex()
        if self.use_vertex and not self.gcp_project:
            self.gcp_project = self._detect_gcp_project()
        return self

    def _load_api_key(self) -> str:
        """Load API key from environment variable or config file."""
        env_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if env_key:
            return env_key

        # Try new config path first
        for config_path in (CONFIG_FILE, _OLD_CONFIG_FILE):
            if config_path.exists():
                if config_path == _OLD_CONFIG_FILE:
                    warnings.warn(
                        f"Reading config from deprecated path {_OLD_CONFIG_FILE}. "
                        f"Migrate to {CONFIG_FILE}.",
                        DeprecationWarning,
                        stacklevel=2,
                    )
                self._check_config_permissions(config_path)
                try:
                    with open(config_path, "rb") as f:
                        config_data = tomllib.load(f)
                    key = config_data.get("api_key", "")
                    if key:
                        return key
                except Exception:
                    pass

        return ""

    def _check_config_permissions(self, path: Path) -> None:
        """Warn if config file has too-open permissions."""
        try:
            mode = path.stat().st_mode
            if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
                warnings.warn(
                    f"Config file {path} has too-open permissions. Run: chmod 600 {path}",
                    stacklevel=2,
                )
        except OSError:
            pass

    def _detect_vertex(self) -> bool:
        """Auto-detect Vertex AI from environment variables."""
        return bool(
            os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("CLOUD_ML_PROJECT_NUMBER")
            or os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID")
        )

    def _detect_gcp_project(self) -> str:
        """Auto-detect GCP project from environment variables."""
        return (
            os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("CLOUD_ML_PROJECT_NUMBER")
            or ""
        )

    @property
    def has_valid_credentials(self) -> bool:
        """Check if valid credentials are available."""
        if self.use_vertex:
            return bool(self.gcp_project)
        return bool(self.api_key)

    @classmethod
    def from_dcs_config(cls, config: object, **cli_overrides: object) -> FuzzerConfig:
        """Create FuzzerConfig from DCS Config with CLI overrides.

        Args:
            config: DCS Config object.
            **cli_overrides: Values from CLI flags override env defaults.

        Returns:
            FuzzerConfig instance.
        """
        base_kwargs: dict = {
            "model": getattr(config, "fuzz_model", "claude-sonnet-4-6"),
            "max_iterations": getattr(config, "fuzz_max_iterations", 10),
            "inputs_per_iteration": getattr(config, "fuzz_inputs_per_iteration", 10),
            "timeout_ms": getattr(config, "fuzz_timeout_ms", 5000),
            "max_cost_usd": getattr(config, "fuzz_max_cost_usd", 5.0),
            "output_dir": getattr(config, "fuzz_output_dir", "./fuzzy-output"),
            "consent": getattr(config, "fuzz_consent", False),
            "use_vertex": getattr(config, "fuzz_use_vertex", False),
            "gcp_project": getattr(config, "fuzz_gcp_project", ""),
            "gcp_region": getattr(config, "fuzz_gcp_region", "us-east5"),
        }

        # CLI overrides take precedence (only non-None values)
        for key, value in cli_overrides.items():
            if value is not None:
                base_kwargs[key] = value

        return cls(**base_kwargs)
