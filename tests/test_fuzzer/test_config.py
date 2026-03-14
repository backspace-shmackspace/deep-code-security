"""Tests for FuzzerConfig Pydantic model."""

from __future__ import annotations

from unittest.mock import patch

from deep_code_security.fuzzer.config import FuzzerConfig


class TestFuzzerConfig:
    def test_model_validator_loads_key(self) -> None:
        """model_validator loads API key from env."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key-123"}):
            config = FuzzerConfig(target_path="/tmp/test.py")
            assert config.api_key == "test-key-123"

    def test_api_key_not_serialized(self) -> None:
        """api_key excluded from model_dump() and repr()."""
        config = FuzzerConfig(target_path="/tmp/test.py", api_key="secret")
        data = config.model_dump()
        assert "api_key" not in data
        assert "secret" not in repr(config)

    def test_vertex_auto_detect(self) -> None:
        """Detects Vertex AI from GOOGLE_CLOUD_PROJECT."""
        env = {"GOOGLE_CLOUD_PROJECT": "my-project", "ANTHROPIC_API_KEY": ""}
        # Clear other vertex-related env vars
        for key in ("CLOUD_ML_PROJECT_NUMBER", "ANTHROPIC_VERTEX_PROJECT_ID"):
            env[key] = ""
        with patch.dict("os.environ", env, clear=False):
            # Need to explicitly construct to avoid env interference
            config = FuzzerConfig(target_path="/tmp/test.py")
            assert config.use_vertex is True

    def test_has_valid_credentials_vertex(self) -> None:
        config = FuzzerConfig.model_construct(use_vertex=True, gcp_project="proj", api_key="")
        assert config.has_valid_credentials is True

    def test_has_valid_credentials_api_key(self) -> None:
        config = FuzzerConfig.model_construct(api_key="key123", use_vertex=False, gcp_project="")
        assert config.has_valid_credentials is True

    def test_has_valid_credentials_none(self) -> None:
        config = FuzzerConfig.model_construct(
            target_path="/tmp/test.py",
            api_key="",
            use_vertex=False,
            gcp_project="",
        )
        assert config.has_valid_credentials is False

    def test_from_dcs_config(self) -> None:
        """Factory method creates from DCS config + overrides."""

        class MockConfig:
            fuzz_model = "claude-sonnet-4-6"
            fuzz_max_iterations = 10
            fuzz_inputs_per_iteration = 10
            fuzz_timeout_ms = 5000
            fuzz_max_cost_usd = 5.0
            fuzz_output_dir = "./fuzzy-output"
            fuzz_consent = False
            fuzz_use_vertex = False
            fuzz_gcp_project = ""
            fuzz_gcp_region = "us-east5"

        config = FuzzerConfig.from_dcs_config(
            MockConfig(),
            target_path="/tmp/test.py",
            max_iterations=3,
        )
        assert config.target_path == "/tmp/test.py"
        assert config.max_iterations == 3
