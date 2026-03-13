"""MCP tool integration tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from deep_code_security.hunter.registry import clear_registry_cache
from deep_code_security.mcp.server import DeepCodeSecurityMCPServer
from deep_code_security.shared.config import Config, reset_config

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
VULNERABLE_PYTHON = FIXTURES_DIR / "vulnerable_samples" / "python"


@pytest.fixture(autouse=True)
def clear_cache():
    clear_registry_cache()
    yield
    clear_registry_cache()


@pytest.fixture
def integration_config() -> Config:
    os.environ["DCS_ALLOWED_PATHS"] = str(FIXTURES_DIR)
    os.environ["DCS_REGISTRY_PATH"] = str(Path(__file__).parent.parent.parent / "registries")
    reset_config()
    config = Config()
    yield config
    os.environ.pop("DCS_ALLOWED_PATHS", None)
    os.environ.pop("DCS_REGISTRY_PATH", None)
    reset_config()


@pytest.fixture
def server(integration_config: Config) -> DeepCodeSecurityMCPServer:
    server = DeepCodeSecurityMCPServer(config=integration_config)
    server._register_tools()
    return server


class TestMCPToolIntegration:
    """Integration tests for MCP tool round-trips."""

    @pytest.mark.asyncio
    async def test_hunt_returns_valid_json_structure(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        """deep_scan_hunt returns valid JSON with required fields."""
        result = await server._handle_hunt({"path": str(VULNERABLE_PYTHON)})
        assert "content" in result
        assert len(result["content"]) > 0
        content = json.loads(result["content"][0]["text"])
        assert "findings" in content
        assert "stats" in content
        assert "total_count" in content
        assert "has_more" in content
        assert isinstance(content["findings"], list)
        assert isinstance(content["total_count"], int)
        assert isinstance(content["has_more"], bool)

    @pytest.mark.asyncio
    async def test_hunt_pagination_fields_present(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        """Hunt response includes pagination fields."""
        result = await server._handle_hunt({
            "path": str(VULNERABLE_PYTHON),
            "max_results": 1,
            "offset": 0,
        })
        content = json.loads(result["content"][0]["text"])
        assert "total_count" in content
        assert "has_more" in content
        assert isinstance(content["has_more"], bool)

    @pytest.mark.asyncio
    async def test_hunt_findings_have_required_schema(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        """Hunt findings have all required JSON fields."""
        result = await server._handle_hunt({
            "path": str(VULNERABLE_PYTHON),
            "severity_threshold": "low",
        })
        content = json.loads(result["content"][0]["text"])
        for finding in content["findings"]:
            assert "id" in finding
            assert "source" in finding
            assert "sink" in finding
            assert "vulnerability_class" in finding
            assert "severity" in finding
            assert "language" in finding
            assert "raw_confidence" in finding
            # Source fields
            assert "file" in finding["source"]
            assert "line" in finding["source"]
            # Sink fields
            assert "file" in finding["sink"]
            assert "cwe" in finding["sink"]

    @pytest.mark.asyncio
    async def test_status_response_structure(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        """Status response has expected structure."""
        result = await server._handle_status({})
        content = json.loads(result["content"][0]["text"])
        assert "sandbox_available" in content
        assert "container_runtime" in content
        assert "registries_loaded" in content
        assert isinstance(content["registries_loaded"], list)

    @pytest.mark.asyncio
    async def test_full_scan_returns_combined_output(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        """deep_scan_full returns combined output from all phases."""
        result = await server._handle_full({
            "path": str(VULNERABLE_PYTHON),
            "skip_verification": True,  # Skip sandbox for speed
            "severity_threshold": "low",
        })
        content = json.loads(result["content"][0]["text"])
        assert "findings" in content
        assert "verified" in content
        assert "guidance" in content
        assert isinstance(content["findings"], list)
        assert isinstance(content["verified"], list)
        assert isinstance(content["guidance"], list)

    @pytest.mark.asyncio
    async def test_hunt_verify_remediate_pipeline(
        self, server: DeepCodeSecurityMCPServer
    ) -> None:
        """Hunt -> Verify -> Remediate pipeline works end-to-end."""
        # Step 1: Hunt
        hunt_result = await server._handle_hunt({
            "path": str(VULNERABLE_PYTHON),
            "severity_threshold": "low",
        })
        hunt_content = json.loads(hunt_result["content"][0]["text"])
        findings = hunt_content["findings"]

        if not findings:
            pytest.skip("No findings from hunt, skipping pipeline test")

        finding_ids = [f["id"] for f in findings[:2]]

        # Step 2: Verify (with unavailable sandbox — uses base confidence)
        verify_result = await server._handle_verify({
            "finding_ids": finding_ids,
            "target_path": str(VULNERABLE_PYTHON),
        })
        verify_content = json.loads(verify_result["content"][0]["text"])
        assert "verified" in verify_content
        assert "stats" in verify_content

        verified = verify_content["verified"]
        if not verified:
            return  # Nothing to remediate

        # Step 3: Remediate
        verified_ids = [v["finding"]["id"] for v in verified[:2]]
        remediate_result = await server._handle_remediate({
            "finding_ids": verified_ids,
            "target_path": str(VULNERABLE_PYTHON),
        })
        remediate_content = json.loads(remediate_result["content"][0]["text"])
        assert "guidance" in remediate_content
        assert "stats" in remediate_content
