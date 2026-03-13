"""Tests for server.py verify and remediate success paths."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.auditor.models import ExploitResult, VerifiedFinding
from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath, TaintStep
from deep_code_security.mcp.server import DeepCodeSecurityMCPServer
from deep_code_security.shared.config import Config, reset_config

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
REGISTRY_DIR = Path(__file__).parent.parent.parent / "registries"


def _make_raw_finding(suffix: str = "1") -> RawFinding:
    return RawFinding(
        source=Source(
            file=f"/tmp/test{suffix}.py", line=1, column=0,
            function="request.form", category="web_input", language="python"
        ),
        sink=Sink(
            file=f"/tmp/test{suffix}.py", line=5, column=0,
            function="cursor.execute", category="sql_injection",
            cwe="CWE-89", language="python"
        ),
        taint_path=TaintPath(steps=[
            TaintStep(file=f"/tmp/test{suffix}.py", line=1, column=0,
                      variable="user_input", transform="source"),
            TaintStep(file=f"/tmp/test{suffix}.py", line=5, column=0,
                      variable="user_input", transform="sink_argument"),
        ]),
        vulnerability_class="CWE-89: SQL Injection",
        severity="high",
        language="python",
        raw_confidence=0.7,
    )


def _make_verified_finding(raw: RawFinding) -> VerifiedFinding:
    return VerifiedFinding(
        finding=raw,
        exploit_results=[],
        confidence_score=65,
        verification_status="likely",
    )


@pytest.fixture
def server_config(tmp_path: Path) -> Config:
    os.environ["DCS_ALLOWED_PATHS"] = str(tmp_path) + "," + str(FIXTURES_DIR)
    os.environ["DCS_REGISTRY_PATH"] = str(REGISTRY_DIR)
    reset_config()
    config = Config()
    yield config
    os.environ.pop("DCS_ALLOWED_PATHS", None)
    os.environ.pop("DCS_REGISTRY_PATH", None)
    reset_config()


@pytest.fixture
def server(server_config: Config) -> DeepCodeSecurityMCPServer:
    s = DeepCodeSecurityMCPServer(config=server_config)
    s._register_tools()
    return s


class TestVerifySuccessPath:
    """Tests for the successful verify path (lines 323-355)."""

    @pytest.mark.asyncio
    async def test_verify_with_seeded_finding_succeeds(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """When a finding is in session, verify runs the full path."""
        raw = _make_raw_finding()
        scan_id = str(uuid.uuid4())
        server._findings_session[scan_id] = [raw]
        server._finding_by_id[raw.id] = raw

        # Mock the auditor to avoid actual sandbox
        mock_verified = _make_verified_finding(raw)
        from deep_code_security.auditor.models import VerifyStats
        mock_stats = VerifyStats(total_findings=1, verified_count=1, sandbox_available=False)

        with patch.object(server.auditor, "verify", return_value=([mock_verified], mock_stats)):
            result = await server._handle_verify({
                "finding_ids": [raw.id],
                "target_path": str(tmp_path),
                "sandbox_timeout_seconds": 10,
                "max_verifications": 5,
            })

        content = json.loads(result["content"][0]["text"])
        assert "verified" in content
        assert "stats" in content

    @pytest.mark.asyncio
    async def test_verify_stores_verified_in_session(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """Verified findings are stored in auditor session."""
        raw = _make_raw_finding("2")
        scan_id = str(uuid.uuid4())
        server._findings_session[scan_id] = [raw]
        server._finding_by_id[raw.id] = raw

        mock_verified = _make_verified_finding(raw)
        from deep_code_security.auditor.models import VerifyStats
        mock_stats = VerifyStats(total_findings=1, verified_count=1, sandbox_available=False)

        with patch.object(server.auditor, "verify", return_value=([mock_verified], mock_stats)):
            await server._handle_verify({
                "finding_ids": [raw.id],
                "target_path": str(tmp_path),
            })

        assert raw.id in server.auditor._session_verified

    @pytest.mark.asyncio
    async def test_verify_auditor_exception_raises_tool_error(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """If auditor.verify raises, a ToolError is propagated."""
        from deep_code_security.mcp.shared.server_base import ToolError
        raw = _make_raw_finding("3")
        server._finding_by_id[raw.id] = raw

        with patch.object(server.auditor, "verify", side_effect=RuntimeError("boom")):
            with pytest.raises(ToolError, match="Verification failed"):
                await server._handle_verify({
                    "finding_ids": [raw.id],
                    "target_path": str(tmp_path),
                })

    @pytest.mark.asyncio
    async def test_verify_sandbox_timeout_capped_at_300(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """sandbox_timeout_seconds is capped at 300 before being passed to auditor."""
        raw = _make_raw_finding("4")
        server._finding_by_id[raw.id] = raw

        captured_timeout = []

        from deep_code_security.auditor.models import VerifyStats
        mock_stats = VerifyStats()

        def capture_verify(*args, **kwargs):
            captured_timeout.append(kwargs.get("sandbox_timeout"))
            return [], mock_stats

        with patch.object(server.auditor, "verify", side_effect=capture_verify):
            # Even with findings missing (empty list returned), we get past the cap
            # Use a seeded finding so we actually reach verify
            mock_vf = _make_verified_finding(raw)
            with patch.object(server.auditor, "verify",
                               return_value=([mock_vf], mock_stats)) as mock_v:
                await server._handle_verify({
                    "finding_ids": [raw.id],
                    "target_path": str(tmp_path),
                    "sandbox_timeout_seconds": 9999,
                })
                # The capped value should be 300
                call_kwargs = mock_v.call_args[1]
                assert call_kwargs["sandbox_timeout"] == 300


class TestRemediateSuccessPath:
    """Tests for the successful remediate path (lines 391-409)."""

    @pytest.mark.asyncio
    async def test_remediate_with_seeded_verified_finding(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """When a verified finding is in session, remediate runs successfully."""
        raw = _make_raw_finding("5")
        verified = _make_verified_finding(raw)
        server.auditor._session_verified[raw.id] = verified

        from deep_code_security.architect.models import RemediationGuidance, RemediateStats

        mock_guidance = [RemediationGuidance(
            finding_id=raw.id,
            vulnerability_explanation="SQL injection found",
            fix_pattern="Use parameterized queries",
            code_example="cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))",
            effort_estimate="trivial",
        )]
        mock_stats = RemediateStats(total_verified=1, guidance_generated=1)

        with patch.object(server.architect, "remediate",
                           return_value=(mock_guidance, mock_stats)):
            result = await server._handle_remediate({
                "finding_ids": [raw.id],
                "target_path": str(tmp_path),
            })

        content = json.loads(result["content"][0]["text"])
        assert "guidance" in content
        assert "stats" in content

    @pytest.mark.asyncio
    async def test_remediate_architect_exception_raises_tool_error(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """If architect.remediate raises, a ToolError is propagated."""
        from deep_code_security.mcp.shared.server_base import ToolError
        raw = _make_raw_finding("6")
        verified = _make_verified_finding(raw)
        server.auditor._session_verified[raw.id] = verified

        with patch.object(server.architect, "remediate",
                           side_effect=RuntimeError("architect boom")):
            with pytest.raises(ToolError, match="Remediation failed"):
                await server._handle_remediate({
                    "finding_ids": [raw.id],
                    "target_path": str(tmp_path),
                })


class TestFullHandlerVerifyRemediatePaths:
    """Tests for _handle_full paths that include verification and remediation."""

    @pytest.mark.asyncio
    async def test_full_with_findings_and_verification(
        self, server: DeepCodeSecurityMCPServer, tmp_path: Path
    ) -> None:
        """Full scan with verification enabled runs all phases."""
        vuln = tmp_path / "vuln.py"
        vuln.write_text(
            "from flask import request\nimport os\n\n"
            "def handle():\n    x = request.form['q']\n    os.system(x)\n"
        )

        raw = _make_raw_finding("full1")
        verified = _make_verified_finding(raw)
        from deep_code_security.auditor.models import VerifyStats
        from deep_code_security.architect.models import RemediateStats

        mock_vstats = VerifyStats(total_findings=1, verified_count=1, sandbox_available=False)
        mock_rstats = RemediateStats(total_verified=1, guidance_generated=1)

        with patch.object(server.auditor, "verify",
                           return_value=([verified], mock_vstats)), \
             patch.object(server.architect, "remediate",
                           return_value=([], mock_rstats)):
            result = await server._handle_full({
                "path": str(tmp_path),
                "skip_verification": False,
            })

        content = json.loads(result["content"][0]["text"])
        assert "findings" in content
        assert "verified" in content
