"""DeepCodeSecurityMCPServer — MCP server with 5 tools, path validation, and audit logging.

Runs as a native stdio process. Never containerized. Invokes Docker/Podman CLI
for sandbox containers (exploit verification).
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import Any

from deep_code_security.architect.orchestrator import ArchitectOrchestrator
from deep_code_security.auditor.orchestrator import AuditorOrchestrator
from deep_code_security.hunter.models import RawFinding
from deep_code_security.hunter.orchestrator import HunterOrchestrator
from deep_code_security.mcp.input_validator import InputValidationError, validate_raw_finding
from deep_code_security.mcp.path_validator import PathValidationError, validate_path
from deep_code_security.mcp.shared.server_base import BaseMCPServer, ToolError
from deep_code_security.shared.config import Config, get_config
from deep_code_security.shared.json_output import serialize_model, serialize_models

__all__ = ["DeepCodeSecurityMCPServer"]

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("deep_code_security.audit")


class DeepCodeSecurityMCPServer(BaseMCPServer):
    """MCP server exposing deep-code-security tools via stdio.

    Tools:
    - deep_scan_hunt: Run Hunter phase
    - deep_scan_verify: Run Auditor phase
    - deep_scan_remediate: Run Architect phase
    - deep_scan_full: Run all three phases
    - deep_scan_status: Check server health

    All tool invocations are audit-logged with timestamp, tool name,
    input parameters (paths redacted to basename), finding count, and duration.
    """

    SERVER_NAME = "deep-code-security"
    SERVER_VERSION = "1.0.0"

    def __init__(self, config: Config | None = None) -> None:
        super().__init__()
        self.config = config or get_config()
        self.hunter = HunterOrchestrator(config=self.config)
        self.auditor = AuditorOrchestrator(config=self.config)
        self.architect = ArchitectOrchestrator(config=self.config)

        # Server-side session store for findings (bounded at 100 scans via OrderedDict)
        # Maps scan_id -> list[RawFinding]; oldest entry evicted when limit is reached
        self._MAX_SESSION_SCANS: int = 100
        self._findings_session: OrderedDict[str, list[RawFinding]] = OrderedDict()
        # Maps finding_id -> RawFinding (for lookup by ID)
        self._finding_by_id: dict[str, RawFinding] = {}

    async def initialize(self) -> None:
        """Initialize orchestrators and register tools."""
        self._register_tools()

    async def validate_services(self) -> None:
        """Check sandbox availability (non-blocking warning if unavailable)."""
        if not self.auditor.sandbox.is_available():
            logger.warning(
                "Container runtime not available. Auditor phase will use base confidence only."
            )
        else:
            logger.info(
                "Container runtime available: %s",
                self.auditor.sandbox._runtime_cmd or "unknown",
            )

    def _register_tools(self) -> None:
        """Register all 5 MCP tools."""
        self.register_tool(
            name="deep_scan_hunt",
            description=(
                "Run the Hunter phase: parse source code with tree-sitter, "
                "find sources and sinks, trace taint paths. "
                "Returns paginated list of RawFinding objects."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to target codebase (must be in DCS_ALLOWED_PATHS)",
                    },
                    "languages": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter to specific languages (python, go, c)",
                    },
                    "severity_threshold": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                        "description": "Minimum severity to report (default: medium)",
                    },
                    "max_results": {
                        "type": "integer",
                        "default": 100,
                        "description": "Maximum findings per page",
                    },
                    "offset": {
                        "type": "integer",
                        "default": 0,
                        "description": "Pagination offset",
                    },
                },
                "required": ["path"],
            },
            handler=self._handle_hunt,
        )

        self.register_tool(
            name="deep_scan_verify",
            description=(
                "Run the Auditor phase: generate PoC exploits and execute in sandbox containers. "
                "Only accepts finding IDs from a previous deep_scan_hunt (server-side session). "
                "Returns VerifiedFinding objects with confidence scores."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "finding_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Finding UUIDs from a previous deep_scan_hunt",
                    },
                    "target_path": {
                        "type": "string",
                        "description": "Path to target codebase (for sandbox mounts)",
                    },
                    "sandbox_timeout_seconds": {
                        "type": "integer",
                        "default": 30,
                        "description": "Per-exploit timeout in seconds",
                    },
                    "max_verifications": {
                        "type": "integer",
                        "default": 50,
                        "description": "Maximum findings to verify",
                    },
                },
                "required": ["finding_ids", "target_path"],
            },
            handler=self._handle_verify,
        )

        self.register_tool(
            name="deep_scan_remediate",
            description=(
                "Run the Architect phase: generate remediation guidance for verified findings. "
                "Produces vulnerability explanations, fix patterns, and code examples (NOT patches). "
                "Only accepts finding IDs from a previous deep_scan_verify."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "finding_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Finding UUIDs from a previous deep_scan_verify",
                    },
                    "target_path": {
                        "type": "string",
                        "description": "Path to target codebase (validated against DCS_ALLOWED_PATHS)",
                    },
                },
                "required": ["finding_ids", "target_path"],
            },
            handler=self._handle_remediate,
        )

        self.register_tool(
            name="deep_scan_full",
            description=(
                "Run all three phases sequentially: Hunt -> Verify -> Remediate. "
                "Returns combined results from all phases."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to target codebase",
                    },
                    "languages": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "severity_threshold": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "sandbox_timeout_seconds": {
                        "type": "integer",
                        "default": 30,
                    },
                    "skip_verification": {
                        "type": "boolean",
                        "default": False,
                        "description": "Skip Auditor phase (faster, less accurate)",
                    },
                    "max_results": {
                        "type": "integer",
                        "default": 100,
                    },
                    "max_verifications": {
                        "type": "integer",
                        "default": 50,
                    },
                },
                "required": ["path"],
            },
            handler=self._handle_full,
        )

        self.register_tool(
            name="deep_scan_status",
            description="Check sandbox health, registry info, and server configuration.",
            input_schema={"type": "object", "properties": {}},
            handler=self._handle_status,
        )

    async def _handle_hunt(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle deep_scan_hunt tool call."""
        start = time.monotonic()
        path_raw = params.get("path", "")

        # Validate path
        try:
            path = validate_path(path_raw, self.config.allowed_paths_str)
        except PathValidationError as e:
            self._audit_log("deep_scan_hunt", {"path": Path(path_raw).name}, 0, "REJECTED", 0)
            raise ToolError(f"Path validation failed: {e}", retryable=False) from e

        languages = params.get("languages")
        severity_threshold = params.get("severity_threshold", "medium")
        max_results = min(int(params.get("max_results", 100)), 1000)
        offset = max(0, int(params.get("offset", 0)))

        try:
            findings, stats, total_count, has_more = self.hunter.scan(
                target_path=path,
                languages=languages,
                severity_threshold=severity_threshold,
                max_results=max_results,
                offset=offset,
            )
        except Exception as e:
            logger.error("Hunt failed: %s", e)
            raise ToolError(f"Hunt failed: {e}", retryable=True) from e

        # Store findings in session (evict oldest scan when capacity is reached)
        scan_id = str(uuid.uuid4())
        if len(self._findings_session) >= self._MAX_SESSION_SCANS:
            _, evicted_findings = self._findings_session.popitem(last=False)
            for ef in evicted_findings:
                self._finding_by_id.pop(ef.id, None)
        self._findings_session[scan_id] = findings
        for f in findings:
            self._finding_by_id[f.id] = f

        duration_ms = int((time.monotonic() - start) * 1000)
        self._audit_log(
            "deep_scan_hunt",
            {"path": Path(path).name, "languages": languages, "severity_threshold": severity_threshold},
            len(findings),
            "OK",
            duration_ms,
        )

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({
                        "findings": serialize_models(findings),
                        "stats": serialize_model(stats),
                        "total_count": total_count,
                        "has_more": has_more,
                        "scan_id": scan_id,
                    }, ensure_ascii=False),
                }
            ]
        }

    async def _handle_verify(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle deep_scan_verify tool call."""
        start = time.monotonic()
        finding_ids: list[str] = params.get("finding_ids", [])
        target_path_raw: str = params.get("target_path", "")
        sandbox_timeout = min(int(params.get("sandbox_timeout_seconds", 30)), 300)
        max_verifications = int(params.get("max_verifications", 50))

        if not finding_ids:
            raise ToolError("finding_ids is required and must be non-empty", retryable=False)

        # Validate target path
        try:
            target_path = validate_path(target_path_raw, self.config.allowed_paths_str)
        except PathValidationError as e:
            raise ToolError(f"Path validation failed: {e}", retryable=False) from e

        # Retrieve findings from session store (reject externally-crafted IDs)
        findings = self._lookup_findings(finding_ids)
        if not findings:
            raise ToolError(
                "No findings found for the given IDs. "
                "Run deep_scan_hunt first to generate findings.",
                retryable=False,
            )

        # Validate all finding fields before verification
        validated_findings = []
        for f in findings:
            try:
                validated_findings.append(validate_raw_finding(f))
            except InputValidationError as e:
                logger.warning("Finding %s failed input validation: %s", f.id, e)
                # Skip invalid findings rather than failing the entire batch

        try:
            verified, stats = self.auditor.verify(
                findings=validated_findings,
                target_path=target_path,
                sandbox_timeout=sandbox_timeout,
                max_verifications=max_verifications,
            )
        except Exception as e:
            logger.error("Verification failed: %s", e)
            raise ToolError(f"Verification failed: {e}", retryable=True) from e

        # Store verified findings in session
        for vf in verified:
            self.auditor._session_verified[vf.finding.id] = vf

        duration_ms = int((time.monotonic() - start) * 1000)
        self._audit_log(
            "deep_scan_verify",
            {"finding_ids_count": len(finding_ids), "target": Path(target_path).name},
            len(verified),
            "OK",
            duration_ms,
        )

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({
                        "verified": serialize_models(verified),
                        "stats": serialize_model(stats),
                    }, ensure_ascii=False),
                }
            ]
        }

    async def _handle_remediate(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle deep_scan_remediate tool call."""
        start = time.monotonic()
        finding_ids: list[str] = params.get("finding_ids", [])
        target_path_raw: str = params.get("target_path", "")

        if not finding_ids:
            raise ToolError("finding_ids is required and must be non-empty", retryable=False)

        # Validate target path
        try:
            target_path = validate_path(target_path_raw, self.config.allowed_paths_str)
        except PathValidationError as e:
            raise ToolError(f"Path validation failed: {e}", retryable=False) from e

        # Retrieve verified findings from session
        verified_findings = self.auditor.get_verified_for_ids(finding_ids)
        if not verified_findings:
            raise ToolError(
                "No verified findings found for the given IDs. "
                "Run deep_scan_verify first.",
                retryable=False,
            )

        try:
            guidance, stats = self.architect.remediate(
                verified_findings=verified_findings,
                target_path=target_path,
            )
        except Exception as e:
            logger.error("Remediation failed: %s", e)
            raise ToolError(f"Remediation failed: {e}", retryable=True) from e

        duration_ms = int((time.monotonic() - start) * 1000)
        self._audit_log(
            "deep_scan_remediate",
            {"finding_ids_count": len(finding_ids), "target": Path(target_path).name},
            len(guidance),
            "OK",
            duration_ms,
        )

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({
                        "guidance": serialize_models(guidance),
                        "stats": serialize_model(stats),
                    }, ensure_ascii=False),
                }
            ]
        }

    async def _handle_full(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle deep_scan_full tool call."""
        start = time.monotonic()
        path_raw = params.get("path", "")

        # Validate path
        try:
            path = validate_path(path_raw, self.config.allowed_paths_str)
        except PathValidationError as e:
            raise ToolError(f"Path validation failed: {e}", retryable=False) from e

        languages = params.get("languages")
        severity_threshold = params.get("severity_threshold", "medium")
        sandbox_timeout = min(int(params.get("sandbox_timeout_seconds", 30)), 300)
        skip_verification = bool(params.get("skip_verification", False))
        max_results = min(int(params.get("max_results", 100)), 1000)
        max_verifications = int(params.get("max_verifications", 50))

        # Phase 1: Hunt
        try:
            findings, hunt_stats, total_count, has_more = self.hunter.scan(
                target_path=path,
                languages=languages,
                severity_threshold=severity_threshold,
                max_results=max_results,
                offset=0,
            )
        except Exception as e:
            raise ToolError(f"Hunt phase failed: {e}", retryable=True) from e

        # Store findings
        for f in findings:
            self._finding_by_id[f.id] = f

        # Phase 2: Verify (optional)
        verified = []
        verify_stats = None
        if not skip_verification and findings:
            validated = []
            for f in findings:
                try:
                    validated.append(validate_raw_finding(f))
                except InputValidationError:
                    pass

            try:
                verified, verify_stats = self.auditor.verify(
                    findings=validated,
                    target_path=path,
                    sandbox_timeout=sandbox_timeout,
                    max_verifications=max_verifications,
                )
                for vf in verified:
                    self.auditor._session_verified[vf.finding.id] = vf
            except Exception as e:
                logger.warning("Verify phase failed (continuing): %s", e)

        # Phase 3: Remediate
        guidance = []
        remediate_stats = None
        if verified:
            try:
                guidance, remediate_stats = self.architect.remediate(
                    verified_findings=verified,
                    target_path=path,
                )
            except Exception as e:
                logger.warning("Remediate phase failed (continuing): %s", e)
        elif findings and skip_verification:
            # Create synthetic verified findings for remediation when skipping verification
            from deep_code_security.auditor.confidence import compute_confidence
            from deep_code_security.auditor.models import VerifiedFinding
            synthetic_verified = []
            for f in findings:
                confidence, status = compute_confidence(f, [])
                synthetic_verified.append(VerifiedFinding(
                    finding=f,
                    exploit_results=[],
                    confidence_score=confidence,
                    verification_status=status,
                ))
            try:
                guidance, remediate_stats = self.architect.remediate(
                    verified_findings=synthetic_verified,
                    target_path=path,
                )
            except Exception as e:
                logger.warning("Remediate phase failed (continuing): %s", e)

        duration_ms = int((time.monotonic() - start) * 1000)
        self._audit_log(
            "deep_scan_full",
            {"path": Path(path).name, "severity_threshold": severity_threshold},
            len(findings),
            "OK",
            duration_ms,
        )

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({
                        "findings": serialize_models(findings),
                        "verified": serialize_models(verified),
                        "guidance": serialize_models(guidance),
                        "hunt_stats": serialize_model(hunt_stats),
                        "verify_stats": serialize_model(verify_stats) if verify_stats else None,
                        "remediate_stats": serialize_model(remediate_stats) if remediate_stats else None,
                        "total_count": total_count,
                        "has_more": has_more,
                    }, ensure_ascii=False),
                }
            ]
        }

    async def _handle_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle deep_scan_status tool call."""
        sandbox_available = self.auditor.sandbox.is_available()
        runtime = self.auditor.sandbox._runtime_cmd or "none"

        # Check which registry files are loaded
        registries = []
        registry_path = self.config.registry_path
        if registry_path.exists():
            registries = [
                f.stem
                for f in registry_path.glob("*.yaml")
                if f.is_file()
            ]

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({
                        "sandbox_available": sandbox_available,
                        "container_runtime": runtime,
                        "registries_loaded": sorted(registries),
                        "languages_supported": sorted(registries),
                        "server_version": self.SERVER_VERSION,
                        "allowed_paths": self.config.allowed_paths_str,
                    }, ensure_ascii=False),
                }
            ]
        }

    def _lookup_findings(self, finding_ids: list[str]) -> list[RawFinding]:
        """Look up findings from the server-side session store.

        Only returns findings that were generated by a previous deep_scan_hunt.
        External callers cannot inject arbitrary findings.

        Args:
            finding_ids: List of finding UUIDs.

        Returns:
            List of matching RawFinding instances.
        """
        return [
            self._finding_by_id[fid]
            for fid in finding_ids
            if fid in self._finding_by_id
        ]

    def _audit_log(
        self,
        tool: str,
        params_summary: dict[str, Any],
        result_count: int,
        verdict: str,
        duration_ms: int,
    ) -> None:
        """Log a tool invocation for audit purposes.

        Args:
            tool: Tool name.
            params_summary: Sanitized parameters (paths reduced to basename).
            result_count: Number of results returned.
            verdict: "OK", "REJECTED", "ERROR".
            duration_ms: Execution duration in milliseconds.
        """
        audit_logger.info(
            "TOOL_CALL tool=%s params=%s results=%d verdict=%s duration_ms=%d",
            tool,
            json.dumps(params_summary, ensure_ascii=False),
            result_count,
            verdict,
            duration_ms,
        )
