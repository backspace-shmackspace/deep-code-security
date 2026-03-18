"""DeepCodeSecurityMCPServer — MCP server with 6+ tools, path validation, and audit logging.

Runs as a native stdio process. Never containerized. Invokes Docker/Podman CLI
for sandbox containers (exploit verification and fuzzing).
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from deep_code_security.architect.orchestrator import ArchitectOrchestrator
from deep_code_security.auditor.orchestrator import AuditorOrchestrator
from deep_code_security.fuzzer.execution.sandbox import ContainerBackend, select_backend
from deep_code_security.hunter.models import RawFinding, ScanStats
from deep_code_security.hunter.orchestrator import HunterOrchestrator
from deep_code_security.mcp.input_validator import (
    InputValidationError,
    validate_crash_data,
    validate_function_name,
    validate_raw_finding,
)
from deep_code_security.mcp.path_validator import PathValidationError, validate_path
from deep_code_security.mcp.shared.server_base import BaseMCPServer, ToolError
from deep_code_security.shared.config import Config, get_config
from deep_code_security.shared.json_output import serialize_model, serialize_models

__all__ = ["DeepCodeSecurityMCPServer", "FuzzRunState"]

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("deep_code_security.audit")

_MAX_FUZZ_RUNS: int = 100
_MAX_CONCURRENT_FUZZ_RUNS: int = 2


@dataclass
class FuzzRunState:
    """Tracks the state of a single MCP-triggered fuzz run."""

    run_id: str
    status: str  # "running" | "completed" | "failed" | "timeout"
    result: dict | None = field(default=None)
    error: str | None = field(default=None)
    started_at: float = field(default_factory=time.monotonic)
    # Hunt-fuzz pipeline extras (populated for deep_scan_hunt_fuzz runs only)
    bridge_result: dict | None = field(default=None)
    correlation_result: dict | None = field(default=None)


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

        # Fuzz run state store (bounded to _MAX_FUZZ_RUNS entries)
        # Maps run_id -> FuzzRunState
        self._fuzz_runs: dict[str, FuzzRunState] = {}

    async def initialize(self) -> None:
        """Initialize orchestrators and register tools."""
        self._cleanup_orphan_containers()
        self._register_tools()

    def _cleanup_orphan_containers(self) -> None:
        """Remove any leftover fuzz containers from a previous server crash.

        Finds containers labelled dcs.fuzz_run_id and force-removes them.
        Silently skips if Podman is not available.
        """
        import subprocess as _sp

        try:
            result = _sp.run(
                ["podman", "ps", "-aq", "--filter", "label=dcs.fuzz_run_id"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return
            container_ids = result.stdout.strip().splitlines()
            if container_ids:
                logger.info(
                    "Cleaning up %d orphan fuzz container(s): %s",
                    len(container_ids),
                    container_ids,
                )
                _sp.run(
                    ["podman", "rm", "-f", *container_ids],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
        except Exception as exc:
            logger.debug("Orphan container cleanup skipped: %s", exc)

    async def validate_services(self) -> None:
        """Check sandbox availability (non-blocking warning if unavailable)."""
        if not self.auditor.sandbox.is_available():
            logger.warning(
                "Container runtime not available. Auditor phase will use base confidence only."
            )
        else:
            logger.info(
                "Container runtime available: %s",
                getattr(self.auditor.sandbox, "_runtime_cmd", None) or "unknown",
            )

    def _register_tools(self) -> None:
        """Register MCP tools. deep_scan_fuzz is registered only when ContainerBackend is available."""
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
                    "ignore_suppressions": {
                        "type": "boolean",
                        "default": False,
                        "description": "Ignore .dcs-suppress.yaml suppression rules",
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
                    "ignore_suppressions": {
                        "type": "boolean",
                        "default": False,
                        "description": "Ignore .dcs-suppress.yaml suppression rules",
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

        self.register_tool(
            name="deep_scan_fuzz_status",
            description=(
                "Check fuzzer availability and poll running fuzz operations. "
                "Returns anthropic SDK availability, Vertex AI configuration, "
                "consent status, available plugins, and container backend availability."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "fuzz_run_id": {
                        "type": "string",
                        "description": "Poll a specific fuzz run (optional)",
                    },
                },
            },
            handler=self._handle_fuzz_status,
        )

        # Register deep_scan_fuzz only when the ContainerBackend is available.
        # This resolves SD-01: MCP-triggered fuzz runs require container isolation.
        if ContainerBackend.is_available():
            self.register_tool(
                name="deep_scan_fuzz",
                description=(
                    "Run AI-powered fuzzing against a Python target file using the "
                    "Podman container backend for safe sandboxed execution. "
                    "Requires explicit consent=true (source code will be sent to the "
                    "Anthropic API for input generation). Returns a fuzz_run_id that "
                    "can be polled with deep_scan_fuzz_status."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "target_path": {
                            "type": "string",
                            "description": (
                                "Absolute path to the Python file to fuzz "
                                "(must be in DCS_ALLOWED_PATHS)"
                            ),
                        },
                        "functions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Specific function names to fuzz. "
                                "If omitted, all discovered targets are fuzzed."
                            ),
                        },
                        "consent": {
                            "type": "boolean",
                            "description": (
                                "Must be true. Confirms that you consent to sending "
                                "source code to the Anthropic API for fuzz input generation."
                            ),
                        },
                        "max_iterations": {
                            "type": "integer",
                            "default": 3,
                            "description": "Maximum fuzzing iterations (default: 3)",
                        },
                    },
                    "required": ["target_path", "consent"],
                },
                handler=self._handle_fuzz,
            )
            logger.info("deep_scan_fuzz tool registered (ContainerBackend available)")

            # Check Anthropic SDK availability for hunt-fuzz
            _anthropic_available = False
            try:
                import anthropic as _anthro  # noqa: F401
                _anthropic_available = True
            except ImportError:
                pass

            if _anthropic_available:
                self.register_tool(
                    name="deep_scan_hunt_fuzz",
                    description=(
                        "Run SAST analysis followed by AI-powered fuzzing of the vulnerable "
                        "functions identified. Requires consent=true (source code will be "
                        "sent to the Anthropic API for input generation). Returns a "
                        "fuzz_run_id that can be polled with deep_scan_fuzz_status."
                    ),
                    input_schema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": (
                                    "Absolute path to target codebase "
                                    "(must be in DCS_ALLOWED_PATHS)"
                                ),
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
                            "consent": {
                                "type": "boolean",
                                "description": (
                                    "Must be true. Confirms consent to send source code "
                                    "to the Anthropic API for fuzz input generation."
                                ),
                            },
                            "max_iterations": {
                                "type": "integer",
                                "default": 5,
                                "description": "Maximum fuzzing iterations (default: 5)",
                            },
                            "max_findings": {
                                "type": "integer",
                                "default": 100,
                                "description": "Maximum SAST findings to process",
                            },
                            "max_fuzz_targets": {
                                "type": "integer",
                                "default": 10,
                                "description": "Maximum fuzz targets from bridge (default: 10)",
                            },
                            "ignore_suppressions": {
                                "type": "boolean",
                                "default": False,
                                "description": "Ignore .dcs-suppress.yaml suppression rules",
                            },
                        },
                        "required": ["path", "consent"],
                    },
                    handler=self._handle_hunt_fuzz,
                )
                logger.info(
                    "deep_scan_hunt_fuzz tool registered "
                    "(ContainerBackend + Anthropic SDK available)"
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
        ignore_suppressions = bool(params.get("ignore_suppressions", False))

        try:
            findings, stats, total_count, has_more = self.hunter.scan(
                target_path=path,
                languages=languages,
                severity_threshold=severity_threshold,
                max_results=max_results,
                offset=offset,
                ignore_suppressions=ignore_suppressions,
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

        response: dict[str, Any] = {
            "findings": serialize_models(findings),
            "stats": serialize_model(stats),
            "total_count": total_count,
            "has_more": has_more,
            "scan_id": scan_id,
        }

        # Include suppression summary from ScanStats fields
        if (
            isinstance(stats, ScanStats)
            and (stats.suppression_rules_loaded > 0 or stats.findings_suppressed > 0)
        ):
            response["suppressions"] = {
                "suppressed_count": stats.findings_suppressed,
                "total_rules": stats.suppression_rules_loaded,
                "expired_rules": stats.suppression_rules_expired,
                "suppressed_finding_ids": stats.suppressed_finding_ids,
            }

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(response, ensure_ascii=False),
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
        ignore_suppressions = bool(params.get("ignore_suppressions", False))

        # Phase 1: Hunt
        try:
            findings, hunt_stats, total_count, has_more = self.hunter.scan(
                target_path=path,
                languages=languages,
                severity_threshold=severity_threshold,
                max_results=max_results,
                offset=0,
                ignore_suppressions=ignore_suppressions,
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

        full_response: dict[str, Any] = {
            "findings": serialize_models(findings),
            "verified": serialize_models(verified),
            "guidance": serialize_models(guidance),
            "hunt_stats": serialize_model(hunt_stats),
            "verify_stats": serialize_model(verify_stats) if verify_stats else None,
            "remediate_stats": serialize_model(remediate_stats) if remediate_stats else None,
            "total_count": total_count,
            "has_more": has_more,
        }

        # Include suppression summary from ScanStats fields
        if (
            isinstance(hunt_stats, ScanStats)
            and (hunt_stats.suppression_rules_loaded > 0 or hunt_stats.findings_suppressed > 0)
        ):
            full_response["suppressions"] = {
                "suppressed_count": hunt_stats.findings_suppressed,
                "total_rules": hunt_stats.suppression_rules_loaded,
                "expired_rules": hunt_stats.suppression_rules_expired,
                "suppressed_finding_ids": hunt_stats.suppressed_finding_ids,
            }

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(full_response, ensure_ascii=False),
                }
            ]
        }

    async def _handle_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle deep_scan_status tool call."""
        sandbox_available = self.auditor.sandbox.is_available()
        runtime = getattr(self.auditor.sandbox, "_runtime_cmd", None) or "none"

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

    async def _handle_fuzz_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle deep_scan_fuzz_status tool call."""
        start = time.monotonic()
        fuzz_run_id = params.get("fuzz_run_id")

        # Check anthropic availability
        try:
            import anthropic  # noqa: F401
            anthropic_available = True
        except ImportError:
            anthropic_available = False

        # Check Vertex configuration
        vertex_configured = self.config.fuzz_use_vertex

        # Check consent
        from deep_code_security.fuzzer.consent import has_stored_consent
        consent_stored = has_stored_consent()

        # Check available plugins
        try:
            from deep_code_security.fuzzer.plugins.registry import registry
            available_plugins = registry.list_plugins()
        except Exception:
            available_plugins = []

        # Dynamically check container backend availability
        container_backend_available = ContainerBackend.is_available()

        result: dict[str, Any] = {
            "anthropic_available": anthropic_available,
            "vertex_configured": vertex_configured,
            "consent_stored": consent_stored,
            "available_plugins": available_plugins,
            "container_backend_available": container_backend_available,
        }

        # If fuzz_run_id is provided, look it up in the run store
        if fuzz_run_id:
            run_state = self._fuzz_runs.get(fuzz_run_id)
            if run_state is None:
                result["fuzz_run"] = {
                    "fuzz_run_id": fuzz_run_id,
                    "status": "not_found",
                    "message": "No fuzz run found with this ID.",
                }
            else:
                run_info: dict[str, Any] = {
                    "fuzz_run_id": run_state.run_id,
                    "status": run_state.status,
                }
                if run_state.error:
                    run_info["error"] = run_state.error
                if run_state.result:
                    run_info["result"] = run_state.result
                if run_state.bridge_result:
                    run_info["bridge_result"] = run_state.bridge_result
                if run_state.correlation_result:
                    run_info["correlation_result"] = run_state.correlation_result
                result["fuzz_run"] = run_info

        duration_ms = int((time.monotonic() - start) * 1000)
        self._audit_log(
            "deep_scan_fuzz_status",
            {"fuzz_run_id": fuzz_run_id or "none"},
            0,
            "OK",
            duration_ms,
        )

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, ensure_ascii=False),
                }
            ]
        }

    async def _handle_fuzz(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle deep_scan_fuzz tool call.

        Validates consent, path, and function names, then launches a background
        thread that runs FuzzOrchestrator with ContainerBackend. Returns immediately
        with a fuzz_run_id that can be polled via deep_scan_fuzz_status.
        """

        # Consent check — must be explicitly True
        consent = params.get("consent", False)
        if not consent:
            raise ToolError(
                "deep_scan_fuzz requires explicit consent=true. "
                "By passing consent=true you acknowledge that source code from the target "
                "file will be transmitted to the Anthropic API for fuzz input generation.",
                retryable=False,
            )

        # Validate target path
        target_path_raw = params.get("target_path", "")
        try:
            target_path = validate_path(target_path_raw, self.config.allowed_paths_str)
        except PathValidationError as e:
            raise ToolError(f"Path validation failed: {e}", retryable=False) from e

        # Validate function names
        functions: list[str] = params.get("functions") or []
        validated_functions: list[str] = []
        for fn in functions:
            try:
                validated_functions.append(validate_function_name(fn))
            except InputValidationError as e:
                raise ToolError(
                    f"Invalid function name {fn!r}: {e}", retryable=False
                ) from e

        max_iterations = int(params.get("max_iterations", 3))

        # Enforce concurrent run limit before creating a new run state
        active_count = sum(
            1 for rs in self._fuzz_runs.values() if rs.status == "running"
        )
        if active_count >= _MAX_CONCURRENT_FUZZ_RUNS:
            raise ToolError(
                f"Maximum concurrent fuzz runs ({_MAX_CONCURRENT_FUZZ_RUNS}) already active. "
                "Try again later.",
                retryable=False,
            )

        # Create run state and store it (evict oldest non-running entries when full)
        run_id = str(uuid.uuid4())
        run_state = FuzzRunState(run_id=run_id, status="running")
        if len(self._fuzz_runs) >= _MAX_FUZZ_RUNS:
            # Evict oldest completed/failed/timeout entry
            evict_id = next(
                (
                    rid
                    for rid, rs in self._fuzz_runs.items()
                    if rs.status != "running"
                ),
                next(iter(self._fuzz_runs)),  # fallback: evict oldest
            )
            self._fuzz_runs.pop(evict_id, None)
        self._fuzz_runs[run_id] = run_state

        config = self.config

        # Shared mutable container so the timer callback can reach the orchestrator
        # after it is constructed inside the background thread.
        orchestrator_ref: list[Any] = [None]

        def _cancel_timeout() -> None:
            """Timer callback: mark run as timed out and signal orchestrator to stop."""
            if run_state.status == "running":
                logger.warning(
                    "Fuzz run %s exceeded MCP wall-clock timeout (%ds), marking as timeout",
                    run_id,
                    config.fuzz_mcp_timeout,
                )
                run_state.status = "timeout"
                run_state.error = (
                    f"Fuzz run exceeded the {config.fuzz_mcp_timeout}s wall-clock timeout."
                )
                orc = orchestrator_ref[0]
                if orc is not None:
                    orc._shutdown_requested = True

        def _run_fuzz() -> None:
            """Background thread: run fuzzing and update run_state."""
            from deep_code_security.fuzzer.config import FuzzerConfig
            from deep_code_security.fuzzer.orchestrator import FuzzOrchestrator

            timer: threading.Timer | None = None
            try:
                backend = select_backend(require_container=True)

                fuzz_config = FuzzerConfig(
                    target_path=target_path,
                    target_functions=validated_functions,
                    model=config.fuzz_model,
                    max_iterations=max_iterations,
                    inputs_per_iteration=config.fuzz_inputs_per_iteration,
                    timeout_ms=config.fuzz_timeout_ms,
                    max_cost_usd=config.fuzz_max_cost_usd,
                    output_dir=config.fuzz_output_dir,
                    consent=True,  # already validated above
                    use_vertex=config.fuzz_use_vertex,
                    gcp_project=config.fuzz_gcp_project,
                    gcp_region=config.fuzz_gcp_region,
                    plugin_name="python",
                    verbose=False,
                )

                orchestrator = FuzzOrchestrator(
                    config=fuzz_config,
                    install_signal_handlers=False,
                    backend=backend,
                )
                # Publish the orchestrator reference so the timer callback can
                # call orchestrator._shutdown_requested = True if needed.
                orchestrator_ref[0] = orchestrator

                # Start the wall-clock timeout timer now that the orchestrator
                # reference is in place.
                timer = threading.Timer(config.fuzz_mcp_timeout, _cancel_timeout)
                timer.daemon = True
                timer.start()

                report = orchestrator.run()

                run_state.status = "completed"
                run_state.result = {
                    "total_iterations": report.total_iterations,
                    "total_executions": len(report.all_results),
                    "crashes_found": len(report.crashes),
                    "targets": [t.qualified_name for t in report.targets],
                }

            except Exception as exc:
                logger.error("Fuzz run %s failed: %s", run_id, exc, exc_info=True)
                run_state.status = "failed"
                run_state.error = str(exc)

            finally:
                # Cancel the timer whether run completed normally or raised.
                # This prevents a completed-run timer from firing and prevents
                # the timer closure from holding references after exit.
                if timer is not None:
                    timer.cancel()

        fuzz_thread = threading.Thread(target=_run_fuzz, daemon=True, name=f"fuzz-{run_id[:8]}")
        fuzz_thread.start()

        self._audit_log(
            "deep_scan_fuzz",
            {"target": Path(target_path).name, "max_iterations": max_iterations},
            0,
            "OK",
            0,
        )

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "fuzz_run_id": run_id,
                            "status": "running",
                            "message": (
                                "Fuzz run started. Poll with deep_scan_fuzz_status "
                                f"using fuzz_run_id={run_id!r}."
                            ),
                        },
                        ensure_ascii=False,
                    ),
                }
            ]
        }

    async def _handle_hunt_fuzz(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle deep_scan_hunt_fuzz tool call.

        Validates consent and path, runs Hunter synchronously, runs bridge resolver
        synchronously, then launches fuzzing in a background thread (same pattern as
        _handle_fuzz). Returns immediately with a fuzz_run_id for polling.
        """

        # Consent check -- must be explicitly True
        consent = params.get("consent", False)
        if not consent:
            raise ToolError(
                "deep_scan_hunt_fuzz requires explicit consent=true. "
                "By passing consent=true you acknowledge that source code from the target "
                "codebase will be transmitted to the Anthropic API for fuzz input generation.",
                retryable=False,
            )

        # Validate path
        path_raw = params.get("path", "")
        try:
            path = validate_path(path_raw, self.config.allowed_paths_str)
        except PathValidationError as e:
            raise ToolError(f"Path validation failed: {e}", retryable=False) from e

        languages = params.get("languages")
        severity_threshold = params.get("severity_threshold", "medium")
        max_findings = min(int(params.get("max_findings", 100)), 1000)
        max_fuzz_targets = min(max(1, int(params.get("max_fuzz_targets", 10))), 100)
        max_iterations = int(params.get("max_iterations", 5))
        ignore_suppressions = bool(params.get("ignore_suppressions", False))

        # Enforce concurrent run limit
        active_count = sum(
            1 for rs in self._fuzz_runs.values() if rs.status == "running"
        )
        if active_count >= _MAX_CONCURRENT_FUZZ_RUNS:
            raise ToolError(
                f"Maximum concurrent fuzz runs ({_MAX_CONCURRENT_FUZZ_RUNS}) already active. "
                "Try again later.",
                retryable=False,
            )

        # Phase 1: Hunt (synchronous -- fast)
        try:
            findings, hunt_stats, total_count, has_more = self.hunter.scan(
                target_path=path,
                languages=languages,
                severity_threshold=severity_threshold,
                max_results=max_findings,
                offset=0,
                ignore_suppressions=ignore_suppressions,
            )
        except Exception as e:
            logger.error("Hunt phase failed in hunt_fuzz: %s", e)
            raise ToolError(f"Hunt phase failed: {e}", retryable=True) from e

        # Store findings in session
        scan_id = str(uuid.uuid4())
        if len(self._findings_session) >= self._MAX_SESSION_SCANS:
            _, evicted_findings = self._findings_session.popitem(last=False)
            for ef in evicted_findings:
                self._finding_by_id.pop(ef.id, None)
        self._findings_session[scan_id] = findings
        for f in findings:
            self._finding_by_id[f.id] = f

        # Phase 2: Bridge (synchronous -- fast)
        from deep_code_security.bridge.models import BridgeConfig
        from deep_code_security.bridge.orchestrator import BridgeOrchestrator

        bridge_config = BridgeConfig(max_targets=max_fuzz_targets)
        bridge_orc = BridgeOrchestrator()
        bridge_result = bridge_orc.run_bridge(findings, config=bridge_config)
        fuzz_targets = bridge_result.fuzz_targets

        bridge_summary = {
            "total_findings": bridge_result.total_findings,
            "fuzz_targets_count": len(fuzz_targets),
            "skipped_findings": bridge_result.skipped_findings,
            "not_directly_fuzzable": bridge_result.not_directly_fuzzable,
            "targets": [
                {
                    "function_name": t.function_name,
                    "file_path": t.file_path,
                    "requires_instance": t.requires_instance,
                    "severity": t.sast_context.severity,
                }
                for t in fuzz_targets
            ],
        }

        if not fuzz_targets:
            # No fuzz targets -- return immediately with diagnostics
            no_target_response: dict[str, Any] = {
                "status": "no_fuzz_targets",
                "message": (
                    "No fuzz targets found. Findings may be in route handlers "
                    "that require framework harnesses. "
                    f"not_directly_fuzzable={bridge_result.not_directly_fuzzable}"
                ),
                "hunt_summary": {
                    "total_findings": total_count,
                    "scan_id": scan_id,
                },
                "bridge_summary": bridge_summary,
            }
            if (
                isinstance(hunt_stats, ScanStats)
                and (hunt_stats.suppression_rules_loaded > 0 or hunt_stats.findings_suppressed > 0)
            ):
                no_target_response["suppressions"] = {
                    "suppressed_count": hunt_stats.findings_suppressed,
                    "total_rules": hunt_stats.suppression_rules_loaded,
                    "expired_rules": hunt_stats.suppression_rules_expired,
                    "suppressed_finding_ids": hunt_stats.suppressed_finding_ids,
                }
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(no_target_response, ensure_ascii=False),
                    }
                ]
            }

        # Create run state
        run_id = str(uuid.uuid4())
        run_state = FuzzRunState(run_id=run_id, status="running")
        if len(self._fuzz_runs) >= _MAX_FUZZ_RUNS:
            evict_id = next(
                (
                    rid
                    for rid, rs in self._fuzz_runs.items()
                    if rs.status != "running"
                ),
                next(iter(self._fuzz_runs)),
            )
            self._fuzz_runs.pop(evict_id, None)
        self._fuzz_runs[run_id] = run_state

        config = self.config
        orchestrator_ref: list[Any] = [None]

        def _cancel_timeout_hf() -> None:
            if run_state.status == "running":
                logger.warning(
                    "Hunt-fuzz run %s exceeded MCP wall-clock timeout (%ds)",
                    run_id,
                    config.fuzz_mcp_timeout,
                )
                run_state.status = "timeout"
                run_state.error = (
                    f"Fuzz run exceeded the {config.fuzz_mcp_timeout}s wall-clock timeout."
                )
                orc = orchestrator_ref[0]
                if orc is not None:
                    orc._shutdown_requested = True

        # Capture loop-local values for the thread closure
        _fuzz_targets = list(fuzz_targets)
        _bridge_result = bridge_result
        _bridge_orc = bridge_orc

        def _run_hunt_fuzz() -> None:
            from deep_code_security.fuzzer.config import FuzzerConfig
            from deep_code_security.fuzzer.execution.sandbox import select_backend
            from deep_code_security.fuzzer.orchestrator import FuzzOrchestrator

            timer: threading.Timer | None = None
            try:
                backend = select_backend(require_container=True)

                sast_contexts = {t.function_name: t.sast_context for t in _fuzz_targets}
                target_functions = [t.function_name for t in _fuzz_targets]
                fuzz_target_path = str(path)

                fuzz_config = FuzzerConfig(
                    target_path=fuzz_target_path,
                    target_functions=target_functions,
                    model=config.fuzz_model,
                    max_iterations=max_iterations,
                    inputs_per_iteration=config.fuzz_inputs_per_iteration,
                    timeout_ms=config.fuzz_timeout_ms,
                    max_cost_usd=config.fuzz_max_cost_usd,
                    output_dir=config.fuzz_output_dir,
                    consent=True,
                    use_vertex=config.fuzz_use_vertex,
                    gcp_project=config.fuzz_gcp_project,
                    gcp_region=config.fuzz_gcp_region,
                    plugin_name="python",
                    verbose=False,
                )
                fuzz_config.sast_contexts = sast_contexts  # type: ignore[assignment]

                orchestrator = FuzzOrchestrator(
                    config=fuzz_config,
                    install_signal_handlers=False,
                    backend=backend,
                )
                orchestrator_ref[0] = orchestrator

                timer = threading.Timer(config.fuzz_mcp_timeout, _cancel_timeout_hf)
                timer.daemon = True
                timer.start()

                fuzz_report = orchestrator.run()

                # Correlate
                correlation = _bridge_orc.correlate(_bridge_result, fuzz_report)

                # Sanitize crash signatures before storing in run state
                sanitized_entries = []
                for entry in correlation.entries:
                    sanitized_sigs: list[str] = []
                    for sig in entry.crash_signatures:
                        try:
                            validated = validate_crash_data(
                                exception=sig,
                                traceback_str=None,
                                target_function=entry.target_function,
                            )
                            safe_sig = validated.get("exception") or sig[:2048]
                        except Exception:
                            safe_sig = sig[:2048]
                        sanitized_sigs.append(safe_sig)
                    sanitized_entries.append({
                        "finding_id": entry.finding_id,
                        "vulnerability_class": entry.vulnerability_class,
                        "severity": entry.severity,
                        "sink_function": entry.sink_function,
                        "target_function": entry.target_function,
                        "crash_in_finding_scope": entry.crash_in_finding_scope,
                        "crash_count": entry.crash_count,
                        "crash_signatures": sanitized_sigs,
                    })

                run_state.correlation_result = {
                    "total_sast_findings": correlation.total_sast_findings,
                    "crash_in_scope_count": correlation.crash_in_scope_count,
                    "fuzz_targets_count": correlation.fuzz_targets_count,
                    "total_crashes": correlation.total_crashes,
                    "entries": sanitized_entries,
                }
                run_state.bridge_result = bridge_summary
                run_state.status = "completed"
                run_state.result = {
                    "total_iterations": fuzz_report.total_iterations,
                    "total_executions": len(fuzz_report.all_results),
                    "crashes_found": len(fuzz_report.crashes),
                    "targets": [t.qualified_name for t in fuzz_report.targets],
                }

            except Exception as exc:
                logger.error("Hunt-fuzz run %s failed: %s", run_id, exc, exc_info=True)
                run_state.status = "failed"
                run_state.error = str(exc)

            finally:
                if timer is not None:
                    timer.cancel()

        hf_thread = threading.Thread(
            target=_run_hunt_fuzz,
            daemon=True,
            name=f"hunt-fuzz-{run_id[:8]}",
        )
        hf_thread.start()

        self._audit_log(
            "deep_scan_hunt_fuzz",
            {
                "path": Path(path).name,
                "max_iterations": max_iterations,
                "fuzz_targets": len(fuzz_targets),
            },
            len(findings),
            "OK",
            0,
        )

        hf_started_response: dict[str, Any] = {
            "fuzz_run_id": run_id,
            "status": "running",
            "hunt_summary": {
                "total_findings": total_count,
                "scan_id": scan_id,
            },
            "bridge_summary": bridge_summary,
            "message": (
                "Hunt-fuzz run started. Poll with deep_scan_fuzz_status "
                f"using fuzz_run_id={run_id!r}."
            ),
        }
        if (
            isinstance(hunt_stats, ScanStats)
            and (hunt_stats.suppression_rules_loaded > 0 or hunt_stats.findings_suppressed > 0)
        ):
            hf_started_response["suppressions"] = {
                "suppressed_count": hunt_stats.findings_suppressed,
                "total_rules": hunt_stats.suppression_rules_loaded,
                "expired_rules": hunt_stats.suppression_rules_expired,
                "suppressed_finding_ids": hunt_stats.suppressed_finding_ids,
            }

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(hf_started_response, ensure_ascii=False),
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
