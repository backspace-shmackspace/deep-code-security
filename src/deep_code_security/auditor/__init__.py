"""Auditor phase — Verification Agent for exploit testing and confidence scoring."""

from deep_code_security.auditor.models import ExploitResult, VerifiedFinding, VerifyStats
from deep_code_security.auditor.noop import NoOpExploitGenerator, NoOpSandbox
from deep_code_security.auditor.orchestrator import AuditorOrchestrator
from deep_code_security.auditor.protocols import ExploitGeneratorProtocol, SandboxProvider

__all__ = [
    "AuditorOrchestrator",
    "ExploitGeneratorProtocol",
    "ExploitResult",
    "NoOpExploitGenerator",
    "NoOpSandbox",
    "SandboxProvider",
    "VerifiedFinding",
    "VerifyStats",
]
