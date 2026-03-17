"""SAST-to-Fuzz bridge module.

Converts Hunter-phase RawFinding[] into fuzzer-compatible target specifications,
enabling automated fuzz target selection based on SAST taint analysis results.
"""

from __future__ import annotations

from deep_code_security.bridge.models import (
    BridgeConfig,
    BridgeResult,
    CorrelationEntry,
    CorrelationReport,
    FuzzTarget,
    SASTContext,
)
from deep_code_security.bridge.orchestrator import BridgeOrchestrator
from deep_code_security.bridge.resolver import resolve_findings_to_targets

__all__ = [
    "BridgeConfig",
    "BridgeOrchestrator",
    "BridgeResult",
    "CorrelationEntry",
    "CorrelationReport",
    "FuzzTarget",
    "SASTContext",
    "resolve_findings_to_targets",
]
