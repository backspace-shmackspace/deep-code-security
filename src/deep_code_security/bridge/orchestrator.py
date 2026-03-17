"""Orchestrates the SAST-to-Fuzz pipeline."""

from __future__ import annotations

import logging

from deep_code_security.bridge.models import (
    BridgeConfig,
    BridgeResult,
    CorrelationEntry,
    CorrelationReport,
)
from deep_code_security.bridge.resolver import resolve_findings_to_targets
from deep_code_security.fuzzer.models import FuzzReport
from deep_code_security.hunter.models import RawFinding

__all__ = ["BridgeOrchestrator"]

logger = logging.getLogger(__name__)


class BridgeOrchestrator:
    """Orchestrates the Hunt -> Resolve -> Fuzz -> Correlate pipeline."""

    def run_bridge(
        self,
        findings: list[RawFinding],
        config: BridgeConfig | None = None,
    ) -> BridgeResult:
        """Convert SAST findings to fuzz targets.

        Args:
            findings: RawFinding list from the Hunter phase.
            config: Optional bridge configuration.

        Returns:
            BridgeResult with deduplicated, capped fuzz target list.
        """
        return resolve_findings_to_targets(findings, config=config)

    def correlate(
        self,
        bridge_result: BridgeResult,
        fuzz_report: FuzzReport,
    ) -> CorrelationReport:
        """Correlate SAST findings with fuzz results.

        For each fuzz target derived from SAST findings, check if the
        fuzzer found crashes in the same function. A crash in a function
        that has a SAST finding indicates dynamic crash activity in the
        same scope, but does NOT confirm that the specific SAST
        vulnerability was exploited.

        Args:
            bridge_result: The bridge analysis result containing fuzz targets.
            fuzz_report: The completed fuzz report.

        Returns:
            CorrelationReport with entries for each finding.
        """
        # Build lookup: function_name -> list of crash signatures
        crashes_by_function: dict[str, list[str]] = {}
        for crash in fuzz_report.crashes:
            fn = crash.input.target_function
            crashes_by_function.setdefault(fn, [])

        # Build unique crash signatures by function
        for uc in fuzz_report.unique_crashes:
            fn = uc.representative.input.target_function
            sig = uc.signature
            crashes_by_function.setdefault(fn, [])
            if sig and sig not in crashes_by_function[fn]:
                crashes_by_function[fn].append(sig)

        # Count raw crashes per function
        crash_counts_by_function: dict[str, int] = {}
        for crash in fuzz_report.crashes:
            fn = crash.input.target_function
            crash_counts_by_function[fn] = crash_counts_by_function.get(fn, 0) + 1

        entries: list[CorrelationEntry] = []
        crash_in_scope_count = 0

        for target in bridge_result.fuzz_targets:
            fn_name = target.function_name
            in_scope = fn_name in crashes_by_function and crash_counts_by_function.get(fn_name, 0) > 0
            crash_count = crash_counts_by_function.get(fn_name, 0)
            crash_sigs = crashes_by_function.get(fn_name, [])

            for finding_id in target.finding_ids:
                entry = CorrelationEntry(
                    finding_id=finding_id,
                    vulnerability_class=target.sast_context.vulnerability_classes[0]
                    if target.sast_context.vulnerability_classes
                    else "",
                    severity=target.sast_context.severity,
                    sink_function=target.sast_context.sink_functions[0]
                    if target.sast_context.sink_functions
                    else "",
                    target_function=fn_name,
                    crash_in_finding_scope=in_scope,
                    crash_count=crash_count,
                    crash_signatures=list(crash_sigs),
                )
                entries.append(entry)
                if in_scope:
                    crash_in_scope_count += 1

        return CorrelationReport(
            entries=entries,
            total_sast_findings=sum(
                len(t.finding_ids) for t in bridge_result.fuzz_targets
            ),
            crash_in_scope_count=crash_in_scope_count,
            fuzz_targets_count=len(bridge_result.fuzz_targets),
            total_crashes=len(fuzz_report.crashes),
        )
