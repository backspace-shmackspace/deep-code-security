"""JSON formatter -- structured JSON output."""

from __future__ import annotations

import json

from deep_code_security.shared.formatters.protocol import (
    FullScanResult,
    FuzzReportResult,
    HuntFuzzResult,
    HuntResult,
    ReplayResultDTO,
)
from deep_code_security.shared.json_output import serialize_model, serialize_models

__all__ = ["JsonFormatter"]


class JsonFormatter:
    """Produce structured JSON output compatible with current --json-output."""

    def format_hunt(self, data: HuntResult, target_path: str = "") -> str:
        """Format hunt phase results as JSON."""
        output = {
            "findings": serialize_models(data.findings),
            "stats": serialize_model(data.stats),
            "total_count": data.total_count,
            "has_more": data.has_more,
        }
        return json.dumps(output, indent=2, ensure_ascii=False)

    def format_full_scan(self, data: FullScanResult, target_path: str = "") -> str:
        """Format full-scan results as JSON."""
        output = {
            "findings": serialize_models(data.findings),
            "verified": serialize_models(data.verified),
            "guidance": serialize_models(data.guidance),
            "hunt_stats": serialize_model(data.hunt_stats),
            "verify_stats": serialize_model(data.verify_stats) if data.verify_stats else None,
            "remediate_stats": (
                serialize_model(data.remediate_stats) if data.remediate_stats else None
            ),
            "total_count": data.total_count,
            "has_more": data.has_more,
        }
        return json.dumps(output, indent=2, ensure_ascii=False)

    def format_fuzz(self, data: FuzzReportResult, target_path: str = "") -> str:
        """Format fuzz run results as JSON."""
        output = {
            "schema_version": 2,
            "timestamp": data.timestamp,
            "config": serialize_model(data.config_summary),
            "summary": {
                "total_targets": len(data.targets),
                "total_iterations": data.total_iterations,
                "total_inputs": data.total_inputs,
                "crash_count": data.crash_count,
                "unique_crash_count": data.unique_crash_count,
                "timeout_count": data.timeout_count,
            },
            "targets": [serialize_model(t) for t in data.targets],
            "crashes": [serialize_model(c) for c in data.crashes],
            "unique_crashes": [serialize_model(uc) for uc in data.unique_crashes],
            "coverage": {
                "coverage_percent": data.coverage_percent,
            } if data.coverage_percent is not None else None,
            "api_usage": {
                "estimated_cost_usd": data.api_cost_usd,
            } if data.api_cost_usd is not None else None,
            "analysis_mode": data.analysis_mode,
        }
        return json.dumps(output, indent=2, ensure_ascii=False)

    def format_hunt_fuzz(self, data: HuntFuzzResult, target_path: str = "") -> str:
        """Format hunt-fuzz pipeline results as JSON."""
        br = data.bridge_result

        bridge_out = {
            "total_findings": br.total_findings,
            "fuzz_targets": [
                {
                    "file_path": t.file_path,
                    "function_name": t.function_name,
                    "requires_instance": t.requires_instance,
                    "parameter_count": t.parameter_count,
                    "finding_ids": t.finding_ids,
                    "sast_context": {
                        "cwe_ids": t.sast_context.cwe_ids,
                        "vulnerability_classes": t.sast_context.vulnerability_classes,
                        "sink_functions": t.sast_context.sink_functions,
                        "source_categories": t.sast_context.source_categories,
                        "severity": t.sast_context.severity,
                        "finding_count": t.sast_context.finding_count,
                    },
                }
                for t in br.fuzz_targets
            ],
            "skipped_findings": br.skipped_findings,
            "not_directly_fuzzable": br.not_directly_fuzzable,
            "skipped_reasons": br.skipped_reasons,
        }

        fuzz_out = None
        if data.fuzz_result:
            fr = data.fuzz_result
            fuzz_out = {
                "schema_version": 2,
                "timestamp": fr.timestamp,
                "config": serialize_model(fr.config_summary),
                "summary": {
                    "total_targets": len(fr.targets),
                    "total_iterations": fr.total_iterations,
                    "total_inputs": fr.total_inputs,
                    "crash_count": fr.crash_count,
                    "unique_crash_count": fr.unique_crash_count,
                    "timeout_count": fr.timeout_count,
                },
                "targets": [serialize_model(t) for t in fr.targets],
                "crashes": [serialize_model(c) for c in fr.crashes],
                "unique_crashes": [serialize_model(uc) for uc in fr.unique_crashes],
                "analysis_mode": fr.analysis_mode,
            }

        correlation_out = None
        if data.correlation:
            corr = data.correlation
            correlation_out = {
                "total_sast_findings": corr.total_sast_findings,
                "crash_in_scope_count": corr.crash_in_scope_count,
                "fuzz_targets_count": corr.fuzz_targets_count,
                "total_crashes": corr.total_crashes,
                "entries": [
                    {
                        "finding_id": e.finding_id,
                        "vulnerability_class": e.vulnerability_class,
                        "severity": e.severity,
                        "sink_function": e.sink_function,
                        "target_function": e.target_function,
                        "crash_in_finding_scope": e.crash_in_finding_scope,
                        "crash_count": e.crash_count,
                        "crash_signatures": e.crash_signatures,
                    }
                    for e in corr.entries
                ],
            }

        output = {
            "schema_version": 1,
            "analysis_mode": data.analysis_mode,
            "hunt_result": {
                "findings": serialize_models(data.hunt_result.findings),
                "stats": serialize_model(data.hunt_result.stats),
                "total_count": data.hunt_result.total_count,
                "has_more": data.hunt_result.has_more,
            },
            "bridge_result": bridge_out,
            "fuzz_result": fuzz_out,
            "correlation": correlation_out,
        }
        return json.dumps(output, indent=2, ensure_ascii=False)

    def format_replay(self, data: ReplayResultDTO, target_path: str = "") -> str:
        """Format replay results as JSON."""
        output = {
            "schema_version": 1,
            "summary": {
                "total": data.total_count,
                "fixed": data.fixed_count,
                "still_failing": data.still_failing_count,
                "error": data.error_count,
            },
            "results": [serialize_model(r) for r in data.results],
        }
        return json.dumps(output, indent=2, ensure_ascii=False)
