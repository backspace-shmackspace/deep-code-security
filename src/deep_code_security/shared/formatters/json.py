"""JSON formatter -- structured JSON output."""

from __future__ import annotations

import json

from deep_code_security.shared.formatters.protocol import (
    FullScanResult,
    FuzzReportResult,
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
