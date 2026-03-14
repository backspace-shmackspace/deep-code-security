"""JSON formatter — structured JSON output matching current --json-output behavior."""

from __future__ import annotations

import json

from deep_code_security.shared.formatters.protocol import FullScanResult, HuntResult
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
