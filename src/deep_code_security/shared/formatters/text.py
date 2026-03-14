"""Text formatter — human-readable output matching current CLI behavior."""

from __future__ import annotations

from pathlib import Path

from deep_code_security.shared.formatters.protocol import FullScanResult, HuntResult

__all__ = ["TextFormatter"]


class TextFormatter:
    """Produce human-readable text output."""

    def format_hunt(self, data: HuntResult, target_path: str = "") -> str:
        """Format hunt phase results as human-readable text."""
        lines: list[str] = []

        lines.append(
            f"Scanned {data.stats.files_scanned} files, "
            f"found {data.total_count} findings "
            f"({data.stats.scan_duration_ms}ms)"
        )

        for f in data.findings:
            lines.append(
                f"[{f.severity.upper()}] {f.vulnerability_class} "
                f"in {Path(f.source.file).name}:{f.source.line} -> "
                f"{Path(f.sink.file).name}:{f.sink.line}"
            )

        if data.has_more:
            lines.append("... and more results available (increase --max-results or use --offset)")

        return "\n".join(lines)

    def format_full_scan(self, data: FullScanResult, target_path: str = "") -> str:
        """Format full-scan results as human-readable text."""
        lines: list[str] = []

        lines.append("=== RESULTS ===")

        confirmed = [v for v in data.verified if v.verification_status == "confirmed"]
        likely = [v for v in data.verified if v.verification_status == "likely"]

        lines.append(f"Total findings: {data.total_count}")
        lines.append(f"Confirmed: {len(confirmed)}")
        lines.append(f"Likely: {len(likely)}")
        lines.append(f"Guidance items: {len(data.guidance)}")

        return "\n".join(lines)
