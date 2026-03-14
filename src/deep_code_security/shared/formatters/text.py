"""Text formatter -- human-readable output matching current CLI behavior."""

from __future__ import annotations

import time
from pathlib import Path

from deep_code_security.shared.formatters.protocol import (
    FullScanResult,
    FuzzReportResult,
    HuntResult,
    ReplayResultDTO,
)

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

    def format_fuzz(self, data: FuzzReportResult, target_path: str = "") -> str:
        """Format fuzz run results as human-readable text."""
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("DEEP-CODE-SECURITY FUZZING REPORT")
        lines.append("=" * 60)

        if data.timestamp:
            lines.append(
                f"Timestamp:  "
                f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data.timestamp))}"
            )
        lines.append(f"Target:     {data.config_summary.target_path}")
        lines.append(f"Plugin:     {data.config_summary.plugin}")
        lines.append(f"Model:      {data.config_summary.model}")
        lines.append("")

        lines.append("--- Summary ---")
        lines.append(f"Targets discovered:   {len(data.targets)}")
        lines.append(f"Total iterations:     {data.total_iterations}")
        lines.append(f"Total inputs run:     {data.total_inputs}")
        lines.append(f"Crashes found:        {data.crash_count}")
        lines.append(f"Unique bugs:          {data.unique_crash_count}")
        lines.append(f"Timeouts:             {data.timeout_count}")

        if data.coverage_percent is not None:
            lines.append(f"Coverage:             {data.coverage_percent:.1f}%")

        if data.api_cost_usd is not None:
            lines.append(f"Estimated cost:       ${data.api_cost_usd:.4f}")

        lines.append("")

        if data.targets:
            lines.append("--- Targets ---")
            for target in data.targets:
                lines.append(f"  {target.qualified_name} ({target.signature})")
            lines.append("")

        if data.unique_crashes:
            lines.append("--- Crashes Found ---")
            lines.append(
                f"  Total raw crashes: {data.crash_count},"
                f" Unique bugs: {data.unique_crash_count}"
            )
            lines.append("")
            for i, uc in enumerate(data.unique_crashes, 1):
                count_label = f"({uc.count} occurrence{'s' if uc.count != 1 else ''})"
                lines.append(f"  [{i}] {uc.exception_type} {count_label}")
                lines.append(f"      Function:  {uc.representative.target_function}")
                lines.append(f"      Exception: {uc.representative.exception}")
                lines.append(f"      Args:      {uc.representative.args}")
                if uc.location:
                    lines.append(f"      Location:  {uc.location}")
                lines.append("")
        else:
            lines.append("--- No Crashes Found ---")
            lines.append("")

        lines.append("=" * 60)

        return "\n".join(lines)

    def format_replay(self, data: ReplayResultDTO, target_path: str = "") -> str:
        """Format replay results as human-readable text."""
        lines = ["=== Replay Results ==="]

        if not data.results:
            lines.append("No crash inputs were replayed.")
            return "\n".join(lines)

        for rr in data.results:
            fn = rr.target_function
            orig_type = rr.original_exception.split(":", 1)[0].strip()

            if rr.status == "fixed":
                lines.append(f"FIXED:  {fn} ({orig_type}) - no longer crashes")
            elif rr.status == "still_failing":
                replayed_msg = rr.replayed_exception or rr.original_exception
                lines.append(
                    f"FAIL:   {fn} ({orig_type}) - still crashes with {replayed_msg}"
                )
            else:
                new_type = (rr.replayed_exception or "").split(":", 1)[0].strip()
                lines.append(
                    f"ERROR:  {fn} ({orig_type}) - now raises {new_type}"
                    f" instead of {orig_type}"
                )

        lines.append("")
        lines.append(
            f"Summary: {data.fixed_count} fixed, {data.still_failing_count} still failing,"
            f" {data.error_count} error (total {data.total_count})"
        )

        return "\n".join(lines)
