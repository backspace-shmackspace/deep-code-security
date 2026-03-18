"""Text formatter -- human-readable output matching current CLI behavior."""

from __future__ import annotations

import time
from pathlib import Path

from deep_code_security.shared.formatters.protocol import (
    FullScanResult,
    FuzzReportResult,
    HuntFuzzResult,
    HuntResult,
    ReplayResultDTO,
)

__all__ = ["TextFormatter"]


class TextFormatter:
    """Produce human-readable text output."""

    def format_hunt(self, data: HuntResult, target_path: str = "") -> str:
        """Format hunt phase results as human-readable text."""
        lines: list[str] = []

        suppressed_count = (
            data.suppression_summary.suppressed_count
            if data.suppression_summary is not None
            else 0
        )
        suppressed_note = f" ({suppressed_count} suppressed)" if suppressed_count > 0 else ""

        lines.append(
            f"Scanned {data.stats.files_scanned} files, "
            f"found {data.total_count} findings{suppressed_note} "
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

        if data.suppression_summary is not None and suppressed_count > 0:
            ss = data.suppression_summary
            expired_note = f", {ss.expired_rules} expired" if ss.expired_rules > 0 else ""
            lines.append(
                f"Suppressions: {suppressed_count} suppressed "
                f"({ss.total_rules} rules{expired_note})"
            )

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

    def format_hunt_fuzz(self, data: HuntFuzzResult, target_path: str = "") -> str:
        """Format combined hunt-fuzz pipeline results as human-readable text."""
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("DEEP-CODE-SECURITY HUNT+FUZZ REPORT")
        lines.append("=" * 60)
        lines.append("")

        # SAST section
        lines.append("--- SAST Results ---")
        lines.append(
            f"Scanned {data.hunt_result.stats.files_scanned} files, "
            f"found {data.hunt_result.total_count} findings "
            f"({data.hunt_result.stats.scan_duration_ms}ms)"
        )
        for f in data.hunt_result.findings:
            lines.append(
                f"  [{f.severity.upper()}] {f.vulnerability_class} "
                f"in {Path(f.source.file).name}:{f.source.line} -> "
                f"{Path(f.sink.file).name}:{f.sink.line}"
            )
        lines.append("")

        # Bridge section
        br = data.bridge_result
        lines.append("--- Bridge Analysis ---")
        lines.append(f"Total findings:         {br.total_findings}")
        lines.append(f"Fuzz targets found:     {len(br.fuzz_targets)}")
        lines.append(f"Not directly fuzzable:  {br.not_directly_fuzzable}")
        lines.append(f"Skipped findings:       {br.skipped_findings}")
        if br.fuzz_targets:
            for t in br.fuzz_targets:
                instance_note = " [requires instance]" if t.requires_instance else ""
                lines.append(
                    f"  Target: {t.function_name}{instance_note} "
                    f"({t.sast_context.severity}, {t.parameter_count} fuzzable params)"
                )
        lines.append("")

        # Fuzz section
        if data.fuzz_result:
            fr = data.fuzz_result
            lines.append("--- Fuzz Results ---")
            lines.append(f"Iterations:    {fr.total_iterations}")
            lines.append(f"Inputs run:    {fr.total_inputs}")
            lines.append(f"Crashes found: {fr.crash_count}")
            lines.append(f"Unique bugs:   {fr.unique_crash_count}")
            if fr.unique_crashes:
                for uc in fr.unique_crashes:
                    lines.append(
                        f"  [{uc.exception_type}] in {uc.representative.target_function}"
                    )
            lines.append("")

        # Correlation section
        if data.correlation:
            corr = data.correlation
            lines.append("--- Correlation ---")
            lines.append(
                f"Findings with crash activity in same scope: "
                f"{corr.crash_in_scope_count}/{corr.total_sast_findings}"
            )
            for entry in corr.entries:
                if entry.crash_in_finding_scope:
                    lines.append(
                        f"  CRASH IN SCOPE: {entry.target_function} "
                        f"({entry.vulnerability_class}) -- {entry.crash_count} crash(es)"
                    )
                    lines.append(
                        "    Note: crash does not confirm SAST vulnerability exploitation."
                    )
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
