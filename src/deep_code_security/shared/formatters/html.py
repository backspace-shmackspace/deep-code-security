"""HTML formatter — self-contained HTML report with inline CSS."""

from __future__ import annotations

import html
from datetime import UTC, datetime
from string import Template
from typing import Any

from deep_code_security.shared.formatters.protocol import FullScanResult, HuntResult

__all__ = ["HtmlFormatter"]

# Page skeleton template — only used for outermost structure.
# Repeating sections are built programmatically.
_PAGE_TEMPLATE = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       margin: 0; padding: 20px; background: #f5f5f5; color: #333; }
.container { max-width: 1200px; margin: 0 auto; }
h1 { color: #1a1a2e; }
.summary { background: #fff; padding: 20px; border-radius: 8px;
           margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.summary table { border-collapse: collapse; width: 100%; }
.summary td, .summary th { padding: 8px 12px; text-align: left; border-bottom: 1px solid #eee; }
.findings { background: #fff; padding: 20px; border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.finding-row { border-bottom: 1px solid #eee; padding: 10px 0; }
.severity-critical { color: #d32f2f; font-weight: bold; }
.severity-high { color: #e65100; font-weight: bold; }
.severity-medium { color: #f9a825; font-weight: bold; }
.severity-low { color: #2e7d32; }
details { margin: 10px 0; }
summary { cursor: pointer; padding: 5px; }
summary:hover { background: #f0f0f0; }
.code-block { background: #f8f8f8; padding: 12px; border-radius: 4px;
              font-family: monospace; white-space: pre-wrap; overflow-x: auto;
              border: 1px solid #e0e0e0; }
.taint-step { margin: 4px 0; padding-left: 20px; border-left: 2px solid #ccc; }
.guidance { background: #e8f5e9; padding: 12px; border-radius: 4px; margin: 8px 0; }
.footer { margin-top: 20px; padding: 12px; text-align: center; color: #888; font-size: 0.85em; }
.no-findings { color: #666; font-style: italic; padding: 20px; text-align: center; }
table.findings-table { border-collapse: collapse; width: 100%; }
table.findings-table th { background: #f0f0f0; padding: 8px 12px; text-align: left;
                          border-bottom: 2px solid #ddd; }
table.findings-table td { padding: 8px 12px; border-bottom: 1px solid #eee; }
</style>
</head>
<body>
<div class="container">
$summary_html
$findings_html
$footer_html
</div>
</body>
</html>
""")


def _escape(value: str) -> str:
    """HTML-escape a string and neutralize dollar signs for template safety."""
    escaped = html.escape(str(value), quote=True)
    return escaped.replace("$", "&#36;")


def _severity_class(severity: str) -> str:
    """Return CSS class for severity level."""
    return f"severity-{severity.lower()}"


class HtmlFormatter:
    """Produce self-contained HTML report."""

    def format_hunt(self, data: HuntResult, target_path: str = "") -> str:
        """Format hunt phase results as HTML."""
        title = "Deep Code Security — Hunt Report"
        summary_html = self._build_hunt_summary(data, target_path)
        findings_html = self._build_hunt_findings(data)
        footer_html = self._build_footer()

        return _PAGE_TEMPLATE.safe_substitute(
            title=_escape(title),
            summary_html=summary_html,
            findings_html=findings_html,
            footer_html=footer_html,
        )

    def format_full_scan(self, data: FullScanResult, target_path: str = "") -> str:
        """Format full-scan results as HTML."""
        title = "Deep Code Security — Full Scan Report"
        summary_html = self._build_full_scan_summary(data, target_path)
        findings_html = self._build_full_scan_findings(data)
        footer_html = self._build_footer()

        return _PAGE_TEMPLATE.safe_substitute(
            title=_escape(title),
            summary_html=summary_html,
            findings_html=findings_html,
            footer_html=footer_html,
        )

    def _build_hunt_summary(self, data: HuntResult, target_path: str) -> str:
        """Build summary section for hunt results."""
        now = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        parts = [
            '<div class="summary">',
            f"<h1>{_escape('Hunt Results')}</h1>",
            "<table>",
        ]
        if target_path:
            parts.append(
                f"<tr><th>Target</th><td>{_escape(target_path)}</td></tr>"
            )
        parts.extend([
            f"<tr><th>Scan Date</th><td>{_escape(now)}</td></tr>",
            f"<tr><th>Files Scanned</th><td>{data.stats.files_scanned}</td></tr>",
            f"<tr><th>Total Findings</th><td>{data.total_count}</td></tr>",
            f"<tr><th>Duration</th><td>{data.stats.scan_duration_ms}ms</td></tr>",
            "</table>",
            "</div>",
        ])
        return "\n".join(parts)

    def _build_full_scan_summary(self, data: FullScanResult, target_path: str) -> str:
        """Build summary section for full-scan results."""
        now = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        confirmed = sum(1 for v in data.verified if v.verification_status == "confirmed")
        likely = sum(1 for v in data.verified if v.verification_status == "likely")

        parts = [
            '<div class="summary">',
            f"<h1>{_escape('Full Scan Results')}</h1>",
            "<table>",
        ]
        if target_path:
            parts.append(
                f"<tr><th>Target</th><td>{_escape(target_path)}</td></tr>"
            )
        parts.extend([
            f"<tr><th>Scan Date</th><td>{_escape(now)}</td></tr>",
            f"<tr><th>Files Scanned</th><td>{data.hunt_stats.files_scanned}</td></tr>",
            f"<tr><th>Total Findings</th><td>{data.total_count}</td></tr>",
            f"<tr><th>Confirmed</th><td>{confirmed}</td></tr>",
            f"<tr><th>Likely</th><td>{likely}</td></tr>",
            f"<tr><th>Guidance Items</th><td>{len(data.guidance)}</td></tr>",
            "</table>",
            "</div>",
        ])
        return "\n".join(parts)

    def _build_hunt_findings(self, data: HuntResult) -> str:
        """Build findings section for hunt results."""
        if not data.findings:
            return '<div class="findings"><p class="no-findings">No findings detected.</p></div>'

        parts = ['<div class="findings">', "<h2>Findings</h2>"]
        parts.append('<table class="findings-table">')
        parts.append(
            "<thead><tr>"
            "<th>Severity</th>"
            "<th>CWE</th>"
            "<th>File:Line</th>"
            "<th>Vulnerability</th>"
            "<th>Confidence</th>"
            "</tr></thead>"
        )
        parts.append("<tbody>")

        for f in data.findings:
            sev_cls = _severity_class(f.severity)
            parts.append("<tr>")
            parts.append(f'<td class="{sev_cls}">{_escape(f.severity.upper())}</td>')
            parts.append(f"<td>{_escape(f.sink.cwe)}</td>")
            parts.append(
                f"<td>{_escape(f.sink.file)}:{f.sink.line}</td>"
            )
            parts.append(f"<td>{_escape(f.vulnerability_class)}</td>")
            parts.append(f"<td>{f.raw_confidence:.0%}</td>")
            parts.append("</tr>")

            # Expandable details
            parts.append("<tr><td colspan='5'>")
            parts.append("<details>")
            parts.append(f"<summary>Details for {_escape(f.vulnerability_class)}</summary>")
            parts.append(
                f"<p><strong>Source:</strong> {_escape(f.source.function)} "
                f"at {_escape(f.source.file)}:{f.source.line}</p>"
            )
            parts.append(
                f"<p><strong>Sink:</strong> {_escape(f.sink.function)} "
                f"at {_escape(f.sink.file)}:{f.sink.line}</p>"
            )

            if f.taint_path and f.taint_path.steps:
                parts.append("<p><strong>Taint Path:</strong></p>")
                for step in f.taint_path.steps:
                    parts.append(
                        f'<div class="taint-step">'
                        f"{_escape(step.file)}:{step.line} — "
                        f"{_escape(step.variable)} ({_escape(step.transform)})"
                        f"</div>"
                    )

            parts.append("</details>")
            parts.append("</td></tr>")

        parts.append("</tbody></table>")

        if data.has_more:
            parts.append(
                '<p style="color: #666; font-style: italic;">'
                "Additional findings available. Increase --max-results or use --offset.</p>"
            )

        parts.append("</div>")
        return "\n".join(parts)

    def _build_full_scan_findings(self, data: FullScanResult) -> str:
        """Build findings section for full-scan results."""
        if not data.findings:
            return '<div class="findings"><p class="no-findings">No findings detected.</p></div>'

        # Build lookups
        verified_by_id: dict[str, Any] = {}
        for v in data.verified:
            verified_by_id[v.finding.id] = v

        guidance_by_id: dict[str, Any] = {}
        for g in data.guidance:
            guidance_by_id[g.finding_id] = g

        parts = ['<div class="findings">', "<h2>Findings</h2>"]
        parts.append('<table class="findings-table">')
        parts.append(
            "<thead><tr>"
            "<th>Severity</th>"
            "<th>CWE</th>"
            "<th>File:Line</th>"
            "<th>Vulnerability</th>"
            "<th>Confidence</th>"
            "<th>Status</th>"
            "</tr></thead>"
        )
        parts.append("<tbody>")

        for f in data.findings:
            sev_cls = _severity_class(f.severity)
            verified = verified_by_id.get(f.id)
            guidance_item = guidance_by_id.get(f.id)

            confidence_str = f"{f.raw_confidence:.0%}"
            status_str = "—"
            if verified:
                confidence_str = f"{verified.confidence_score}%"
                status_str = verified.verification_status

            parts.append("<tr>")
            parts.append(f'<td class="{sev_cls}">{_escape(f.severity.upper())}</td>')
            parts.append(f"<td>{_escape(f.sink.cwe)}</td>")
            parts.append(
                f"<td>{_escape(f.sink.file)}:{f.sink.line}</td>"
            )
            parts.append(f"<td>{_escape(f.vulnerability_class)}</td>")
            parts.append(f"<td>{_escape(confidence_str)}</td>")
            parts.append(f"<td>{_escape(status_str)}</td>")
            parts.append("</tr>")

            # Expandable details
            parts.append("<tr><td colspan='6'>")
            parts.append("<details>")
            parts.append(f"<summary>Details for {_escape(f.vulnerability_class)}</summary>")
            parts.append(
                f"<p><strong>Source:</strong> {_escape(f.source.function)} "
                f"at {_escape(f.source.file)}:{f.source.line}</p>"
            )
            parts.append(
                f"<p><strong>Sink:</strong> {_escape(f.sink.function)} "
                f"at {_escape(f.sink.file)}:{f.sink.line}</p>"
            )

            if f.taint_path and f.taint_path.steps:
                parts.append("<p><strong>Taint Path:</strong></p>")
                for step in f.taint_path.steps:
                    parts.append(
                        f'<div class="taint-step">'
                        f"{_escape(step.file)}:{step.line} — "
                        f"{_escape(step.variable)} ({_escape(step.transform)})"
                        f"</div>"
                    )

            if guidance_item:
                parts.append('<div class="guidance">')
                parts.append("<p><strong>Remediation Guidance:</strong></p>")
                parts.append(
                    f"<p>{_escape(guidance_item.vulnerability_explanation)}</p>"
                )
                parts.append(
                    f"<p><strong>Fix Pattern:</strong> {_escape(guidance_item.fix_pattern)}</p>"
                )
                parts.append(
                    f'<div class="code-block">{_escape(guidance_item.code_example)}</div>'
                )
                if guidance_item.references:
                    parts.append("<p><strong>References:</strong></p><ul>")
                    for ref in guidance_item.references:
                        parts.append(f"<li>{_escape(ref)}</li>")
                    parts.append("</ul>")
                parts.append("</div>")

            parts.append("</details>")
            parts.append("</td></tr>")

        parts.append("</tbody></table>")
        parts.append("</div>")
        return "\n".join(parts)

    def _build_footer(self) -> str:
        """Build footer with tool version and timestamp."""
        try:
            from deep_code_security import __version__
        except (ImportError, AttributeError):
            __version__ = "1.0.0"

        now = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        return (
            f'<div class="footer">'
            f"Generated by deep-code-security v{_escape(__version__)} "
            f"at {_escape(now)}"
            f"</div>"
        )
