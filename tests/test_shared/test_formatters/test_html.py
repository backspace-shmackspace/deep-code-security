"""Tests for HtmlFormatter."""

from __future__ import annotations

from deep_code_security.hunter.models import (
    RawFinding,
    Sink,
    Source,
    TaintPath,
)
from deep_code_security.shared.formatters.html import HtmlFormatter
from deep_code_security.shared.formatters.protocol import HuntResult


class TestHtmlStructure:
    def test_html_valid_structure(self, sample_hunt_result):
        fmt = HtmlFormatter()
        output = fmt.format_hunt(sample_hunt_result)
        assert "<html" in output
        assert "<head>" in output
        assert "<body>" in output
        assert "</html>" in output

    def test_html_meta_charset(self, sample_hunt_result):
        fmt = HtmlFormatter()
        output = fmt.format_hunt(sample_hunt_result)
        assert '<meta charset="utf-8">' in output

    def test_html_contains_finding_data(self, sample_hunt_result):
        fmt = HtmlFormatter()
        output = fmt.format_hunt(sample_hunt_result)
        assert "app.py" in output
        assert ":15" in output  # sink line
        assert "SQL Injection" in output

    def test_html_summary_stats(self, sample_hunt_result):
        fmt = HtmlFormatter()
        output = fmt.format_hunt(sample_hunt_result, target_path="/tmp/project")
        assert "42" in output  # files_scanned
        assert "150ms" in output  # duration


class TestHtmlEscaping:
    def test_html_escapes_special_chars(self, sample_stats):
        """<script> in file path must be escaped."""
        finding = RawFinding(
            id="xss-test",
            source=Source(
                file="/tmp/<script>alert(1)</script>.py",
                line=1, column=0,
                function="request.form",
                category="web_input",
                language="python",
            ),
            sink=Sink(
                file="/tmp/<script>alert(1)</script>.py",
                line=5, column=0,
                function="eval",
                category="code_injection",
                cwe="CWE-94",
                language="python",
            ),
            taint_path=TaintPath(steps=[], sanitized=False),
            vulnerability_class="CWE-94: Code Injection",
            severity="high",
            language="python",
            raw_confidence=0.5,
        )
        result = HuntResult(findings=[finding], stats=sample_stats, total_count=1)
        fmt = HtmlFormatter()
        output = fmt.format_hunt(result)
        assert "<script>" not in output
        assert "&lt;script&gt;" in output

    def test_html_escapes_quotes(self, sample_stats):
        """Quotes in attribute contexts must be escaped."""
        finding = RawFinding(
            id="quote-test",
            source=Source(
                file='/tmp/test"file.py',
                line=1, column=0,
                function="request.form",
                category="web_input",
                language="python",
            ),
            sink=Sink(
                file='/tmp/test"file.py',
                line=5, column=0,
                function="eval",
                category="code_injection",
                cwe="CWE-94",
                language="python",
            ),
            taint_path=TaintPath(steps=[], sanitized=False),
            vulnerability_class="CWE-94: Code Injection",
            severity="high",
            language="python",
            raw_confidence=0.5,
        )
        result = HuntResult(findings=[finding], stats=sample_stats, total_count=1)
        fmt = HtmlFormatter()
        output = fmt.format_hunt(result)
        assert '&quot;' in output

    def test_html_escapes_ampersand(self, sample_stats):
        finding = RawFinding(
            id="amp-test",
            source=Source(
                file="/tmp/test.py",
                line=1, column=0,
                function="request.form",
                category="web_input",
                language="python",
            ),
            sink=Sink(
                file="/tmp/test.py",
                line=5, column=0,
                function="eval",
                category="code_injection",
                cwe="CWE-94",
                language="python",
            ),
            taint_path=TaintPath(steps=[], sanitized=False),
            vulnerability_class="CWE-94: A & B Injection",
            severity="high",
            language="python",
            raw_confidence=0.5,
        )
        result = HuntResult(findings=[finding], stats=sample_stats, total_count=1)
        fmt = HtmlFormatter()
        output = fmt.format_hunt(result)
        assert "A &amp; B Injection" in output

    def test_html_escapes_dollar_sign(self, sample_stats):
        """$HOME in file path rendered as &#36;HOME, not substituted."""
        finding = RawFinding(
            id="dollar-test",
            source=Source(
                file="/tmp/$HOME/test.py",
                line=1, column=0,
                function="request.form",
                category="web_input",
                language="python",
            ),
            sink=Sink(
                file="/tmp/$HOME/test.py",
                line=5, column=0,
                function="eval",
                category="code_injection",
                cwe="CWE-94",
                language="python",
            ),
            taint_path=TaintPath(steps=[], sanitized=False),
            vulnerability_class="CWE-94: Code Injection",
            severity="high",
            language="python",
            raw_confidence=0.5,
        )
        result = HuntResult(findings=[finding], stats=sample_stats, total_count=1)
        fmt = HtmlFormatter()
        output = fmt.format_hunt(result)
        assert "&#36;HOME" in output
        assert "$HOME" not in output


class TestHtmlSeverityColors:
    def test_html_severity_colors(
        self, sample_finding, sample_finding_medium, sample_finding_low, sample_stats
    ):
        result = HuntResult(
            findings=[sample_finding, sample_finding_medium, sample_finding_low],
            stats=sample_stats,
            total_count=3,
        )
        fmt = HtmlFormatter()
        output = fmt.format_hunt(result)
        assert "severity-critical" in output
        assert "severity-medium" in output
        assert "severity-low" in output


class TestHtmlFullScan:
    def test_html_full_scan_includes_guidance(self, sample_full_scan_result):
        fmt = HtmlFormatter()
        output = fmt.format_full_scan(sample_full_scan_result, target_path="/tmp/project")
        assert "Remediation Guidance" in output
        assert "parameterized queries" in output

    def test_html_empty_findings(self, sample_stats):
        result = HuntResult(findings=[], stats=sample_stats, total_count=0)
        fmt = HtmlFormatter()
        output = fmt.format_hunt(result)
        assert "No findings detected" in output
        assert "<html" in output


class TestHtmlSuppressions:
    """Tests for HTML suppression section in hunt output."""

    def test_html_format_hunt_with_suppressions(self, sample_finding, sample_stats):
        """HTML output includes a suppression section when suppressions active."""
        from deep_code_security.shared.formatters.protocol import HuntResult, SuppressionSummary

        ss = SuppressionSummary(
            suppressed_count=2,
            total_rules=3,
            expired_rules=0,
            suppression_reasons={
                "f1": "Admin controlled path",
                "f2": "Auto-generated code",
            },
            suppression_file="/project/.dcs-suppress.yaml",
        )
        result = HuntResult(
            findings=[sample_finding],
            stats=sample_stats,
            total_count=1,
            has_more=False,
            suppression_summary=ss,
        )
        fmt = HtmlFormatter()
        output = fmt.format_hunt(result)
        assert "Suppressions" in output
        assert "2 finding(s) suppressed" in output
        assert "Admin controlled path" in output
        assert "Auto-generated code" in output

    def test_html_format_hunt_with_suppressions_and_expired(
        self, sample_finding, sample_stats
    ):
        """Expired count appears in suppression section."""
        from deep_code_security.shared.formatters.protocol import HuntResult, SuppressionSummary

        ss = SuppressionSummary(
            suppressed_count=1,
            total_rules=4,
            expired_rules=2,
            suppression_reasons={"f1": "Known FP"},
            suppression_file="/project/.dcs-suppress.yaml",
        )
        result = HuntResult(
            findings=[sample_finding],
            stats=sample_stats,
            total_count=1,
            has_more=False,
            suppression_summary=ss,
        )
        fmt = HtmlFormatter()
        output = fmt.format_hunt(result)
        assert "2 expired" in output

    def test_html_format_hunt_no_suppressions(self, sample_hunt_result):
        """No suppression section when suppression_summary is None."""
        fmt = HtmlFormatter()
        output = fmt.format_hunt(sample_hunt_result)
        assert "Suppressions" not in output

    def test_html_format_hunt_zero_suppressed_no_section(
        self, sample_finding, sample_stats
    ):
        """No suppression section when suppressed_count is 0."""
        from deep_code_security.shared.formatters.protocol import HuntResult, SuppressionSummary

        ss = SuppressionSummary(
            suppressed_count=0,
            total_rules=2,
            expired_rules=0,
            suppression_reasons={},
            suppression_file="/project/.dcs-suppress.yaml",
        )
        result = HuntResult(
            findings=[sample_finding],
            stats=sample_stats,
            total_count=1,
            has_more=False,
            suppression_summary=ss,
        )
        fmt = HtmlFormatter()
        output = fmt.format_hunt(result)
        assert "Suppressions" not in output

    def test_html_suppression_section_escapes_reasons(
        self, sample_finding, sample_stats
    ):
        """Suppression reasons are HTML-escaped."""
        from deep_code_security.shared.formatters.protocol import HuntResult, SuppressionSummary

        ss = SuppressionSummary(
            suppressed_count=1,
            total_rules=1,
            expired_rules=0,
            suppression_reasons={"f1": "<script>alert(1)</script>"},
            suppression_file="/project/.dcs-suppress.yaml",
        )
        result = HuntResult(
            findings=[sample_finding],
            stats=sample_stats,
            total_count=1,
            has_more=False,
            suppression_summary=ss,
        )
        fmt = HtmlFormatter()
        output = fmt.format_hunt(result)
        assert "<script>" not in output
        assert "&lt;script&gt;" in output
