"""Tests for stderr pattern parsing in ScanRunner."""

from __future__ import annotations

import re

from deep_code_security.tui.runner import (
    PATTERN_ERROR,
    PATTERN_FINDINGS_COUNT,
    PATTERN_PHASE_TRANSITION,
    PATTERN_SCANNING,
    parse_stderr_line,
)


class TestPatternConstants:
    """Verify the regex constants match expected strings."""

    def test_scanning_pattern_matches(self) -> None:
        """PATTERN_SCANNING matches 'Scanning /path...' lines."""
        m = PATTERN_SCANNING.match("Scanning /tmp/project...")
        assert m is not None
        assert m.group("path") == "/tmp/project"

    def test_scanning_pattern_with_spaces(self) -> None:
        """PATTERN_SCANNING matches paths with spaces."""
        m = PATTERN_SCANNING.match("Scanning /tmp/my project/src...")
        assert m is not None
        assert m.group("path") == "/tmp/my project/src"

    def test_phase_transition_pattern(self) -> None:
        """PATTERN_PHASE_TRANSITION matches '[1/3] Scanning...'."""
        m = PATTERN_PHASE_TRANSITION.match("[1/3] Scanning...")
        assert m is not None
        assert m.group("current") == "1"
        assert m.group("total") == "3"
        assert m.group("description") == "Scanning..."

    def test_phase_transition_with_detail(self) -> None:
        """PATTERN_PHASE_TRANSITION matches '[2/3] Verifying 47 findings...'."""
        m = PATTERN_PHASE_TRANSITION.match("[2/3] Verifying 47 findings...")
        assert m is not None
        assert m.group("current") == "2"
        assert m.group("total") == "3"
        assert m.group("description") == "Verifying 47 findings..."

    def test_findings_count_pattern(self) -> None:
        """PATTERN_FINDINGS_COUNT matches 'Found N findings in M files'."""
        m = PATTERN_FINDINGS_COUNT.match("Found 12 findings in 34 files")
        assert m is not None
        assert m.group("findings") == "12"
        assert m.group("files") == "34"

    def test_findings_count_leading_whitespace(self) -> None:
        """PATTERN_FINDINGS_COUNT matches with leading whitespace."""
        m = PATTERN_FINDINGS_COUNT.match("  Found 5 findings in 3 files")
        assert m is not None
        assert m.group("findings") == "5"
        assert m.group("files") == "3"

    def test_findings_count_singular(self) -> None:
        """PATTERN_FINDINGS_COUNT matches singular 'finding' and 'file'."""
        m = PATTERN_FINDINGS_COUNT.match("Found 1 finding in 1 file")
        assert m is not None
        assert m.group("findings") == "1"
        assert m.group("files") == "1"

    def test_error_pattern(self) -> None:
        """PATTERN_ERROR matches 'Error: message'."""
        m = PATTERN_ERROR.match("Error: something went wrong")
        assert m is not None
        assert m.group("message") == "something went wrong"

    def test_error_pattern_with_path(self) -> None:
        """PATTERN_ERROR captures full error message including paths."""
        m = PATTERN_ERROR.match("Error: Path validation failed: /etc/passwd")
        assert m is not None
        assert m.group("message") == "Path validation failed: /etc/passwd"

    def test_patterns_are_compiled_regex(self) -> None:
        """All pattern constants are compiled regex Pattern objects."""
        assert isinstance(PATTERN_SCANNING, re.Pattern)
        assert isinstance(PATTERN_PHASE_TRANSITION, re.Pattern)
        assert isinstance(PATTERN_FINDINGS_COUNT, re.Pattern)
        assert isinstance(PATTERN_ERROR, re.Pattern)


class TestParseStderrLine:
    """Tests for the parse_stderr_line() function."""

    def test_parse_scanning_line(self) -> None:
        """Scanning line returns type='scanning' with path."""
        result = parse_stderr_line("Scanning /home/user/project...")
        assert result["type"] == "scanning"
        assert result["path"] == "/home/user/project"
        assert result["raw"] == "Scanning /home/user/project..."

    def test_parse_phase_transition(self) -> None:
        """Phase transition returns type='phase' with details."""
        result = parse_stderr_line("[1/3] Scanning...")
        assert result["type"] == "phase"
        assert result["current"] == 1
        assert result["total"] == 3
        assert result["description"] == "Scanning..."
        assert result["raw"] == "[1/3] Scanning..."

    def test_parse_phase_transition_second(self) -> None:
        """Phase 2 transition is parsed correctly."""
        result = parse_stderr_line("[2/3] Verifying up to 50 findings...")
        assert result["type"] == "phase"
        assert result["current"] == 2
        assert result["total"] == 3

    def test_parse_phase_transition_third(self) -> None:
        """Phase 3 transition is parsed correctly."""
        result = parse_stderr_line("[3/3] Generating guidance for 12 findings...")
        assert result["type"] == "phase"
        assert result["current"] == 3
        assert result["total"] == 3

    def test_parse_findings_count(self) -> None:
        """Findings count line returns type='findings' with counts."""
        result = parse_stderr_line("Found 12 findings in 34 files")
        assert result["type"] == "findings"
        assert result["findings"] == 12
        assert result["files"] == 34
        assert result["raw"] == "Found 12 findings in 34 files"

    def test_parse_findings_count_with_indent(self) -> None:
        """Indented findings count is parsed correctly."""
        result = parse_stderr_line("  Found 5 findings in 3 files")
        assert result["type"] == "findings"
        assert result["findings"] == 5
        assert result["files"] == 3

    def test_parse_error_line(self) -> None:
        """Error line returns type='error' with message."""
        result = parse_stderr_line("Error: target path does not exist")
        assert result["type"] == "error"
        assert result["message"] == "target path does not exist"
        assert result["raw"] == "Error: target path does not exist"

    def test_parse_unrecognized_line(self) -> None:
        """Unrecognized line returns type='other' with raw text."""
        result = parse_stderr_line("Some other output from dcs")
        assert result["type"] == "other"
        assert result["raw"] == "Some other output from dcs"

    def test_parse_empty_line(self) -> None:
        """Empty line returns type='other'."""
        result = parse_stderr_line("")
        assert result["type"] == "other"
        assert result["raw"] == ""

    def test_parse_suppression_line(self) -> None:
        """Suppression output is 'other' -- not a recognized pattern."""
        result = parse_stderr_line(
            "Suppressions: 3 finding(s) suppressed (2 rule(s))"
        )
        assert result["type"] == "other"

    def test_parse_scanning_no_false_positive(self) -> None:
        """Lines starting with 'Scanning' but not matching are 'other'."""
        # This doesn't end with '...' so should not match
        result = parse_stderr_line("Scanning is fun")
        assert result["type"] == "other"

    def test_parse_phase_priority(self) -> None:
        """Scanning pattern is checked before phase pattern."""
        # "Scanning /tmp/project..." matches PATTERN_SCANNING first
        result = parse_stderr_line("Scanning /tmp/project...")
        assert result["type"] == "scanning"

    def test_all_patterns_have_raw_field(self) -> None:
        """Every parsed result includes the 'raw' field."""
        lines = [
            "Scanning /path...",
            "[1/3] Scanning...",
            "Found 1 finding in 1 file",
            "Error: bad",
            "something else",
        ]
        for line in lines:
            result = parse_stderr_line(line)
            assert "raw" in result, f"Missing 'raw' for: {line}"
            assert result["raw"] == line
