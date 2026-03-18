"""Tests for shared/suppressions.py."""

from __future__ import annotations

import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from pydantic import ValidationError

from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath
from deep_code_security.shared.suppressions import (
    SuppressionConfig,
    SuppressionLoadError,
    SuppressionResult,
    SuppressionRule,
    _glob_match,
    apply_suppressions,
    load_suppressions,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    file: str = "/project/src/app.py",
    line: int = 42,
    cwe: str = "CWE-78",
    finding_id: str | None = None,
) -> RawFinding:
    """Build a minimal RawFinding for suppression tests."""
    source = Source(
        file=file,
        line=1,
        column=0,
        function="request.form",
        category="web_input",
        language="python",
    )
    sink = Sink(
        file=file,
        line=line,
        column=0,
        function="os.system",
        category="command_injection",
        cwe=cwe,
        language="python",
    )
    kwargs: dict = {}
    if finding_id is not None:
        kwargs["id"] = finding_id
    return RawFinding(
        source=source,
        sink=sink,
        taint_path=TaintPath(steps=[], sanitized=False),
        vulnerability_class=f"{cwe}: Test Vulnerability",
        severity="high",
        language="python",
        raw_confidence=0.6,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# SuppressionRule model validation
# ---------------------------------------------------------------------------


class TestSuppressionRuleValidation:
    def test_suppression_rule_valid_rule_only(self) -> None:
        rule = SuppressionRule(rule="CWE-78", reason="Known false positive")
        assert rule.rule == "CWE-78"
        assert rule.file is None
        assert rule.lines is None
        assert rule.expires is None

    def test_suppression_rule_valid_file_only(self) -> None:
        rule = SuppressionRule(file="src/config/*.py", reason="Admin controlled")
        assert rule.file == "src/config/*.py"
        assert rule.rule is None

    def test_suppression_rule_valid_rule_and_file(self) -> None:
        rule = SuppressionRule(
            rule="CWE-22", file="src/config/*.py", reason="Admin paths"
        )
        assert rule.rule == "CWE-22"
        assert rule.file == "src/config/*.py"

    def test_suppression_rule_valid_with_lines(self) -> None:
        rule = SuppressionRule(rule="CWE-78", lines=[42, 55], reason="Hardcoded")
        assert rule.lines == [42, 55]

    def test_suppression_rule_valid_with_expires(self) -> None:
        rule = SuppressionRule(
            rule="CWE-78", reason="Temporary", expires="2099-12-31"
        )
        assert rule.expires == "2099-12-31"

    def test_suppression_rule_invalid_no_rule_no_file(self) -> None:
        with pytest.raises(ValidationError, match="At least one of"):
            SuppressionRule(reason="No matcher specified")

    def test_suppression_rule_invalid_rule_format(self) -> None:
        with pytest.raises(ValidationError, match="Invalid rule format"):
            SuppressionRule(rule="SQL Injection", reason="Bad format")

    def test_suppression_rule_invalid_lines_single(self) -> None:
        with pytest.raises(ValidationError, match="two-element list"):
            SuppressionRule(rule="CWE-78", lines=[42], reason="Single element")

    def test_suppression_rule_invalid_lines_reversed(self) -> None:
        with pytest.raises(ValidationError, match="must be <="):
            SuppressionRule(rule="CWE-78", lines=[55, 42], reason="Reversed range")

    def test_suppression_rule_invalid_lines_zero(self) -> None:
        with pytest.raises(ValidationError, match="must be >= 1"):
            SuppressionRule(rule="CWE-78", lines=[0, 10], reason="Zero start")

    def test_suppression_rule_invalid_expires_format(self) -> None:
        with pytest.raises(ValidationError, match="YYYY-MM-DD"):
            SuppressionRule(rule="CWE-78", reason="Bad date", expires="March 2026")

    def test_suppression_rule_missing_reason(self) -> None:
        with pytest.raises(ValidationError):
            SuppressionRule(rule="CWE-78")  # reason is required

    def test_suppression_rule_empty_reason(self) -> None:
        with pytest.raises(ValidationError):
            SuppressionRule(rule="CWE-78", reason="")


class TestSuppressionConfigValidation:
    def test_suppression_config_valid(self) -> None:
        config = SuppressionConfig(
            version=1,
            suppressions=[
                SuppressionRule(rule="CWE-78", reason="Known FP"),
            ],
        )
        assert config.version == 1
        assert len(config.suppressions) == 1

    def test_suppression_config_invalid_version(self) -> None:
        with pytest.raises(ValidationError, match="Only version 1"):
            SuppressionConfig(version=2, suppressions=[])

    def test_suppression_config_empty_suppressions(self) -> None:
        config = SuppressionConfig(version=1, suppressions=[])
        assert config.suppressions == []


# ---------------------------------------------------------------------------
# load_suppressions()
# ---------------------------------------------------------------------------


class TestLoadSuppressions:
    def test_load_suppressions_file_missing(self, tmp_path: Path) -> None:
        result = load_suppressions(tmp_path)
        assert result is None

    def test_load_suppressions_file_exists(self, tmp_path: Path) -> None:
        suppress_file = tmp_path / ".dcs-suppress.yaml"
        suppress_file.write_text(
            "version: 1\nsuppressons: []\n"
            "suppressions:\n"
            "  - rule: CWE-78\n"
            "    reason: Known false positive\n",
            encoding="utf-8",
        )
        config = load_suppressions(tmp_path)
        assert config is not None
        assert config.version == 1
        assert len(config.suppressions) == 1

    def test_load_suppressions_file_empty(self, tmp_path: Path) -> None:
        suppress_file = tmp_path / ".dcs-suppress.yaml"
        suppress_file.write_text("", encoding="utf-8")
        config = load_suppressions(tmp_path)
        assert config is not None
        assert config.suppressions == []

    def test_load_suppressions_file_malformed_yaml(self, tmp_path: Path) -> None:
        suppress_file = tmp_path / ".dcs-suppress.yaml"
        suppress_file.write_text(
            "version: 1\nsuppressions: [{\n  broken yaml\n", encoding="utf-8"
        )
        with pytest.raises(ValueError, match="Invalid YAML"):
            load_suppressions(tmp_path)

    def test_load_suppressions_file_wrong_type(self, tmp_path: Path) -> None:
        suppress_file = tmp_path / ".dcs-suppress.yaml"
        suppress_file.write_text("just a string\n", encoding="utf-8")
        with pytest.raises(ValueError, match="YAML mapping"):
            load_suppressions(tmp_path)

    def test_load_suppressions_uses_safe_load(self, tmp_path: Path) -> None:
        """Verify yaml.safe_load is called and yaml.load is not used directly."""
        suppress_file = tmp_path / ".dcs-suppress.yaml"
        suppress_file.write_text("version: 1\nsuppressions: []\n", encoding="utf-8")

        # Patch at the module level where yaml is imported to avoid interfering
        # with yaml's internal implementation (safe_load delegates to load internally).
        with patch(
            "deep_code_security.shared.suppressions.yaml.safe_load",
            wraps=yaml.safe_load,
        ) as mock_safe_load:
            result = load_suppressions(tmp_path)
            mock_safe_load.assert_called_once()
            assert result is not None

    def test_load_suppressions_invalid_schema(self, tmp_path: Path) -> None:
        suppress_file = tmp_path / ".dcs-suppress.yaml"
        # Missing 'version' key
        suppress_file.write_text(
            "suppressions:\n  - rule: CWE-78\n    reason: Missing version\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError):
            load_suppressions(tmp_path)

    def test_load_suppressions_file_too_large(self, tmp_path: Path) -> None:
        suppress_file = tmp_path / ".dcs-suppress.yaml"
        # Write a file exceeding 64 KB
        suppress_file.write_bytes(b"x" * (65536 + 1))
        with pytest.raises(SuppressionLoadError, match="64KB"):
            load_suppressions(tmp_path)

    def test_load_suppressions_too_many_rules(self, tmp_path: Path) -> None:
        suppress_file = tmp_path / ".dcs-suppress.yaml"
        # Build a YAML with 501 rules (just over the 500 limit)
        rules = [
            {"rule": f"CWE-{i}", "reason": f"Rule {i}"}
            for i in range(1, 502)
        ]
        content = yaml.dump({"version": 1, "suppressions": rules})
        suppress_file.write_text(content, encoding="utf-8")
        with pytest.raises(SuppressionLoadError, match="500"):
            load_suppressions(tmp_path)


# ---------------------------------------------------------------------------
# _glob_match() unit tests
# ---------------------------------------------------------------------------


class TestGlobMatch:
    def test_glob_match_single_star_no_slash(self) -> None:
        assert _glob_match(["foo.py"], ["*.py"]) is True

    def test_glob_match_single_star_blocks_slash(self) -> None:
        # src/*.py should NOT match src/sub/foo.py
        assert _glob_match(["src", "sub", "foo.py"], ["src", "*.py"]) is False

    def test_glob_match_double_star_zero(self) -> None:
        # **/*.py matches foo.py (zero directory levels)
        assert _glob_match(["foo.py"], ["**", "*.py"]) is True

    def test_glob_match_double_star_deep(self) -> None:
        # **/*.py matches a/b/c/foo.py
        assert _glob_match(["a", "b", "c", "foo.py"], ["**", "*.py"]) is True

    def test_glob_match_middle_double_star(self) -> None:
        # src/**/test.py matches src/a/b/test.py
        assert _glob_match(
            ["src", "a", "b", "test.py"], ["src", "**", "test.py"]
        ) is True

    def test_glob_match_exact(self) -> None:
        assert _glob_match(
            ["src", "config", "loader.py"], ["src", "config", "loader.py"]
        ) is True

    def test_glob_match_no_match(self) -> None:
        assert _glob_match(["src", "handlers", "api.py"], ["src", "config", "*.py"]) is False


# ---------------------------------------------------------------------------
# SuppressionRule.matches() tests
# ---------------------------------------------------------------------------


class TestSuppressionRuleMatches:
    def test_matches_rule_only(self, tmp_path: Path) -> None:
        rule = SuppressionRule(rule="CWE-78", reason="Known FP")
        finding = _make_finding(file=str(tmp_path / "src/app.py"), cwe="CWE-78")
        assert rule.matches(finding, tmp_path) is True

    def test_matches_rule_mismatch(self, tmp_path: Path) -> None:
        rule = SuppressionRule(rule="CWE-89", reason="SQL only")
        finding = _make_finding(file=str(tmp_path / "src/app.py"), cwe="CWE-78")
        assert rule.matches(finding, tmp_path) is False

    def test_matches_file_glob_single_star(self, tmp_path: Path) -> None:
        rule = SuppressionRule(file="src/config/*.py", reason="Admin controlled")
        finding = _make_finding(file=str(tmp_path / "src/config/loader.py"))
        assert rule.matches(finding, tmp_path) is True

    def test_matches_file_glob_single_star_no_cross_directory(
        self, tmp_path: Path
    ) -> None:
        rule = SuppressionRule(file="src/config/*.py", reason="Admin controlled")
        finding = _make_finding(file=str(tmp_path / "src/config/sub/loader.py"))
        assert rule.matches(finding, tmp_path) is False

    def test_matches_file_glob_recursive_zero_dirs(self, tmp_path: Path) -> None:
        # generated/**/*.py matches generated/foo.py
        rule = SuppressionRule(file="generated/**/*.py", reason="Auto-generated")
        finding = _make_finding(file=str(tmp_path / "generated/foo.py"))
        assert rule.matches(finding, tmp_path) is True

    def test_matches_file_glob_recursive_one_dir(self, tmp_path: Path) -> None:
        rule = SuppressionRule(file="generated/**/*.py", reason="Auto-generated")
        finding = _make_finding(file=str(tmp_path / "generated/a/foo.py"))
        assert rule.matches(finding, tmp_path) is True

    def test_matches_file_glob_recursive_deep(self, tmp_path: Path) -> None:
        rule = SuppressionRule(file="generated/**/*.py", reason="Auto-generated")
        finding = _make_finding(file=str(tmp_path / "generated/a/b/c/foo.py"))
        assert rule.matches(finding, tmp_path) is True

    def test_matches_file_glob_mismatch(self, tmp_path: Path) -> None:
        rule = SuppressionRule(file="src/config/*.py", reason="Config only")
        finding = _make_finding(file=str(tmp_path / "src/handlers/api.py"))
        assert rule.matches(finding, tmp_path) is False

    def test_matches_lines_within_range(self, tmp_path: Path) -> None:
        rule = SuppressionRule(rule="CWE-78", lines=[42, 55], reason="Hardcoded")
        finding = _make_finding(file=str(tmp_path / "app.py"), line=45)
        assert rule.matches(finding, tmp_path) is True

    def test_matches_lines_outside_range(self, tmp_path: Path) -> None:
        rule = SuppressionRule(rule="CWE-78", lines=[42, 55], reason="Hardcoded")
        finding = _make_finding(file=str(tmp_path / "app.py"), line=60)
        assert rule.matches(finding, tmp_path) is False

    def test_matches_lines_boundary_start(self, tmp_path: Path) -> None:
        rule = SuppressionRule(rule="CWE-78", lines=[42, 55], reason="Hardcoded")
        finding = _make_finding(file=str(tmp_path / "app.py"), line=42)
        assert rule.matches(finding, tmp_path) is True

    def test_matches_lines_boundary_end(self, tmp_path: Path) -> None:
        rule = SuppressionRule(rule="CWE-78", lines=[42, 55], reason="Hardcoded")
        finding = _make_finding(file=str(tmp_path / "app.py"), line=55)
        assert rule.matches(finding, tmp_path) is True

    def test_matches_combined_rule_and_file(self, tmp_path: Path) -> None:
        rule = SuppressionRule(
            rule="CWE-78", file="src/config/*.py", reason="Combined"
        )
        finding = _make_finding(
            file=str(tmp_path / "src/config/loader.py"), cwe="CWE-78"
        )
        assert rule.matches(finding, tmp_path) is True

    def test_matches_combined_partial_mismatch(self, tmp_path: Path) -> None:
        # Rule matches but file does not
        rule = SuppressionRule(
            rule="CWE-78", file="src/config/*.py", reason="Combined"
        )
        finding = _make_finding(
            file=str(tmp_path / "src/handlers/api.py"), cwe="CWE-78"
        )
        assert rule.matches(finding, tmp_path) is False

    def test_matches_expired_suppression(self, tmp_path: Path) -> None:
        rule = SuppressionRule(
            rule="CWE-78", reason="Expired", expires="2020-01-01"
        )
        finding = _make_finding(file=str(tmp_path / "app.py"))
        today = datetime.date(2026, 1, 1)
        assert rule.matches(finding, tmp_path, today=today) is False

    def test_matches_not_yet_expired(self, tmp_path: Path) -> None:
        rule = SuppressionRule(
            rule="CWE-78", reason="Future", expires="2099-12-31"
        )
        finding = _make_finding(file=str(tmp_path / "app.py"))
        today = datetime.date(2026, 1, 1)
        assert rule.matches(finding, tmp_path, today=today) is True

    def test_matches_expires_today(self, tmp_path: Path) -> None:
        """Expiration is inclusive -- a rule expiring today still matches."""
        today = datetime.date(2026, 6, 15)
        rule = SuppressionRule(
            rule="CWE-78", reason="Expires today", expires="2026-06-15"
        )
        finding = _make_finding(file=str(tmp_path / "app.py"))
        assert rule.matches(finding, tmp_path, today=today) is True


# ---------------------------------------------------------------------------
# apply_suppressions() tests
# ---------------------------------------------------------------------------


class TestApplySuppressions:
    def test_apply_suppressions_no_matches(self, tmp_path: Path) -> None:
        config = SuppressionConfig(
            version=1,
            suppressions=[SuppressionRule(rule="CWE-89", reason="SQL only")],
        )
        findings = [
            _make_finding(file=str(tmp_path / "app.py"), cwe="CWE-78"),
        ]
        result = apply_suppressions(findings, config, tmp_path)
        assert len(result.active_findings) == 1
        assert len(result.suppressed_findings) == 0

    def test_apply_suppressions_one_match(self, tmp_path: Path) -> None:
        config = SuppressionConfig(
            version=1,
            suppressions=[SuppressionRule(rule="CWE-78", reason="Known FP")],
        )
        findings = [
            _make_finding(
                file=str(tmp_path / "app.py"), cwe="CWE-78", finding_id="f1"
            ),
            _make_finding(
                file=str(tmp_path / "app.py"), cwe="CWE-89", finding_id="f2"
            ),
        ]
        result = apply_suppressions(findings, config, tmp_path)
        assert len(result.active_findings) == 1
        assert len(result.suppressed_findings) == 1
        assert result.suppressed_findings[0].id == "f1"
        assert result.active_findings[0].id == "f2"

    def test_apply_suppressions_all_match(self, tmp_path: Path) -> None:
        config = SuppressionConfig(
            version=1,
            suppressions=[SuppressionRule(file="*.py", reason="All suppressed")],
        )
        findings = [
            _make_finding(file=str(tmp_path / "a.py"), finding_id="f1"),
            _make_finding(file=str(tmp_path / "b.py"), finding_id="f2"),
        ]
        result = apply_suppressions(findings, config, tmp_path)
        assert len(result.active_findings) == 0
        assert len(result.suppressed_findings) == 2

    def test_apply_suppressions_records_reasons(self, tmp_path: Path) -> None:
        config = SuppressionConfig(
            version=1,
            suppressions=[SuppressionRule(rule="CWE-78", reason="Tracked reason")],
        )
        findings = [
            _make_finding(
                file=str(tmp_path / "app.py"), cwe="CWE-78", finding_id="f1"
            ),
        ]
        result = apply_suppressions(findings, config, tmp_path)
        assert "f1" in result.suppression_reasons
        assert result.suppression_reasons["f1"] == "Tracked reason"

    def test_apply_suppressions_first_rule_wins(self, tmp_path: Path) -> None:
        """When multiple rules match, the first rule's reason is recorded."""
        config = SuppressionConfig(
            version=1,
            suppressions=[
                SuppressionRule(rule="CWE-78", reason="First rule"),
                SuppressionRule(file="*.py", reason="Second rule"),
            ],
        )
        findings = [
            _make_finding(
                file=str(tmp_path / "app.py"), cwe="CWE-78", finding_id="f1"
            ),
        ]
        result = apply_suppressions(findings, config, tmp_path)
        assert result.suppression_reasons["f1"] == "First rule"

    def test_apply_suppressions_expired_rules_counted(self, tmp_path: Path) -> None:
        today = datetime.date(2026, 1, 1)
        config = SuppressionConfig(
            version=1,
            suppressions=[
                SuppressionRule(
                    rule="CWE-78", reason="Expired", expires="2020-01-01"
                ),
                SuppressionRule(rule="CWE-89", reason="Active"),
            ],
        )
        findings = [
            _make_finding(
                file=str(tmp_path / "app.py"), cwe="CWE-78", finding_id="f1"
            ),
        ]
        result = apply_suppressions(findings, config, tmp_path, today=today)
        # The expired rule does not suppress f1 (CWE-78 expired)
        # The active rule (CWE-89) does not match f1 either
        assert len(result.active_findings) == 1
        assert result.expired_rules == 1

    def test_apply_suppressions_multiple_rules(self, tmp_path: Path) -> None:
        config = SuppressionConfig(
            version=1,
            suppressions=[
                SuppressionRule(rule="CWE-78", reason="Command injection FP"),
                SuppressionRule(rule="CWE-89", reason="SQL injection FP"),
            ],
        )
        findings = [
            _make_finding(
                file=str(tmp_path / "app.py"), cwe="CWE-78", finding_id="f1"
            ),
            _make_finding(
                file=str(tmp_path / "app.py"), cwe="CWE-89", finding_id="f2"
            ),
            _make_finding(
                file=str(tmp_path / "app.py"), cwe="CWE-22", finding_id="f3"
            ),
        ]
        result = apply_suppressions(findings, config, tmp_path)
        assert len(result.suppressed_findings) == 2
        assert len(result.active_findings) == 1
        assert result.active_findings[0].id == "f3"

    def test_apply_suppressions_result_fields(self, tmp_path: Path) -> None:
        config = SuppressionConfig(
            version=1,
            suppressions=[SuppressionRule(rule="CWE-78", reason="Known FP")],
        )
        findings = [
            _make_finding(
                file=str(tmp_path / "app.py"), cwe="CWE-78", finding_id="f1"
            ),
        ]
        result = apply_suppressions(findings, config, tmp_path)
        assert result.total_rules == 1
        assert result.expired_rules == 0
        assert result.suppression_file_path.endswith(".dcs-suppress.yaml")
        assert isinstance(result, SuppressionResult)
