"""Tests that validate Semgrep rule files in registries/semgrep/.

Each parametrized test calls ``semgrep --validate --config <file>`` and asserts
exit code 0.  Tests are skipped when the ``semgrep`` binary is not available.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest
import yaml
from pathlib import Path

SEMGREP_RULES_DIR = Path(__file__).parent.parent.parent / "registries" / "semgrep"


def is_semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


skip_if_no_semgrep = pytest.mark.skipif(
    not is_semgrep_available(),
    reason="semgrep not installed",
)


@skip_if_no_semgrep
@pytest.mark.parametrize("rule_file", list(SEMGREP_RULES_DIR.rglob("*.yaml")))
def test_rule_validates(rule_file: Path) -> None:
    """Each rule file passes ``semgrep --validate``."""
    result = subprocess.run(
        ["semgrep", "--validate", "--config", str(rule_file)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"Rule validation failed for {rule_file}:\n{result.stderr}"
    )


def test_semgrep_rules_dir_exists() -> None:
    """The registries/semgrep/ directory must exist."""
    assert SEMGREP_RULES_DIR.exists(), "registries/semgrep/ directory does not exist"


def test_python_rules_exist() -> None:
    """At least 4 Python Semgrep rule files must be present."""
    python_rules = list((SEMGREP_RULES_DIR / "python").glob("*.yaml"))
    assert len(python_rules) >= 4, (
        f"Expected 4+ Python rules, found {len(python_rules)}"
    )


def test_go_rules_exist() -> None:
    """At least 3 Go Semgrep rule files must be present."""
    go_rules = list((SEMGREP_RULES_DIR / "go").glob("*.yaml"))
    assert len(go_rules) >= 3, (
        f"Expected 3+ Go rules, found {len(go_rules)}"
    )


def test_c_rules_exist() -> None:
    """At least 6 C Semgrep rule files must be present."""
    c_rules = list((SEMGREP_RULES_DIR / "c").glob("*.yaml"))
    assert len(c_rules) >= 6, (
        f"Expected 6+ C rules, found {len(c_rules)}"
    )


def test_rule_files_have_required_metadata() -> None:
    """Every rule must declare metadata.cwe and metadata.dcs_severity.

    Taint-mode rules additionally require metadata.source_function and
    metadata.sink_function.
    """
    for rule_file in SEMGREP_RULES_DIR.rglob("*.yaml"):
        with open(rule_file) as f:
            content = yaml.safe_load(f)
        for rule in content.get("rules", []):
            metadata = rule.get("metadata", {})
            assert "cwe" in metadata, f"{rule_file}: missing metadata.cwe"
            if rule.get("mode") == "taint":
                assert "source_function" in metadata, (
                    f"{rule_file}: missing metadata.source_function"
                )
                assert "sink_function" in metadata, (
                    f"{rule_file}: missing metadata.sink_function"
                )
            assert "dcs_severity" in metadata, (
                f"{rule_file}: missing metadata.dcs_severity"
            )
