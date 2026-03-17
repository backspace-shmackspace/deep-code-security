"""Tests for the CWE-to-fuzzing guidance map."""

from __future__ import annotations

from deep_code_security.bridge.cwe_guidance import CWE_FUZZ_GUIDANCE, get_guidance_for_cwes


def test_known_cwe_returns_guidance() -> None:
    """CWE-78 returns shell metacharacter guidance."""
    guidance = get_guidance_for_cwes(["CWE-78"])
    assert "CWE-78" in guidance
    assert len(guidance) > 0
    # Should mention shell metacharacters
    lower = guidance.lower()
    assert "shell" in lower or "semicolon" in lower or "pipe" in lower


def test_unknown_cwe_returns_empty() -> None:
    """CWE-999 (unknown) returns empty string."""
    guidance = get_guidance_for_cwes(["CWE-999"])
    assert guidance == ""


def test_multiple_cwes() -> None:
    """Returns combined guidance for multiple CWEs."""
    guidance = get_guidance_for_cwes(["CWE-78", "CWE-89"])
    assert "CWE-78" in guidance
    assert "CWE-89" in guidance


def test_empty_cwe_list() -> None:
    """Empty list returns empty string."""
    guidance = get_guidance_for_cwes([])
    assert guidance == ""


def test_all_registered_cwes_have_nonempty_guidance() -> None:
    """Sanity check: every registered CWE has non-empty guidance."""
    for cwe, guidance_str in CWE_FUZZ_GUIDANCE.items():
        assert guidance_str, f"CWE {cwe} has empty guidance"
        assert len(guidance_str) > 10, f"CWE {cwe} has suspiciously short guidance"


def test_cwe_22_path_traversal() -> None:
    """CWE-22 returns path traversal guidance."""
    guidance = get_guidance_for_cwes(["CWE-22"])
    assert "CWE-22" in guidance
    assert "path traversal" in guidance.lower() or "../" in guidance


def test_cwe_94_code_injection() -> None:
    """CWE-94 returns code injection guidance."""
    guidance = get_guidance_for_cwes(["CWE-94"])
    assert "CWE-94" in guidance


def test_cwe_79_xss() -> None:
    """CWE-79 returns XSS guidance."""
    guidance = get_guidance_for_cwes(["CWE-79"])
    assert "CWE-79" in guidance
    assert "script" in guidance.lower() or "html" in guidance.lower()


def test_duplicate_cwes_deduplicated() -> None:
    """Duplicate CWE IDs produce only one guidance entry."""
    guidance_once = get_guidance_for_cwes(["CWE-78"])
    guidance_twice = get_guidance_for_cwes(["CWE-78", "CWE-78"])
    assert guidance_once == guidance_twice


def test_mixed_known_unknown() -> None:
    """Mix of known and unknown CWEs returns only known entries."""
    guidance = get_guidance_for_cwes(["CWE-78", "CWE-9999", "CWE-89"])
    assert "CWE-78" in guidance
    assert "CWE-89" in guidance
    assert "CWE-9999" not in guidance
