"""Tests for guidance generation."""

from __future__ import annotations

from deep_code_security.architect.guidance_generator import generate_guidance
from deep_code_security.auditor.models import VerifiedFinding
from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath, TaintStep


def make_verified_finding(cwe: str, language: str, sanitized: bool = False) -> VerifiedFinding:
    """Helper to create a VerifiedFinding for testing."""
    source = Source(
        file="/test.py", line=5, column=0,
        function="request.form", category="web_input", language=language
    )
    sink = Sink(
        file="/test.py", line=10, column=0,
        function="cursor.execute", category="sql_injection",
        cwe=cwe, language=language
    )
    taint_path = TaintPath(
        steps=[
            TaintStep(file="/test.py", line=5, column=0, variable="x", transform="source"),
            TaintStep(file="/test.py", line=10, column=0, variable="x", transform="sink_argument"),
        ],
        sanitized=sanitized,
    )
    raw = RawFinding(
        source=source,
        sink=sink,
        taint_path=taint_path,
        vulnerability_class=f"{cwe}: Test Vulnerability",
        severity="critical",
        language=language,
        raw_confidence=0.7,
    )
    return VerifiedFinding(
        finding=raw,
        exploit_results=[],
        confidence_score=70,
        verification_status="likely",
    )


class TestGuidanceGenerator:
    """Tests for generate_guidance()."""

    def test_generates_sql_injection_guidance_python(self) -> None:
        """Generates SQL injection guidance for Python."""
        vf = make_verified_finding("CWE-89", "python")
        guidance = generate_guidance(vf)
        assert guidance.finding_id == vf.finding.id
        assert "SQL" in guidance.vulnerability_explanation
        assert "parameterized" in guidance.fix_pattern.lower()
        assert len(guidance.code_example) > 50

    def test_generates_command_injection_guidance_python(self) -> None:
        """Generates command injection guidance for Python."""
        vf = make_verified_finding("CWE-78", "python")
        guidance = generate_guidance(vf)
        assert "command" in guidance.vulnerability_explanation.lower()
        assert len(guidance.code_example) > 50

    def test_generates_path_traversal_guidance_python(self) -> None:
        """Generates path traversal guidance for Python."""
        vf = make_verified_finding("CWE-22", "python")
        guidance = generate_guidance(vf)
        assert "path" in guidance.vulnerability_explanation.lower() or \
               "traversal" in guidance.vulnerability_explanation.lower()

    def test_generates_code_injection_guidance_python(self) -> None:
        """Generates code injection guidance for Python."""
        vf = make_verified_finding("CWE-94", "python")
        guidance = generate_guidance(vf)
        assert "eval" in guidance.fix_pattern.lower() or \
               "inject" in guidance.vulnerability_explanation.lower()

    def test_generates_guidance_for_go(self) -> None:
        """Generates guidance for Go findings."""
        vf = make_verified_finding("CWE-78", "go")
        guidance = generate_guidance(vf)
        assert guidance is not None
        assert len(guidance.vulnerability_explanation) > 20

    def test_guidance_has_effort_estimate(self) -> None:
        """Guidance includes effort estimate."""
        vf = make_verified_finding("CWE-89", "python")
        guidance = generate_guidance(vf)
        assert guidance.effort_estimate in ("trivial", "small", "medium", "large")

    def test_guidance_has_test_suggestions(self) -> None:
        """Guidance includes test suggestions."""
        vf = make_verified_finding("CWE-89", "python")
        guidance = generate_guidance(vf)
        assert len(guidance.test_suggestions) > 0

    def test_guidance_has_references(self) -> None:
        """Guidance includes CWE and OWASP references."""
        vf = make_verified_finding("CWE-89", "python")
        guidance = generate_guidance(vf)
        assert len(guidance.references) > 0
        assert any("cwe.mitre.org" in r or "owasp.org" in r for r in guidance.references)

    def test_guidance_no_patch_or_diff(self) -> None:
        """Guidance does not produce apply-ready patches."""
        vf = make_verified_finding("CWE-89", "python")
        guidance = generate_guidance(vf)
        # The guidance model should not have a 'patch' or 'diff' field
        guidance_dict = guidance.model_dump()
        assert "patch" not in guidance_dict
        assert "diff" not in guidance_dict

    def test_guidance_is_json_serializable(self) -> None:
        """Guidance can be serialized to JSON."""
        import json

        from deep_code_security.shared.json_output import serialize_model

        vf = make_verified_finding("CWE-89", "python")
        guidance = generate_guidance(vf)
        json_str = json.dumps(serialize_model(guidance))
        assert isinstance(json_str, str)

    def test_unknown_cwe_returns_default_guidance(self) -> None:
        """Unknown CWE returns default guidance without error."""
        vf = make_verified_finding("CWE-9999", "python")
        guidance = generate_guidance(vf)
        assert guidance is not None
        assert len(guidance.vulnerability_explanation) > 20
