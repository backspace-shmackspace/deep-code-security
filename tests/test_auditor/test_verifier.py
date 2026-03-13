"""Tests for the exploit verifier."""

from __future__ import annotations

import pytest

from deep_code_security.auditor.exploit_generator import generate_exploit
from deep_code_security.auditor.verifier import Verifier
from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath, TaintStep


@pytest.fixture
def sql_finding() -> RawFinding:
    return RawFinding(
        source=Source(
            file="/test.py", line=5, column=0,
            function="request.form", category="web_input", language="python"
        ),
        sink=Sink(
            file="/test.py", line=10, column=0,
            function="cursor.execute", category="sql_injection",
            cwe="CWE-89", language="python"
        ),
        taint_path=TaintPath(steps=[
            TaintStep(file="/test.py", line=5, column=0, variable="user_input", transform="source"),
            TaintStep(file="/test.py", line=10, column=0, variable="user_input", transform="sink_argument"),
        ]),
        vulnerability_class="CWE-89: SQL Injection",
        severity="critical",
        language="python",
        raw_confidence=0.7,
    )


@pytest.fixture
def cmd_finding() -> RawFinding:
    return RawFinding(
        source=Source(
            file="/test.py", line=3, column=0,
            function="request.form", category="web_input", language="python"
        ),
        sink=Sink(
            file="/test.py", line=8, column=0,
            function="os.system", category="command_injection",
            cwe="CWE-78", language="python"
        ),
        taint_path=TaintPath(steps=[
            TaintStep(file="/test.py", line=3, column=0, variable="host", transform="source"),
            TaintStep(file="/test.py", line=8, column=0, variable="host", transform="sink_argument"),
        ]),
        vulnerability_class="CWE-78: OS Command Injection",
        severity="critical",
        language="python",
        raw_confidence=0.8,
    )


class TestExploitGenerator:
    """Tests for ExploitGenerator."""

    def test_generates_sql_injection_poc(self, sql_finding) -> None:
        """Generates a Python PoC for SQL injection."""
        script, script_hash = generate_exploit(sql_finding)
        assert "SQL" in script.upper() or "sql" in script.lower()
        assert len(script) > 50
        assert len(script_hash) == 64  # SHA-256 hex

    def test_generates_command_injection_poc(self, cmd_finding) -> None:
        """Generates a Python PoC for command injection."""
        script, script_hash = generate_exploit(cmd_finding)
        assert len(script) > 50
        assert len(script_hash) == 64

    def test_poc_contains_finding_metadata(self, sql_finding) -> None:
        """PoC script contains source/sink metadata from the finding."""
        script, _ = generate_exploit(sql_finding)
        # Should mention the function names
        assert "request.form" in script or "cursor.execute" in script

    def test_script_hash_is_sha256(self, sql_finding) -> None:
        """Script hash is a valid SHA-256 hex string."""
        import hashlib
        script, script_hash = generate_exploit(sql_finding)
        expected = hashlib.sha256(script.encode()).hexdigest()
        assert script_hash == expected

    def test_generates_different_scripts_per_cwe(
        self, sql_finding, cmd_finding
    ) -> None:
        """Different CWE findings produce different PoC scripts."""
        script_sql, _ = generate_exploit(sql_finding)
        script_cmd, _ = generate_exploit(cmd_finding)
        assert script_sql != script_cmd

    def test_generation_rejects_malicious_function_name(self) -> None:
        """Input validation catches malicious function names before generation."""
        from deep_code_security.mcp.input_validator import (
            InputValidationError,
            validate_raw_finding,
        )

        malicious_finding = RawFinding(
            source=Source(
                file="/test.py", line=1, column=0,
                function="os.system; rm -rf /",  # Malicious function name
                category="web_input", language="python"
            ),
            sink=Sink(
                file="/test.py", line=2, column=0,
                function="cursor.execute", category="sql_injection",
                cwe="CWE-89", language="python"
            ),
            taint_path=TaintPath(steps=[]),
            vulnerability_class="CWE-89: SQL Injection",
            severity="critical",
            language="python",
            raw_confidence=0.5,
        )
        with pytest.raises(InputValidationError, match="Invalid function name"):
            validate_raw_finding(malicious_finding)

    def test_generation_rejects_backtick_in_function_name(self) -> None:
        """Input validation rejects backticks in function names."""
        from deep_code_security.mcp.input_validator import (
            InputValidationError,
            validate_function_name,
        )

        with pytest.raises(InputValidationError):
            validate_function_name("`id`")

    def test_generation_rejects_semicolon_in_function_name(self) -> None:
        """Input validation rejects semicolons in function names."""
        from deep_code_security.mcp.input_validator import (
            InputValidationError,
            validate_function_name,
        )

        with pytest.raises(InputValidationError):
            validate_function_name("os.system; rm")


class TestVerifier:
    """Tests for Verifier."""

    def test_verify_without_sandbox(self, sql_finding, mock_sandbox) -> None:
        """Verification without sandbox uses base confidence only."""
        verifier = Verifier(sandbox=mock_sandbox)
        result = verifier.verify_finding(sql_finding, target_path="/tmp")
        assert result.finding == sql_finding
        assert result.exploit_results == []  # No sandbox, no exploit results
        assert 0 <= result.confidence_score <= 100

    def test_verify_with_sandbox_available(
        self, sql_finding, mock_sandbox_available
    ) -> None:
        """Verification with available sandbox runs the exploit."""
        verifier = Verifier(sandbox=mock_sandbox_available)
        result = verifier.verify_finding(sql_finding, target_path="/tmp")
        # Sandbox was available, so exploit was attempted
        mock_sandbox_available.run_exploit.assert_called_once()
        assert len(result.exploit_results) == 1

    def test_exploit_stored_as_hash_not_script(
        self, sql_finding, mock_sandbox_available
    ) -> None:
        """ExploitResult stores hash, not full script content."""
        verifier = Verifier(sandbox=mock_sandbox_available)
        result = verifier.verify_finding(sql_finding, target_path="/tmp")
        if result.exploit_results:
            # Hash should be hex string, not full Python script
            h = result.exploit_results[0].exploit_script_hash
            assert len(h) >= 32  # At least 32 hex chars
            assert not h.startswith("#!/")  # Not a script

    def test_failed_exploit_does_not_reduce_confidence(
        self, sql_finding, mock_sandbox_available
    ) -> None:
        """CRITICAL: A failed sandbox exploit must not reduce confidence below base."""
        # mock_sandbox_available already returns exploitable=False (non-exploitable result)
        from unittest.mock import MagicMock

        verifier_no_sandbox = Verifier(sandbox=MagicMock())
        verifier_no_sandbox.sandbox.is_available.return_value = False

        verifier_with_sandbox = Verifier(sandbox=mock_sandbox_available)

        result_no_sandbox = verifier_no_sandbox.verify_finding(sql_finding, "/tmp")
        result_with_sandbox = verifier_with_sandbox.verify_finding(sql_finding, "/tmp")

        # Failed exploit should not reduce confidence
        assert result_with_sandbox.confidence_score >= result_no_sandbox.confidence_score

    def test_verification_status_correct(self, sql_finding, mock_sandbox) -> None:
        """Verification status matches confidence score thresholds."""
        verifier = Verifier(sandbox=mock_sandbox)
        result = verifier.verify_finding(sql_finding, target_path="/tmp")
        score = result.confidence_score
        status = result.verification_status
        if score >= 75:
            assert status == "confirmed"
        elif score >= 45:
            assert status == "likely"
        elif score >= 20:
            assert status == "unconfirmed"
        else:
            assert status == "false_positive"
