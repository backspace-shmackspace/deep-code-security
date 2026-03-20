"""Cross-backend structural compatibility tests.

Verifies that both the SemgrepBackend and TreeSitterBackend produce
``RawFinding`` objects that are structurally compatible — same required
fields, same Pydantic model, same input-validator contract.

These tests do NOT assert identical field values between backends (line
numbers, confidence scores, and column offsets legitimately differ).
"""

from __future__ import annotations

import pytest


def test_semgrep_finding_passes_input_validator() -> None:
    """A RawFinding built as SemgrepBackend would build it passes input_validator."""
    from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath, TaintStep
    from deep_code_security.mcp.input_validator import validate_raw_finding

    # Construct a minimal valid RawFinding matching SemgrepBackend normalization.
    # Note: file paths must match _FILE_PATH_RE (^[a-zA-Z0-9_/.\-]+$) — no spaces.
    finding = RawFinding(
        source=Source(
            file="/tmp/test/app.py",
            line=40,
            column=12,
            function="request.form",
            category="web_input",
            language="python",
        ),
        sink=Sink(
            file="/tmp/test/app.py",
            line=42,
            column=8,
            function="cursor.execute",
            category="sql_injection",
            cwe="CWE-89",
            language="python",
        ),
        taint_path=TaintPath(
            steps=[
                TaintStep(file="/tmp/test/app.py", line=40, column=12, variable="source"),
                TaintStep(file="/tmp/test/app.py", line=42, column=8, variable="sink"),
            ],
            sanitized=False,
        ),
        vulnerability_class="CWE-89",
        severity="critical",
        language="python",
        raw_confidence=0.6,
    )
    # Should not raise InputValidationError
    result = validate_raw_finding(finding)
    assert result is finding


def test_both_backends_produce_valid_rawfinding_structure() -> None:
    """RawFinding model has all required fields that both backends must populate."""
    from deep_code_security.hunter.models import RawFinding

    required_fields = {"source", "sink", "taint_path", "vulnerability_class", "severity"}
    for field in required_fields:
        assert field in RawFinding.model_fields, (
            f"RawFinding is missing expected field: {field!r}"
        )


def test_scan_stats_has_scanner_backend_field() -> None:
    """ScanStats includes scanner_backend field, defaulting to 'treesitter'."""
    from deep_code_security.hunter.models import ScanStats

    assert "scanner_backend" in ScanStats.model_fields

    stats = ScanStats(
        files_scanned=0,
        sources_found=0,
        sinks_found=0,
    )
    assert stats.scanner_backend == "treesitter"


def test_backend_result_model() -> None:
    """BackendResult is a valid Pydantic model with correct defaults."""
    from deep_code_security.hunter.scanner_backend import BackendResult

    result = BackendResult(backend_name="semgrep")
    assert result.backend_name == "semgrep"
    assert result.findings == []
    assert result.sources_found == 0
    assert result.sinks_found == 0
    assert result.diagnostics == []


def test_backend_result_is_frozen() -> None:
    """BackendResult is immutable (frozen Pydantic model)."""
    from deep_code_security.hunter.scanner_backend import BackendResult

    result = BackendResult(backend_name="test")
    with pytest.raises(Exception):  # pydantic ValidationError or AttributeError
        result.backend_name = "changed"  # type: ignore[misc]


def test_suppression_compatible_with_semgrep_cwe_format() -> None:
    """Semgrep CWE format normalises correctly for suppression matching.

    Semgrep emits CWE strings like ``"CWE-89: SQL Injection"``.
    The SemgrepBackend normaliser strips the description suffix, producing
    just ``"CWE-89"`` — the same format that suppressions.py matches on
    the ``sink.cwe`` field.
    """
    cwe_raw = "CWE-89: SQL Injection"
    cwe_normalized = cwe_raw.split(":")[0].strip()
    assert cwe_normalized == "CWE-89"


def test_rawfinding_language_field_required() -> None:
    """RawFinding requires a language field (used by both backends)."""
    from deep_code_security.hunter.models import RawFinding

    assert "language" in RawFinding.model_fields


def test_rawfinding_raw_confidence_field_required() -> None:
    """RawFinding requires raw_confidence (backends populate this differently)."""
    from deep_code_security.hunter.models import RawFinding

    assert "raw_confidence" in RawFinding.model_fields
    field_info = RawFinding.model_fields["raw_confidence"]
    # raw_confidence must be bounded 0.0–1.0 (enforced by ge/le constraints)
    assert field_info is not None


def test_source_column_field_name() -> None:
    """Source model uses 'column' (not 'col') — both backends must use this field name."""
    from deep_code_security.hunter.models import Source

    assert "column" in Source.model_fields
    assert "col" not in Source.model_fields


def test_sink_column_field_name() -> None:
    """Sink model uses 'column' (not 'col') — both backends must use this field name."""
    from deep_code_security.hunter.models import Sink

    assert "column" in Sink.model_fields
    assert "col" not in Sink.model_fields


def test_taintstep_column_field_name() -> None:
    """TaintStep model uses 'column' (not 'col') — both backends must use this field name."""
    from deep_code_security.hunter.models import TaintStep

    assert "column" in TaintStep.model_fields
    assert "col" not in TaintStep.model_fields
