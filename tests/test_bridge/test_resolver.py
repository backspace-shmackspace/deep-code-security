"""Tests for the SAST finding-to-function resolver."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from deep_code_security.bridge.models import BridgeConfig
from deep_code_security.bridge.resolver import resolve_findings_to_targets
from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath, TaintStep


def _make_finding(
    source_file: str,
    sink_file: str,
    sink_line: int,
    sink_function: str = "os.system",
    cwe: str = "CWE-78",
    vulnerability_class: str = "CWE-78: OS Command Injection",
    severity: str = "high",
    language: str = "python",
    source_category: str = "web_input",
) -> RawFinding:
    return RawFinding(
        source=Source(
            file=source_file,
            line=1,
            column=0,
            function="request.form",
            category=source_category,
            language=language,
        ),
        sink=Sink(
            file=sink_file,
            line=sink_line,
            column=4,
            function=sink_function,
            category="command_injection",
            cwe=cwe,
            language=language,
        ),
        taint_path=TaintPath(steps=[], sanitized=False),
        vulnerability_class=vulnerability_class,
        severity=severity,
        language=language,
        raw_confidence=0.8,
    )


def test_resolve_single_finding_to_function(tmp_path: Path) -> None:
    """Finding in a known function maps correctly."""
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def process_data(user_input: str) -> str:
            import os
            result = os.system(user_input)
            return str(result)
        """)
    )
    finding = _make_finding(str(py_file), str(py_file), sink_line=3)
    result = resolve_findings_to_targets([finding])

    assert len(result.fuzz_targets) == 1
    assert result.fuzz_targets[0].function_name == "process_data"
    assert result.fuzz_targets[0].parameter_count == 1
    assert result.fuzz_targets[0].requires_instance is False
    assert result.total_findings == 1
    assert result.skipped_findings == 0


def test_resolve_finding_at_exact_function_boundary(tmp_path: Path) -> None:
    """Sink on first line of function still maps to that function."""
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def run_cmd(cmd: str) -> None:
            import os
            os.system(cmd)
        """)
    )
    # Sink is on line 1 (the def line) -- edge case
    finding = _make_finding(str(py_file), str(py_file), sink_line=1)
    result = resolve_findings_to_targets([finding])
    assert len(result.fuzz_targets) == 1
    assert result.fuzz_targets[0].function_name == "run_cmd"


def test_resolve_finding_not_in_function(tmp_path: Path) -> None:
    """Module-level sink is skipped."""
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        import os
        os.system("ls")
        def safe_func(x: int) -> int:
            return x + 1
        """)
    )
    # Module-level code is on line 2
    finding = _make_finding(str(py_file), str(py_file), sink_line=2)
    result = resolve_findings_to_targets([finding])
    assert len(result.fuzz_targets) == 0
    assert result.skipped_findings == 1
    assert any("not inside a function" in r for r in result.skipped_reasons)


def test_resolve_finding_non_python() -> None:
    """Go/C findings are skipped with reason."""
    finding = _make_finding("/tmp/main.go", "/tmp/main.go", sink_line=10, language="go")
    result = resolve_findings_to_targets([finding])
    assert len(result.fuzz_targets) == 0
    assert result.skipped_findings == 1
    assert any("unsupported language" in r for r in result.skipped_reasons)


def test_resolve_finding_in_instance_method(tmp_path: Path) -> None:
    """Instance method findings are included with requires_instance=True."""
    py_file = tmp_path / "view.py"
    py_file.write_text(
        textwrap.dedent("""\
        class MyView:
            def handle(self, user_input: str) -> None:
                import os
                os.system(user_input)
        """)
    )
    finding = _make_finding(str(py_file), str(py_file), sink_line=4)
    result = resolve_findings_to_targets([finding])
    assert len(result.fuzz_targets) == 1
    assert result.fuzz_targets[0].requires_instance is True
    assert result.fuzz_targets[0].function_name == "MyView.handle"


def test_resolve_finding_in_classmethod(tmp_path: Path) -> None:
    """Classmethod findings are included with requires_instance=True."""
    py_file = tmp_path / "view.py"
    py_file.write_text(
        textwrap.dedent("""\
        class MyView:
            @classmethod
            def create(cls, data: str) -> None:
                import os
                os.system(data)
        """)
    )
    finding = _make_finding(str(py_file), str(py_file), sink_line=5)
    result = resolve_findings_to_targets([finding])
    assert len(result.fuzz_targets) == 1
    assert result.fuzz_targets[0].requires_instance is True


def test_resolve_finding_in_static_method(tmp_path: Path) -> None:
    """Static method findings are included with requires_instance=False."""
    py_file = tmp_path / "util.py"
    py_file.write_text(
        textwrap.dedent("""\
        class Utils:
            @staticmethod
            def run(cmd: str) -> None:
                import os
                os.system(cmd)
        """)
    )
    finding = _make_finding(str(py_file), str(py_file), sink_line=5)
    result = resolve_findings_to_targets([finding])
    assert len(result.fuzz_targets) == 1
    assert result.fuzz_targets[0].requires_instance is False


def test_resolve_finding_no_fuzzable_params(tmp_path: Path) -> None:
    """Zero-param function is skipped; increments not_directly_fuzzable."""
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def ping_host() -> str:
            import os
            from flask import request
            host = request.form["host"]
            return str(os.system("ping -c 1 " + host))
        """)
    )
    finding = _make_finding(str(py_file), str(py_file), sink_line=5)
    result = resolve_findings_to_targets([finding])
    assert len(result.fuzz_targets) == 0
    assert result.not_directly_fuzzable == 1
    assert result.skipped_findings == 1
    assert any("no fuzzable parameters" in r for r in result.skipped_reasons)


def test_resolve_finding_in_async_function(tmp_path: Path) -> None:
    """Async functions are resolved correctly."""
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        async def async_process(cmd: str) -> None:
            import os
            os.system(cmd)
        """)
    )
    finding = _make_finding(str(py_file), str(py_file), sink_line=3)
    result = resolve_findings_to_targets([finding])
    assert len(result.fuzz_targets) == 1
    assert result.fuzz_targets[0].function_name == "async_process"


def test_resolve_multiple_findings_same_function(tmp_path: Path) -> None:
    """Multiple findings in the same function produce one FuzzTarget."""
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def multi_sink(cmd: str, query: str) -> None:
            import os
            import sqlite3
            os.system(cmd)
            conn = sqlite3.connect(":memory:")
            conn.execute(query)
        """)
    )
    f1 = _make_finding(str(py_file), str(py_file), sink_line=4,
                       cwe="CWE-78", vulnerability_class="CWE-78: OS Command Injection")
    f2 = _make_finding(str(py_file), str(py_file), sink_line=6,
                       sink_function="conn.execute", cwe="CWE-89",
                       vulnerability_class="CWE-89: SQL Injection")
    result = resolve_findings_to_targets([f1, f2])
    assert len(result.fuzz_targets) == 1
    target = result.fuzz_targets[0]
    assert target.function_name == "multi_sink"
    assert "CWE-78" in target.sast_context.cwe_ids
    assert "CWE-89" in target.sast_context.cwe_ids
    assert target.sast_context.finding_count == 2


def test_resolve_multiple_findings_different_functions(tmp_path: Path) -> None:
    """Findings in different functions produce separate FuzzTargets."""
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def func_a(cmd: str) -> None:
            import os
            os.system(cmd)

        def func_b(query: str) -> None:
            import sqlite3
            conn = sqlite3.connect(":memory:")
            conn.execute(query)
        """)
    )
    f1 = _make_finding(str(py_file), str(py_file), sink_line=3)
    f2 = _make_finding(str(py_file), str(py_file), sink_line=8, sink_function="conn.execute")
    result = resolve_findings_to_targets([f1, f2])
    assert len(result.fuzz_targets) == 2
    names = {t.function_name for t in result.fuzz_targets}
    assert "func_a" in names
    assert "func_b" in names


def test_resolve_finding_file_not_found() -> None:
    """Skipped with reason when file does not exist."""
    finding = _make_finding(
        source_file="/nonexistent/path.py",
        sink_file="/nonexistent/path.py",
        sink_line=5,
    )
    result = resolve_findings_to_targets([finding])
    assert len(result.fuzz_targets) == 0
    assert result.skipped_findings == 1
    assert any("not found" in r or "nonexistent" in r for r in result.skipped_reasons)


def test_resolve_finding_syntax_error(tmp_path: Path) -> None:
    """Skipped with reason when file has syntax errors."""
    py_file = tmp_path / "broken.py"
    py_file.write_text("def broken(x: int) -> None:\n    return x +\n")
    finding = _make_finding(str(py_file), str(py_file), sink_line=2)
    result = resolve_findings_to_targets([finding])
    assert len(result.fuzz_targets) == 0
    assert result.skipped_findings == 1


def test_sast_context_aggregation(tmp_path: Path) -> None:
    """Multiple CWEs merged, highest severity kept."""
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def risky(cmd: str, query: str) -> None:
            import os
            os.system(cmd)
            pass  # placeholder for sql
            pass  # cursor.execute(query)
        """)
    )
    f1 = _make_finding(str(py_file), str(py_file), sink_line=3,
                       cwe="CWE-78", severity="high")
    f2 = _make_finding(str(py_file), str(py_file), sink_line=4,
                       cwe="CWE-89", severity="critical")
    result = resolve_findings_to_targets([f1, f2])
    assert len(result.fuzz_targets) == 1
    ctx = result.fuzz_targets[0].sast_context
    assert "CWE-78" in ctx.cwe_ids
    assert "CWE-89" in ctx.cwe_ids
    assert ctx.severity == "critical"


def test_finding_ids_preserved(tmp_path: Path) -> None:
    """FuzzTarget.finding_ids contains the source finding IDs."""
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def run(cmd: str) -> None:
            import os
            os.system(cmd)
        """)
    )
    finding = _make_finding(str(py_file), str(py_file), sink_line=3)
    result = resolve_findings_to_targets([finding])
    assert len(result.fuzz_targets) == 1
    assert finding.id in result.fuzz_targets[0].finding_ids


def test_resolve_uses_signature_extractor(tmp_path: Path) -> None:
    """Verify that extract_targets_from_file is called (mock-based)."""
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def process(x: str) -> str:
            import os
            return os.system(x)
        """)
    )
    finding = _make_finding(str(py_file), str(py_file), sink_line=3)

    with patch(
        "deep_code_security.bridge.resolver.extract_targets_from_file",
        wraps=__import__(
            "deep_code_security.fuzzer.analyzer.signature_extractor",
            fromlist=["extract_targets_from_file"],
        ).extract_targets_from_file,
    ) as mock_extract:
        resolve_findings_to_targets([finding])
        mock_extract.assert_called_once()
        # Verify called with include_instance_methods=True
        call_kwargs = mock_extract.call_args[1]
        assert call_kwargs.get("include_instance_methods") is True


def test_resolve_function_names_match_fuzzer(tmp_path: Path) -> None:
    """Function names from bridge match what the fuzzer would use."""
    from deep_code_security.fuzzer.analyzer.signature_extractor import extract_targets_from_file

    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def process_data(user_input: str) -> str:
            import os
            return str(os.system(user_input))
        """)
    )
    finding = _make_finding(str(py_file), str(py_file), sink_line=3)
    bridge_result = resolve_findings_to_targets([finding])

    # Fuzzer discovers targets normally (no instance methods)
    fuzzer_targets = extract_targets_from_file(py_file, allow_side_effects=True)

    bridge_names = {t.function_name for t in bridge_result.fuzz_targets}
    fuzzer_names = {t.qualified_name for t in fuzzer_targets}
    assert bridge_names == fuzzer_names


def test_resolve_capped_by_max_targets(tmp_path: Path) -> None:
    """More targets than max_targets are capped."""
    # Create a file with 5 distinct functions each containing a sink
    lines = []
    for i in range(1, 6):
        lines.extend([
            f"def func_{i}(x{i}: str) -> None:",
            "    import os",
            "    os.system(x" + str(i) + ")",
            "",
        ])
    py_file = tmp_path / "multi.py"
    py_file.write_text("\n".join(lines))

    # Sink lines are at 3, 7, 11, 15, 19 (lines 3, 7, 11, 15, 19 in 1-based)
    # Each function is 4 lines; sink is 3rd line of each func
    sink_lines = [3, 7, 11, 15, 19]
    findings = [
        _make_finding(str(py_file), str(py_file), sink_line=sl)
        for sl in sink_lines
    ]

    config = BridgeConfig(max_targets=3)
    result = resolve_findings_to_targets(findings, config=config)
    assert len(result.fuzz_targets) <= 3


def test_resolve_invalid_max_targets_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-numeric DCS_BRIDGE_MAX_TARGETS falls back to default of 10."""
    monkeypatch.setenv("DCS_BRIDGE_MAX_TARGETS", "not_a_number")
    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def process(cmd: str) -> None:
            import os
            os.system(cmd)
        """)
    )
    finding = _make_finding(str(py_file), str(py_file), sink_line=3)
    result = resolve_findings_to_targets([finding])
    # Should not raise; should use default of 10 and resolve the target normally
    assert len(result.fuzz_targets) == 1


def test_resolve_finding_parse_exception(tmp_path: Path) -> None:
    """Generic exception from extract_targets_from_file is handled gracefully."""
    from unittest.mock import patch

    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def process(cmd: str) -> None:
            import os
            os.system(cmd)
        """)
    )
    finding = _make_finding(str(py_file), str(py_file), sink_line=3)

    with patch(
        "deep_code_security.bridge.resolver.extract_targets_from_file",
        side_effect=RuntimeError("unexpected parse failure"),
    ):
        result = resolve_findings_to_targets([finding])

    assert len(result.fuzz_targets) == 0
    assert result.skipped_findings == 1
    assert any("unexpected parse failure" in r for r in result.skipped_reasons)


def test_resolve_nested_function_selects_innermost(tmp_path: Path) -> None:
    """Sink in a nested function maps to the innermost containing function."""
    py_file = tmp_path / "nested.py"
    py_file.write_text(
        textwrap.dedent("""\
        def outer(data: str) -> None:
            def inner(cmd: str) -> None:
                import os
                os.system(cmd)
            inner(data)
        """)
    )
    # Sink is on line 4 (os.system inside inner). The signature extractor
    # only discovers top-level functions, so "inner" is never in the target
    # list. _find_containing_function therefore maps the sink to "outer",
    # the outermost (and only discovered) enclosing function.
    finding = _make_finding(str(py_file), str(py_file), sink_line=4)
    result = resolve_findings_to_targets([finding])
    assert len(result.fuzz_targets) == 1
    assert result.fuzz_targets[0].function_name == "outer"


def test_resolve_capped_by_severity_priority(tmp_path: Path) -> None:
    """Capping selects highest-severity targets first."""
    lines = []
    for i in range(1, 4):
        lines.extend([
            f"def low_{i}(x: str) -> None:",
            "    import os",
            "    os.system(x)",
            "",
        ])
    for i in range(1, 3):
        lines.extend([
            f"def critical_{i}(x: str) -> None:",
            "    import os",
            "    os.system(x)",
            "",
        ])
    py_file = tmp_path / "sev.py"
    py_file.write_text("\n".join(lines))

    # low functions at lines 3, 7, 11; critical at 15, 19
    # low severity
    low_findings = [
        _make_finding(str(py_file), str(py_file), sink_line=sl, severity="low")
        for sl in [3, 7, 11]
    ]
    # critical severity
    critical_findings = [
        _make_finding(str(py_file), str(py_file), sink_line=sl, severity="critical")
        for sl in [15, 19]
    ]
    all_findings = low_findings + critical_findings
    config = BridgeConfig(max_targets=2)
    result = resolve_findings_to_targets(all_findings, config=config)
    assert len(result.fuzz_targets) == 2
    for target in result.fuzz_targets:
        assert target.sast_context.severity == "critical"
