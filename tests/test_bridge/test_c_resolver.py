"""Unit tests for C language support in the SAST-to-Fuzz bridge resolver.

Tests cover:
- C findings mapped to FuzzTarget objects via the C signature extractor
- Correct CWE ID mapping for C-specific vulnerabilities
- Language / file-extension dispatch (Python vs C)
- Warning and skip behaviour when the C plugin is not in DCS_FUZZ_ALLOWED_PLUGINS
- Mixed-language finding lists (Python and C together)
- File-not-found and parse-failure error handling for .c files
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from deep_code_security.bridge.models import BridgeConfig
from deep_code_security.bridge.resolver import resolve_findings_to_targets
from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath, TaintStep


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_c_finding(
    source_file: str,
    sink_file: str,
    sink_line: int,
    sink_function: str = "memcpy",
    cwe: str = "CWE-120",
    vulnerability_class: str = "CWE-120: Buffer Copy without Checking Size of Input",
    severity: str = "high",
    source_category: str = "cli_input",
) -> RawFinding:
    """Build a RawFinding for a C file."""
    return RawFinding(
        source=Source(
            file=source_file,
            line=1,
            column=0,
            function="argv",
            category=source_category,
            language="c",
        ),
        sink=Sink(
            file=sink_file,
            line=sink_line,
            column=4,
            function=sink_function,
            category="buffer_overflow",
            cwe=cwe,
            language="c",
        ),
        taint_path=TaintPath(
            steps=[
                TaintStep(
                    file=sink_file,
                    line=1,
                    column=0,
                    variable="user_buf",
                    transform="assignment",
                )
            ],
            sanitized=False,
        ),
        vulnerability_class=vulnerability_class,
        severity=severity,
        language="c",
        raw_confidence=0.75,
    )


def _make_py_finding(
    source_file: str,
    sink_file: str,
    sink_line: int,
    sink_function: str = "os.system",
    cwe: str = "CWE-78",
    vulnerability_class: str = "CWE-78: OS Command Injection",
    severity: str = "high",
) -> RawFinding:
    """Build a RawFinding for a Python file."""
    return RawFinding(
        source=Source(
            file=source_file,
            line=1,
            column=0,
            function="request.form",
            category="web_input",
            language="python",
        ),
        sink=Sink(
            file=sink_file,
            line=sink_line,
            column=4,
            function=sink_function,
            category="command_injection",
            cwe=cwe,
            language="python",
        ),
        taint_path=TaintPath(steps=[], sanitized=False),
        vulnerability_class=vulnerability_class,
        severity=severity,
        language="python",
        raw_confidence=0.8,
    )


# ---------------------------------------------------------------------------
# Basic C resolution
# ---------------------------------------------------------------------------


def test_c_finding_resolves_to_fuzz_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A C finding in a discoverable function maps to a FuzzTarget."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    c_file = tmp_path / "target.c"
    c_file.write_text(
        textwrap.dedent("""\
        #include <string.h>
        int process_buffer(const char *data, int len) {
            char buf[64];
            memcpy(buf, data, len);
            return 0;
        }
        """)
    )

    finding = _make_c_finding(str(c_file), str(c_file), sink_line=4)
    result = resolve_findings_to_targets([finding])

    assert len(result.fuzz_targets) == 1
    target = result.fuzz_targets[0]
    assert target.function_name == "process_buffer"
    assert target.file_path == str(c_file)
    assert target.parameter_count >= 1
    assert result.total_findings == 1
    assert result.skipped_findings == 0


def test_c_finding_cwe_preserved_in_sast_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CWE IDs from C findings are carried through to the FuzzTarget's SASTContext."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    c_file = tmp_path / "vuln.c"
    c_file.write_text(
        textwrap.dedent("""\
        #include <stdio.h>
        void log_message(const char *msg) {
            printf(msg);
        }
        """)
    )

    finding = _make_c_finding(
        str(c_file),
        str(c_file),
        sink_line=3,
        sink_function="printf",
        cwe="CWE-134",
        vulnerability_class="CWE-134: Use of Externally-Controlled Format String",
    )
    result = resolve_findings_to_targets([finding])

    assert len(result.fuzz_targets) == 1
    ctx = result.fuzz_targets[0].sast_context
    assert "CWE-134" in ctx.cwe_ids
    assert any("Format String" in vc for vc in ctx.vulnerability_classes)


@pytest.mark.parametrize(
    "cwe",
    ["CWE-119", "CWE-120", "CWE-134", "CWE-190", "CWE-676"],
)
def test_c_cwe_ids_resolve_correctly(
    cwe: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each C-specific CWE is preserved faithfully in the resolved FuzzTarget."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    c_file = tmp_path / f"vuln_{cwe.replace('-', '_')}.c"
    c_file.write_text(
        textwrap.dedent("""\
        #include <string.h>
        int fuzz_me(const char *input, int len) {
            char buf[32];
            memcpy(buf, input, len);
            return 0;
        }
        """)
    )

    finding = _make_c_finding(
        str(c_file), str(c_file), sink_line=4, cwe=cwe,
        vulnerability_class=f"{cwe}: Some Vulnerability",
    )
    result = resolve_findings_to_targets([finding])

    assert len(result.fuzz_targets) == 1
    assert cwe in result.fuzz_targets[0].sast_context.cwe_ids


# ---------------------------------------------------------------------------
# Language / file-extension dispatch
# ---------------------------------------------------------------------------


def test_python_finding_still_resolves_with_c_enabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Python findings continue to work when the C plugin is also enabled."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def run_cmd(cmd: str) -> None:
            import os
            os.system(cmd)
        """)
    )

    finding = _make_py_finding(str(py_file), str(py_file), sink_line=3)
    result = resolve_findings_to_targets([finding])

    assert len(result.fuzz_targets) == 1
    assert result.fuzz_targets[0].function_name == "run_cmd"
    assert result.skipped_findings == 0


def test_mixed_python_and_c_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Python and C findings in the same call each produce a FuzzTarget."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def run_cmd(cmd: str) -> None:
            import os
            os.system(cmd)
        """)
    )
    c_file = tmp_path / "target.c"
    c_file.write_text(
        textwrap.dedent("""\
        #include <string.h>
        int copy_data(const char *src, int n) {
            char buf[64];
            memcpy(buf, src, n);
            return 0;
        }
        """)
    )

    py_finding = _make_py_finding(str(py_file), str(py_file), sink_line=3)
    c_finding = _make_c_finding(str(c_file), str(c_file), sink_line=4)
    result = resolve_findings_to_targets([py_finding, c_finding])

    assert result.total_findings == 2
    assert len(result.fuzz_targets) == 2
    file_paths = {t.file_path for t in result.fuzz_targets}
    assert str(py_file) in file_paths
    assert str(c_file) in file_paths


def test_go_finding_still_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Go findings remain unsupported and are skipped with a reason."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    finding = _make_py_finding(
        "/tmp/main.go", "/tmp/main.go", sink_line=10,
    )
    # Override language to go
    go_finding = RawFinding(
        source=Source(
            file="/tmp/main.go", line=1, column=0,
            function="r.FormValue", category="web_input", language="go",
        ),
        sink=Sink(
            file="/tmp/main.go", line=10, column=4,
            function="exec.Command", category="command_injection",
            cwe="CWE-78", language="go",
        ),
        taint_path=TaintPath(steps=[], sanitized=False),
        vulnerability_class="CWE-78: OS Command Injection",
        severity="high",
        language="go",
        raw_confidence=0.8,
    )

    result = resolve_findings_to_targets([go_finding])
    assert len(result.fuzz_targets) == 0
    assert result.skipped_findings == 1
    assert any("unsupported language" in r for r in result.skipped_reasons)


def test_c_file_extension_dispatch_overrides_language_field(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A finding with a .c sink file is dispatched to the C extractor
    even if the language field claims something unexpected."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    c_file = tmp_path / "odd.c"
    c_file.write_text(
        textwrap.dedent("""\
        #include <string.h>
        int parse_input(const char *data, int len) {
            char buf[64];
            memcpy(buf, data, len);
            return 0;
        }
        """)
    )

    # Construct a finding that has language="c" but the sink file is a .c file.
    finding = _make_c_finding(str(c_file), str(c_file), sink_line=4)
    result = resolve_findings_to_targets([finding])

    assert len(result.fuzz_targets) == 1
    assert result.fuzz_targets[0].file_path == str(c_file)


# ---------------------------------------------------------------------------
# Plugin allowlist enforcement
# ---------------------------------------------------------------------------


def test_c_finding_skipped_when_c_plugin_not_allowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C findings are skipped with a diagnostic reason when DCS_FUZZ_ALLOWED_PLUGINS
    does not include 'c'."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python")

    c_file = tmp_path / "target.c"
    c_file.write_text(
        textwrap.dedent("""\
        int fuzz_me(const char *data, int len) {
            char buf[64];
            return 0;
        }
        """)
    )

    finding = _make_c_finding(str(c_file), str(c_file), sink_line=3)
    result = resolve_findings_to_targets([finding])

    assert len(result.fuzz_targets) == 0
    assert result.skipped_findings == 1
    assert any("C plugin not enabled" in r for r in result.skipped_reasons)


def test_c_finding_skipped_when_allowed_plugins_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C findings are skipped when DCS_FUZZ_ALLOWED_PLUGINS is set to an empty value."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "")

    c_file = tmp_path / "target.c"
    c_file.write_text(
        textwrap.dedent("""\
        int fuzz_me(const char *data, int len) {
            char buf[64];
            return 0;
        }
        """)
    )

    finding = _make_c_finding(str(c_file), str(c_file), sink_line=3)
    result = resolve_findings_to_targets([finding])

    assert len(result.fuzz_targets) == 0
    assert result.skipped_findings == 1


def test_c_plugin_only_allowlist_skips_python(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When only 'c' is in the allowlist, Python findings are still processed
    (Python is always handled regardless of the allowlist — the allowlist only
    gates the C extractor)."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "c")

    py_file = tmp_path / "app.py"
    py_file.write_text(
        textwrap.dedent("""\
        def run(cmd: str) -> None:
            import os
            os.system(cmd)
        """)
    )

    finding = _make_py_finding(str(py_file), str(py_file), sink_line=3)
    result = resolve_findings_to_targets([finding])

    # Python is always dispatched by file extension, not gated by allowlist.
    assert len(result.fuzz_targets) == 1


# ---------------------------------------------------------------------------
# C extractor dispatch via mock
# ---------------------------------------------------------------------------


def test_c_extractor_called_for_dot_c_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that _extract_c_targets is called for .c sink files."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    c_file = tmp_path / "target.c"
    c_file.write_text(
        textwrap.dedent("""\
        int process(const char *data, int len) {
            char buf[64];
            return 0;
        }
        """)
    )

    finding = _make_c_finding(str(c_file), str(c_file), sink_line=3)

    with patch(
        "deep_code_security.bridge.resolver._extract_c_targets",
        wraps=__import__(
            "deep_code_security.bridge.resolver",
            fromlist=["_extract_c_targets"],
        )._extract_c_targets,
    ) as mock_c:
        resolve_findings_to_targets([finding])
        mock_c.assert_called_once_with(c_file)


def test_python_extractor_not_called_for_dot_c_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that extract_targets_from_file is NOT called for .c sink files."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    c_file = tmp_path / "target.c"
    c_file.write_text(
        textwrap.dedent("""\
        int process(const char *data, int len) {
            char buf[64];
            return 0;
        }
        """)
    )

    finding = _make_c_finding(str(c_file), str(c_file), sink_line=3)

    with patch(
        "deep_code_security.bridge.resolver.extract_targets_from_file",
    ) as mock_py:
        resolve_findings_to_targets([finding])
        mock_py.assert_not_called()


# ---------------------------------------------------------------------------
# Error handling for .c files
# ---------------------------------------------------------------------------


def test_c_file_not_found_skipped_with_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing .c file produces a skipped finding with a diagnostic reason."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    finding = _make_c_finding(
        "/nonexistent/target.c",
        "/nonexistent/target.c",
        sink_line=5,
    )
    result = resolve_findings_to_targets([finding])

    assert len(result.fuzz_targets) == 0
    assert result.skipped_findings == 1
    assert any("not found" in r for r in result.skipped_reasons)


def test_c_extractor_exception_skipped_gracefully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A RuntimeError from the C extractor is caught and the finding is skipped."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    c_file = tmp_path / "target.c"
    c_file.write_text("int f(const char *x) { return 0; }\n")

    finding = _make_c_finding(str(c_file), str(c_file), sink_line=1)

    with patch(
        "deep_code_security.bridge.resolver._extract_c_targets",
        side_effect=RuntimeError("unexpected C parse failure"),
    ):
        result = resolve_findings_to_targets([finding])

    assert len(result.fuzz_targets) == 0
    assert result.skipped_findings == 1
    assert any("unexpected C parse failure" in r for r in result.skipped_reasons)


def test_c_finding_sink_not_in_any_function(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sink line that falls outside all discovered C functions is skipped."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    c_file = tmp_path / "target.c"
    # Write a file where line 1 is a global variable declaration, not inside a function.
    c_file.write_text(
        textwrap.dedent("""\
        int global_var = 0;
        int process(const char *data, int len) {
            char buf[64];
            return 0;
        }
        """)
    )

    # Sink is on line 1 (the global variable), which no function contains.
    finding = _make_c_finding(str(c_file), str(c_file), sink_line=1)
    result = resolve_findings_to_targets([finding])

    assert len(result.fuzz_targets) == 0
    assert result.skipped_findings == 1
    assert any("not inside a function" in r for r in result.skipped_reasons)


def test_c_function_with_empty_param_list_skipped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A C function with an empty () parameter list (no void, no args) is excluded
    by the C extractor and its sink is skipped as 'not inside a function'."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    # Use an empty () which tree-sitter sees as zero parameters -- different from
    # (void) which it parses as one void-typed parameter.
    c_file = tmp_path / "target.c"
    c_file.write_text(
        textwrap.dedent("""\
        int global_sink = 0;
        void truly_no_params() {
            global_sink = 1;
        }
        """)
    )

    # The C extractor excludes functions with an empty parameter list.
    # The sink line (3) is inside truly_no_params(), but that function is excluded
    # by the extractor, so _find_containing_function returns None and the finding
    # is skipped as "not inside a function".
    finding = _make_c_finding(str(c_file), str(c_file), sink_line=3)
    result = resolve_findings_to_targets([finding])

    # truly_no_params() has no parameters -- C extractor skips it.
    # Either: (a) skipped as "not inside a function" (extractor excluded it), or
    # (b) skipped as "no fuzzable parameters" (if extractor includes it with params=[]).
    assert len(result.fuzz_targets) == 0
    assert result.skipped_findings == 1


# ---------------------------------------------------------------------------
# Multiple C findings
# ---------------------------------------------------------------------------


def test_multiple_c_findings_same_function_merged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple C findings in the same function produce exactly one FuzzTarget."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    c_file = tmp_path / "target.c"
    c_file.write_text(
        textwrap.dedent("""\
        #include <stdio.h>
        #include <string.h>
        int multi_vuln(const char *data, int len) {
            char buf[64];
            memcpy(buf, data, len);
            printf(data);
            return 0;
        }
        """)
    )

    f1 = _make_c_finding(
        str(c_file), str(c_file), sink_line=5,
        sink_function="memcpy", cwe="CWE-120",
    )
    f2 = _make_c_finding(
        str(c_file), str(c_file), sink_line=6,
        sink_function="printf", cwe="CWE-134",
        vulnerability_class="CWE-134: Use of Externally-Controlled Format String",
    )

    result = resolve_findings_to_targets([f1, f2])

    assert len(result.fuzz_targets) == 1
    target = result.fuzz_targets[0]
    assert target.function_name == "multi_vuln"
    assert "CWE-120" in target.sast_context.cwe_ids
    assert "CWE-134" in target.sast_context.cwe_ids
    assert target.sast_context.finding_count == 2


def test_multiple_c_findings_different_functions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C findings in different functions produce separate FuzzTargets."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    c_file = tmp_path / "target.c"
    c_file.write_text(
        textwrap.dedent("""\
        #include <string.h>
        int func_a(const char *src, int n) {
            char buf[64];
            memcpy(buf, src, n);
            return 0;
        }
        int func_b(const char *fmt) {
            char buf[32];
            memcpy(buf, fmt, 10);
            return 0;
        }
        """)
    )

    f1 = _make_c_finding(str(c_file), str(c_file), sink_line=4)
    f2 = _make_c_finding(str(c_file), str(c_file), sink_line=9)
    result = resolve_findings_to_targets([f1, f2])

    assert len(result.fuzz_targets) == 2
    names = {t.function_name for t in result.fuzz_targets}
    assert "func_a" in names
    assert "func_b" in names


# ---------------------------------------------------------------------------
# Severity and capping
# ---------------------------------------------------------------------------


def test_c_targets_severity_aggregation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Highest severity among C findings for a function is propagated."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    c_file = tmp_path / "target.c"
    c_file.write_text(
        textwrap.dedent("""\
        #include <string.h>
        int risky(const char *data, int len) {
            char buf[64];
            memcpy(buf, data, len);
            memcpy(buf, data, len);
            return 0;
        }
        """)
    )

    f1 = _make_c_finding(str(c_file), str(c_file), sink_line=4, severity="medium")
    f2 = _make_c_finding(str(c_file), str(c_file), sink_line=5, severity="critical")
    result = resolve_findings_to_targets([f1, f2])

    assert len(result.fuzz_targets) == 1
    assert result.fuzz_targets[0].sast_context.severity == "critical"


def test_c_targets_capped_by_max_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C targets are capped when the total exceeds max_targets."""
    monkeypatch.setenv("DCS_FUZZ_ALLOWED_PLUGINS", "python,c")

    # Write a C file with 4 distinct fuzzable functions.
    lines = ["#include <string.h>"]
    for i in range(1, 5):
        lines += [
            f"int func_{i}(const char *data, int len) {{",
            "    char buf[64];",
            "    memcpy(buf, data, len);",
            "    return 0;",
            "}",
            "",
        ]
    c_file = tmp_path / "multi.c"
    c_file.write_text("\n".join(lines))

    # Sink lines: line 3 of each func block (1-indexed, after the #include line).
    # func_1 starts at line 2, memcpy at line 4
    # func_2 starts at line 7, memcpy at line 9
    # func_3 starts at line 12, memcpy at line 14
    # func_4 starts at line 17, memcpy at line 19
    sink_lines = [4, 9, 14, 19]
    findings = [
        _make_c_finding(str(c_file), str(c_file), sink_line=sl)
        for sl in sink_lines
    ]

    config = BridgeConfig(max_targets=2)
    result = resolve_findings_to_targets(findings, config=config)
    assert len(result.fuzz_targets) <= 2


# ---------------------------------------------------------------------------
# Config field: fuzz_c_container_image
# ---------------------------------------------------------------------------


def test_config_fuzz_c_container_image_default() -> None:
    """Config.fuzz_c_container_image defaults to 'dcs-fuzz-c:latest'."""
    from deep_code_security.shared.config import Config

    cfg = Config()
    assert cfg.fuzz_c_container_image == "dcs-fuzz-c:latest"


def test_config_fuzz_c_container_image_env_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DCS_FUZZ_C_CONTAINER_IMAGE overrides the default image name."""
    monkeypatch.setenv("DCS_FUZZ_C_CONTAINER_IMAGE", "my-custom-c-fuzzer:v2")
    from deep_code_security.shared.config import Config

    cfg = Config()
    assert cfg.fuzz_c_container_image == "my-custom-c-fuzzer:v2"
