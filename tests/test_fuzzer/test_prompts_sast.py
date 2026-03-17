"""Tests for SAST-enriched prompt building."""

from __future__ import annotations

from deep_code_security.bridge.models import SASTContext
from deep_code_security.fuzzer.ai.prompts import build_sast_enriched_prompt
from deep_code_security.fuzzer.models import TargetInfo


def _make_target(qualified_name: str = "process_data", params: int = 1) -> TargetInfo:
    parameters = [
        {"name": f"arg{i}", "type_hint": "str", "default": "", "kind": "POSITIONAL_OR_KEYWORD"}
        for i in range(params)
    ]
    return TargetInfo(
        module_path="/tmp/test.py",
        function_name=qualified_name,
        qualified_name=qualified_name,
        signature=f"{qualified_name}({', '.join(p['name'] for p in parameters)})",
        parameters=parameters,
        docstring="A test function.",
        source_code=f"def {qualified_name}(x):\n    import os\n    os.system(x)\n",
        complexity=2,
        is_static_method=False,
        has_side_effects=True,
    )


def _make_context(
    cwe_ids: list[str] | None = None,
    sink_functions: list[str] | None = None,
    severity: str = "high",
) -> SASTContext:
    return SASTContext(
        cwe_ids=cwe_ids or ["CWE-78"],
        vulnerability_classes=["CWE-78: OS Command Injection"],
        sink_functions=sink_functions or ["os.system"],
        source_categories=["web_input"],
        severity=severity,
        finding_count=1,
    )


def test_sast_enriched_prompt_includes_cwe() -> None:
    """Prompt contains CWE ID."""
    target = _make_target()
    ctx = _make_context(cwe_ids=["CWE-78"])
    prompt = build_sast_enriched_prompt([target], {"process_data": ctx}, count=5)
    assert "CWE-78" in prompt


def test_sast_enriched_prompt_includes_guidance() -> None:
    """Prompt contains fuzzing guidance for the CWE."""
    target = _make_target()
    ctx = _make_context(cwe_ids=["CWE-78"])
    prompt = build_sast_enriched_prompt([target], {"process_data": ctx}, count=5)
    # Guidance for CWE-78 mentions shell metacharacters
    lower = prompt.lower()
    assert "shell" in lower or "semicolon" in lower or "pipe" in lower or "cwe-78" in lower.lower()


def test_sast_enriched_prompt_includes_source_code() -> None:
    """Source code is wrapped in target_source_code delimiters."""
    target = _make_target()
    ctx = _make_context()
    prompt = build_sast_enriched_prompt([target], {"process_data": ctx}, count=5)
    assert "<target_source_code>" in prompt
    assert "</target_source_code>" in prompt
    assert "os.system" in prompt


def test_sast_enriched_prompt_context_outside_delimiters() -> None:
    """SAST context block appears outside the <target_source_code> delimiters."""
    target = _make_target()
    ctx = _make_context(cwe_ids=["CWE-78"])
    prompt = build_sast_enriched_prompt([target], {"process_data": ctx}, count=5)
    # SAST context should appear before the source code delimiter
    sast_idx = prompt.find("SAST Analysis")
    source_start_idx = prompt.find("<target_source_code>")
    assert sast_idx != -1
    assert source_start_idx != -1
    assert sast_idx < source_start_idx


def test_sast_enriched_prompt_empty_context() -> None:
    """No SAST context in dict still produces a valid prompt."""
    target = _make_target()
    prompt = build_sast_enriched_prompt([target], {}, count=5)
    assert "process_data" in prompt
    assert "<target_source_code>" in prompt
    # No SAST block without context
    assert "SAST Analysis" not in prompt


def test_sast_enriched_prompt_redact_strings() -> None:
    """String redaction still works when SAST context is present."""
    target = _make_target()
    target2 = TargetInfo(
        module_path="/tmp/test.py",
        function_name="proc",
        qualified_name="proc",
        signature="proc(x)",
        parameters=[{"name": "x", "type_hint": "str", "default": "", "kind": "POSITIONAL_OR_KEYWORD"}],
        source_code='def proc(x):\n    return "secret_value"\n',
        complexity=1,
        is_static_method=False,
        has_side_effects=False,
    )
    ctx = _make_context()
    prompt = build_sast_enriched_prompt([target2], {"proc": ctx}, count=3, redact_strings=True)
    assert "secret_value" not in prompt
    assert "<REDACTED>" in prompt


def test_sast_enriched_prompt_diversity_directive() -> None:
    """Prompt includes the diversity directive text."""
    target = _make_target()
    ctx = _make_context()
    prompt = build_sast_enriched_prompt([target], {"process_data": ctx}, count=5)
    # The diversity directive must mention generating unrelated inputs
    assert "completely unrelated" in prompt or "3 inputs" in prompt


def test_sast_enriched_prompt_multiple_targets() -> None:
    """Multiple targets all appear in the prompt."""
    t1 = _make_target("func_a")
    t2 = _make_target("func_b")
    ctx_a = _make_context(cwe_ids=["CWE-78"])
    ctx_b = _make_context(cwe_ids=["CWE-89"])
    prompt = build_sast_enriched_prompt(
        [t1, t2],
        {"func_a": ctx_a, "func_b": ctx_b},
        count=10,
    )
    assert "func_a" in prompt
    assert "func_b" in prompt
    assert "CWE-78" in prompt
    assert "CWE-89" in prompt


def test_sast_enriched_prompt_includes_sink_functions() -> None:
    """Prompt includes the dangerous sink function names."""
    target = _make_target()
    ctx = _make_context(sink_functions=["os.system", "subprocess.call"])
    prompt = build_sast_enriched_prompt([target], {"process_data": ctx}, count=5)
    assert "os.system" in prompt
    assert "subprocess.call" in prompt


def test_sast_enriched_prompt_count_in_prompt() -> None:
    """The requested count appears in the prompt."""
    target = _make_target()
    ctx = _make_context()
    prompt = build_sast_enriched_prompt([target], {"process_data": ctx}, count=7)
    assert "7" in prompt
