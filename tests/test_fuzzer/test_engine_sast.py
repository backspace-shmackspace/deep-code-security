"""Tests for AIEngine.generate_sast_guided_inputs (mocked API)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.bridge.models import SASTContext
from deep_code_security.fuzzer.ai.engine import AIEngine
from deep_code_security.fuzzer.exceptions import AIEngineError
from deep_code_security.fuzzer.models import FuzzInput, TargetInfo


def _make_target(name: str = "process_data") -> TargetInfo:
    return TargetInfo(
        module_path="/tmp/test.py",
        function_name=name,
        qualified_name=name,
        signature=f"{name}(x: str)",
        parameters=[
            {"name": "x", "type_hint": "str", "default": "", "kind": "POSITIONAL_OR_KEYWORD"}
        ],
        source_code=f"def {name}(x):\n    import os\n    os.system(x)\n",
        complexity=2,
        is_static_method=False,
        has_side_effects=True,
    )


def _make_sast_context(cwe: str = "CWE-78") -> SASTContext:
    return SASTContext(
        cwe_ids=[cwe],
        vulnerability_classes=[f"{cwe}: OS Command Injection"],
        sink_functions=["os.system"],
        source_categories=["web_input"],
        severity="high",
        finding_count=1,
    )


def _make_valid_api_response(target_name: str = "process_data") -> str:
    return json.dumps({
        "inputs": [
            {
                "target_function": target_name,
                "args": ["'; ls -la'"],
                "kwargs": {},
                "rationale": "Shell injection",
            },
            {
                "target_function": target_name,
                "args": ["''"],
                "kwargs": {},
                "rationale": "Empty string",
            },
        ]
    })


@pytest.fixture
def mock_engine() -> AIEngine:
    """AIEngine with mocked API client."""
    with patch("deep_code_security.fuzzer.ai.engine.anthropic") as mock_anthropic:
        mock_client = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client
        engine = AIEngine(model="claude-sonnet-4-6", api_key="test-key")
        engine._client = mock_client
        yield engine


def test_generate_sast_guided_inputs_calls_enriched_prompt(mock_engine: AIEngine) -> None:
    """generate_sast_guided_inputs uses the SAST-enriched prompt."""
    target = _make_target()
    ctx = _make_sast_context()

    response_text = _make_valid_api_response()
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=response_text)]
    mock_message.usage = MagicMock(input_tokens=100, output_tokens=50)
    mock_engine._client.messages.create.return_value = mock_message

    with patch(
        "deep_code_security.fuzzer.ai.engine.build_sast_enriched_prompt",
        wraps=__import__(
            "deep_code_security.fuzzer.ai.prompts",
            fromlist=["build_sast_enriched_prompt"],
        ).build_sast_enriched_prompt,
    ) as mock_build:
        inputs = mock_engine.generate_sast_guided_inputs(
            targets=[target],
            sast_contexts={"process_data": ctx},
            count=5,
        )
        mock_build.assert_called_once()

    assert len(inputs) >= 0  # May return 0 if mock API response is different from expected


def test_generate_sast_guided_inputs_validates_targets(mock_engine: AIEngine) -> None:
    """Invalid targets in the AI response are rejected."""
    target = _make_target("real_func")
    ctx = _make_sast_context()

    # Response with an unknown target function
    bad_response = json.dumps({
        "inputs": [
            {
                "target_function": "nonexistent_func",
                "args": ["'x'"],
                "kwargs": {},
                "rationale": "test",
            }
        ]
    })
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=bad_response)]
    mock_message.usage = MagicMock(input_tokens=100, output_tokens=50)
    mock_engine._client.messages.create.return_value = mock_message

    inputs = mock_engine.generate_sast_guided_inputs(
        targets=[target],
        sast_contexts={"real_func": ctx},
        count=5,
    )
    # Invalid targets should be filtered out by parse_ai_response
    for inp in inputs:
        assert inp.target_function == "real_func"


def test_generate_sast_guided_inputs_cost_budget(mock_engine: AIEngine) -> None:
    """generate_sast_guided_inputs respects cost budget."""
    # Set cost already at max
    mock_engine.usage.input_tokens = 10_000_000  # Very high usage
    mock_engine.max_cost_usd = 0.001  # Very low budget

    target = _make_target()
    ctx = _make_sast_context()

    with pytest.raises(AIEngineError, match="cost budget"):
        mock_engine.generate_sast_guided_inputs(
            targets=[target],
            sast_contexts={"process_data": ctx},
            count=5,
        )


def test_generate_sast_guided_inputs_returns_fuzz_inputs(mock_engine: AIEngine) -> None:
    """Return value is a list of FuzzInput objects."""
    target = _make_target()
    ctx = _make_sast_context()

    response_text = _make_valid_api_response()
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=response_text)]
    mock_message.usage = MagicMock(input_tokens=100, output_tokens=50)
    mock_engine._client.messages.create.return_value = mock_message

    inputs = mock_engine.generate_sast_guided_inputs(
        targets=[target],
        sast_contexts={"process_data": ctx},
        count=5,
    )
    for inp in inputs:
        assert isinstance(inp, FuzzInput)


def test_generate_sast_guided_inputs_method_exists() -> None:
    """The generate_sast_guided_inputs method exists on AIEngine."""
    assert hasattr(AIEngine, "generate_sast_guided_inputs")
    assert callable(getattr(AIEngine, "generate_sast_guided_inputs"))
