"""Tests for AIEngine prompt/parser extensibility.

Verifies that AIEngine accepts custom system_prompt, initial_prompt_builder,
refinement_prompt_builder, sast_prompt_builder, and response_parser_fn
parameters and uses them in place of the default Python implementations.

Also verifies backward compatibility: when no overrides are provided, the
engine behaves exactly as before.
"""

from __future__ import annotations

import unittest.mock as mock
from unittest.mock import MagicMock, call, patch

import pytest

from deep_code_security.fuzzer.ai.engine import AIEngine
from deep_code_security.fuzzer.ai.prompts import (
    SYSTEM_PROMPT,
    build_initial_prompt,
    build_refinement_prompt,
    build_sast_enriched_prompt,
)
from deep_code_security.fuzzer.ai.response_parser import parse_ai_response
from deep_code_security.fuzzer.models import FuzzInput, TargetInfo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_target(name: str = "my_func") -> TargetInfo:
    return TargetInfo(
        module_path="/some/module.py",
        function_name=name,
        qualified_name=name,
        signature=f"def {name}(x: int) -> None",
        parameters=[{"name": "x", "type_hint": "int", "default": "", "kind": "POSITIONAL_OR_KEYWORD"}],
        source_code=f"def {name}(x):\n    pass\n",
    )


def _fake_fuzz_input(target: str = "my_func") -> FuzzInput:
    return FuzzInput(target_function=target, args=("0",), kwargs={})


def _make_engine_with_mock_client(**kwargs) -> tuple[AIEngine, MagicMock]:
    """Construct an AIEngine with a mocked Anthropic client.

    Returns (engine, mock_client).

    Patches the module-level ``anthropic`` variable in engine.py rather than
    trying to import the real ``anthropic`` package (which is not installed in
    the test environment).
    """
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text='{"inputs": []}')]
    mock_message.usage = MagicMock(input_tokens=100, output_tokens=50)

    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message

    # Build a fake anthropic module whose .Anthropic() returns mock_client.
    mock_anthropic_module = MagicMock()
    mock_anthropic_module.Anthropic.return_value = mock_client

    import deep_code_security.fuzzer.ai.engine as engine_mod

    with patch.object(engine_mod, "anthropic", mock_anthropic_module):
        engine = AIEngine(**kwargs)

    # Replace the internal client directly so tests can inspect calls
    engine._client = mock_client
    return engine, mock_client


# ---------------------------------------------------------------------------
# Default (backward compatible) behaviour
# ---------------------------------------------------------------------------


class TestDefaultBehaviour:
    def test_default_system_prompt_is_python_system_prompt(self) -> None:
        engine, _ = _make_engine_with_mock_client()
        assert engine._system_prompt == SYSTEM_PROMPT

    def test_default_initial_prompt_builder_is_build_initial_prompt(self) -> None:
        engine, _ = _make_engine_with_mock_client()
        assert engine._initial_prompt_builder is build_initial_prompt

    def test_default_refinement_prompt_builder(self) -> None:
        engine, _ = _make_engine_with_mock_client()
        assert engine._refinement_prompt_builder is build_refinement_prompt

    def test_default_sast_prompt_builder(self) -> None:
        engine, _ = _make_engine_with_mock_client()
        assert engine._sast_prompt_builder is build_sast_enriched_prompt

    def test_default_response_parser_fn(self) -> None:
        engine, _ = _make_engine_with_mock_client()
        assert engine._response_parser_fn is parse_ai_response

    def test_call_api_uses_system_prompt(self) -> None:
        """_call_api must pass self._system_prompt (not the module constant) to the client."""
        engine, mock_client = _make_engine_with_mock_client()
        engine._call_api("test prompt")
        _, kwargs = mock_client.messages.create.call_args
        assert kwargs.get("system") == SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Custom system_prompt
# ---------------------------------------------------------------------------


class TestCustomSystemPrompt:
    def test_custom_system_prompt_stored(self) -> None:
        custom = "You are a custom AI assistant."
        engine, _ = _make_engine_with_mock_client(system_prompt=custom)
        assert engine._system_prompt == custom

    def test_custom_system_prompt_sent_to_api(self) -> None:
        custom = "Custom security analyst prompt."
        engine, mock_client = _make_engine_with_mock_client(system_prompt=custom)
        engine._call_api("some prompt")
        _, kwargs = mock_client.messages.create.call_args
        assert kwargs.get("system") == custom

    def test_none_system_prompt_uses_default(self) -> None:
        engine, _ = _make_engine_with_mock_client(system_prompt=None)
        assert engine._system_prompt == SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Custom initial_prompt_builder
# ---------------------------------------------------------------------------


class TestCustomInitialPromptBuilder:
    def test_custom_builder_called(self) -> None:
        custom_builder = MagicMock(return_value="custom initial prompt")
        custom_parser = MagicMock(return_value=[])

        engine, mock_client = _make_engine_with_mock_client(
            initial_prompt_builder=custom_builder,
            response_parser_fn=custom_parser,
        )
        targets = [_make_target()]
        engine.generate_initial_inputs(targets, count=3)

        custom_builder.assert_called_once()
        args, kwargs = custom_builder.call_args
        # First positional arg should be targets
        assert args[0] == targets or kwargs.get("targets") == targets

    def test_custom_builder_return_value_sent_to_api(self) -> None:
        custom_prompt = "my special C prompt content"
        custom_builder = MagicMock(return_value=custom_prompt)
        custom_parser = MagicMock(return_value=[])

        engine, mock_client = _make_engine_with_mock_client(
            initial_prompt_builder=custom_builder,
            response_parser_fn=custom_parser,
        )
        engine.generate_initial_inputs([_make_target()], count=5)

        _, kwargs = mock_client.messages.create.call_args
        messages = kwargs.get("messages", [])
        assert any(m.get("content") == custom_prompt for m in messages)

    def test_default_builder_used_when_not_overridden(self) -> None:
        engine, _ = _make_engine_with_mock_client()
        assert engine._initial_prompt_builder is build_initial_prompt


# ---------------------------------------------------------------------------
# Custom refinement_prompt_builder
# ---------------------------------------------------------------------------


class TestCustomRefinementPromptBuilder:
    def test_custom_refinement_builder_called(self) -> None:
        custom_refinement_builder = MagicMock(return_value="custom refinement prompt")
        custom_parser = MagicMock(return_value=[])

        engine, mock_client = _make_engine_with_mock_client(
            refinement_prompt_builder=custom_refinement_builder,
            response_parser_fn=custom_parser,
        )
        targets = [_make_target()]
        engine.refine_inputs(
            targets=targets,
            coverage=None,
            previous_results=[],
            corpus_summary={},
            iteration=2,
            count=5,
        )

        custom_refinement_builder.assert_called_once()

    def test_custom_refinement_prompt_sent_to_api(self) -> None:
        expected_prompt = "CUSTOM REFINEMENT CONTENT"
        custom_refinement_builder = MagicMock(return_value=expected_prompt)
        custom_parser = MagicMock(return_value=[])

        engine, mock_client = _make_engine_with_mock_client(
            refinement_prompt_builder=custom_refinement_builder,
            response_parser_fn=custom_parser,
        )
        engine.refine_inputs(
            targets=[_make_target()],
            coverage=None,
            previous_results=[],
            corpus_summary={},
            iteration=1,
            count=5,
        )

        _, kwargs = mock_client.messages.create.call_args
        messages = kwargs.get("messages", [])
        assert any(m.get("content") == expected_prompt for m in messages)


# ---------------------------------------------------------------------------
# Custom response_parser_fn
# ---------------------------------------------------------------------------


class TestCustomResponseParserFn:
    def test_custom_parser_called_with_response_text(self) -> None:
        response_text = '{"inputs": []}'
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text=response_text)]
        mock_message.usage = MagicMock(input_tokens=10, output_tokens=5)

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_message

        custom_parser = MagicMock(return_value=[])

        import deep_code_security.fuzzer.ai.engine as engine_mod
        mock_anthropic_module = MagicMock()
        mock_anthropic_module.Anthropic.return_value = mock_client
        with patch.object(engine_mod, "anthropic", mock_anthropic_module):
            engine = AIEngine(response_parser_fn=custom_parser)
        engine._client = mock_client

        engine.generate_initial_inputs([_make_target()], count=3)

        custom_parser.assert_called_once()
        args, _ = custom_parser.call_args
        assert args[0] == response_text  # first arg is response_text

    def test_custom_parser_return_value_propagated(self) -> None:
        expected = [_fake_fuzz_input("my_func")]
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text="irrelevant")]
        mock_message.usage = MagicMock(input_tokens=10, output_tokens=5)

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_message

        custom_parser = MagicMock(return_value=expected)

        import deep_code_security.fuzzer.ai.engine as engine_mod
        mock_anthropic_module = MagicMock()
        mock_anthropic_module.Anthropic.return_value = mock_client
        with patch.object(engine_mod, "anthropic", mock_anthropic_module):
            engine = AIEngine(response_parser_fn=custom_parser)
        engine._client = mock_client

        result = engine.generate_initial_inputs([_make_target()], count=3)
        assert result == expected

    def test_default_parser_used_when_not_overridden(self) -> None:
        engine, _ = _make_engine_with_mock_client()
        assert engine._response_parser_fn is parse_ai_response


# ---------------------------------------------------------------------------
# Full C engine integration-style test (no real API call)
# ---------------------------------------------------------------------------


class TestCEngineIntegration:
    def test_c_engine_uses_c_system_prompt(self) -> None:
        """Simulate how FuzzOrchestrator would construct an AIEngine for C."""
        from deep_code_security.fuzzer.ai.c_prompts import (
            C_SYSTEM_PROMPT,
            build_c_initial_prompt,
            build_c_refinement_prompt,
        )
        from deep_code_security.fuzzer.ai.c_response_parser import parse_c_ai_response

        engine, mock_client = _make_engine_with_mock_client(  # noqa: E501
            system_prompt=C_SYSTEM_PROMPT,
            initial_prompt_builder=build_c_initial_prompt,
            refinement_prompt_builder=build_c_refinement_prompt,
            response_parser_fn=parse_c_ai_response,
        )

        assert engine._system_prompt == C_SYSTEM_PROMPT
        assert engine._initial_prompt_builder is build_c_initial_prompt
        assert engine._refinement_prompt_builder is build_c_refinement_prompt
        assert engine._response_parser_fn is parse_c_ai_response

        # Verify system prompt sent to API
        engine._call_api("any prompt")
        _, kwargs = mock_client.messages.create.call_args
        assert kwargs.get("system") == C_SYSTEM_PROMPT
        assert kwargs.get("system") != SYSTEM_PROMPT

    def test_c_system_prompt_different_from_python_system_prompt(self) -> None:
        from deep_code_security.fuzzer.ai.c_prompts import C_SYSTEM_PROMPT

        assert C_SYSTEM_PROMPT != SYSTEM_PROMPT

    def test_c_initial_prompt_builder_produces_c_content(self) -> None:
        from deep_code_security.fuzzer.ai.c_prompts import build_c_initial_prompt

        target = TargetInfo(
            module_path="/src/vuln.c",
            function_name="process_input",
            qualified_name="process_input",
            signature="int process_input(const char *data, size_t len)",
            parameters=[
                {"name": "data", "type_hint": "const char *", "default": "", "kind": "POSITIONAL_OR_KEYWORD"},
                {"name": "len", "type_hint": "size_t", "default": "", "kind": "POSITIONAL_OR_KEYWORD"},
            ],
            source_code="int process_input(const char *data, size_t len) { return 0; }",
        )
        prompt = build_c_initial_prompt([target], count=5)
        # Prompt should mention harness or C-specific concepts, NOT Python expression strings
        assert "harness" in prompt.lower() or "extern" in prompt.lower() or "main" in prompt.lower()
        # Should NOT reference Python expression strings
        assert "float('nan')" not in prompt

    def test_engine_with_c_parser_rejects_invalid_c_harness(self) -> None:
        """Custom parser is invoked and can raise InputValidationError."""
        import json
        from deep_code_security.fuzzer.ai.c_response_parser import parse_c_ai_response
        from deep_code_security.fuzzer.exceptions import InputValidationError

        bad_response = json.dumps({
            "inputs": [
                {
                    "target_function": "nonexistent",
                    "harness_source": "int main(void) { return 0; }",
                    "rationale": "bad target",
                }
            ]
        })

        mock_message = MagicMock()
        mock_message.content = [MagicMock(text=bad_response)]
        mock_message.usage = MagicMock(input_tokens=10, output_tokens=5)

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_message

        import deep_code_security.fuzzer.ai.engine as engine_mod
        mock_anthropic_module = MagicMock()
        mock_anthropic_module.Anthropic.return_value = mock_client
        with patch.object(engine_mod, "anthropic", mock_anthropic_module):
            engine = AIEngine(response_parser_fn=parse_c_ai_response)
        engine._client = mock_client

        # The engine retries on InputValidationError and eventually returns []
        result = engine.generate_initial_inputs(
            [TargetInfo(qualified_name="good_func", function_name="good_func")],
            count=3,
        )
        # All retries should fail gracefully
        assert result == []


# ---------------------------------------------------------------------------
# sast_prompt_builder extensibility
# ---------------------------------------------------------------------------


class TestCustomSastPromptBuilder:
    def test_custom_sast_builder_stored(self) -> None:
        custom = MagicMock(return_value="custom sast prompt")
        engine, _ = _make_engine_with_mock_client(sast_prompt_builder=custom)
        assert engine._sast_prompt_builder is custom

    def test_custom_sast_builder_called_by_generate_sast_guided_inputs(self) -> None:
        custom_sast = MagicMock(return_value="sast prompt content")
        custom_parser = MagicMock(return_value=[])

        engine, mock_client = _make_engine_with_mock_client(
            sast_prompt_builder=custom_sast,
            response_parser_fn=custom_parser,
        )
        targets = [_make_target()]
        engine.generate_sast_guided_inputs(targets, sast_contexts={}, count=5)

        custom_sast.assert_called_once()

    def test_default_sast_builder_when_not_overridden(self) -> None:
        engine, _ = _make_engine_with_mock_client()
        assert engine._sast_prompt_builder is build_sast_enriched_prompt
