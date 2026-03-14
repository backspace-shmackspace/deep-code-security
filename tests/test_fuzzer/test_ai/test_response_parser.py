"""Tests for AI response parsing."""

from __future__ import annotations

import pytest

from deep_code_security.fuzzer.ai.response_parser import parse_ai_response
from deep_code_security.fuzzer.exceptions import InputValidationError


class TestParseAIResponse:
    def test_valid_response(self) -> None:
        response = '{"inputs": [{"target_function": "my_func", "args": ["42"], "kwargs": {}, "rationale": "test"}]}'
        result = parse_ai_response(response, {"my_func"})
        assert len(result) == 1
        assert result[0].target_function == "my_func"
        assert result[0].args == ("42",)

    def test_markdown_code_block(self) -> None:
        response = '```json\n{"inputs": [{"target_function": "f", "args": ["1"]}]}\n```'
        result = parse_ai_response(response, {"f"})
        assert len(result) == 1

    def test_invalid_target_rejected(self) -> None:
        response = '{"inputs": [{"target_function": "bad_func", "args": ["1"]}]}'
        with pytest.raises(InputValidationError, match="bad_func"):
            parse_ai_response(response, {"good_func"})

    def test_invalid_expression_skipped(self) -> None:
        response = '{"inputs": [{"target_function": "f", "args": ["__import__(\'os\')"]}]}'
        result = parse_ai_response(response, {"f"})
        assert len(result) == 0  # Skipped due to invalid expression

    def test_no_json(self) -> None:
        result = parse_ai_response("No JSON here", {"f"})
        assert result == []

    def test_empty_inputs(self) -> None:
        response = '{"inputs": []}'
        result = parse_ai_response(response, {"f"})
        assert result == []

    def test_non_string_args_converted(self) -> None:
        response = '{"inputs": [{"target_function": "f", "args": [42], "kwargs": {}}]}'
        result = parse_ai_response(response, {"f"})
        assert len(result) == 1
        assert result[0].args == ("42",)
