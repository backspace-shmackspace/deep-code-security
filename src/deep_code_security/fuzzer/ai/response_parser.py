"""AI response parsing with strict target validation.

Parses Claude's JSON responses into FuzzInput objects. Strictly validates
that target_function values exactly match discovered target names.
"""

from __future__ import annotations

import json
import logging
import re

from deep_code_security.fuzzer.ai.expression_validator import validate_expression
from deep_code_security.fuzzer.exceptions import InputValidationError
from deep_code_security.fuzzer.models import FuzzInput

__all__ = ["parse_ai_response"]

logger = logging.getLogger(__name__)


def parse_ai_response(
    response_text: str,
    valid_targets: set[str],
) -> list[FuzzInput]:
    """Parse an AI response into a list of FuzzInput objects.

    Strictly validates that all target_function values exactly match one of
    the valid_targets. If ANY input has an invalid target_function, the
    ENTIRE response is rejected.
    """
    json_text = _extract_json(response_text)
    if not json_text:
        logger.warning("No JSON found in AI response")
        return []

    try:
        data = json.loads(json_text)
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse JSON from AI response: %s", e)
        return []

    if not isinstance(data, dict) or "inputs" not in data:
        logger.warning("AI response missing 'inputs' key")
        return []

    raw_inputs = data["inputs"]
    if not isinstance(raw_inputs, list):
        logger.warning("'inputs' is not a list in AI response")
        return []

    # STRICT VALIDATION: Check all target_function values before processing any
    for i, raw_input in enumerate(raw_inputs):
        if not isinstance(raw_input, dict):
            continue
        target_fn = raw_input.get("target_function", "")
        if target_fn not in valid_targets:
            raise InputValidationError(
                f"Input {i}: target_function {target_fn!r} does not match any discovered target. "
                f"Valid targets: {sorted(valid_targets)}. Rejecting entire response."
            )

    # Process each input
    fuzz_inputs: list[FuzzInput] = []
    for i, raw_input in enumerate(raw_inputs):
        if not isinstance(raw_input, dict):
            logger.warning("Input %d is not a dict, skipping", i)
            continue

        try:
            fuzz_input = _parse_single_input(raw_input, i)
            if fuzz_input is not None:
                fuzz_inputs.append(fuzz_input)
        except Exception as e:
            logger.warning("Failed to parse input %d: %s, skipping", i, e)

    return fuzz_inputs


def _parse_single_input(raw_input: dict, index: int) -> FuzzInput | None:
    """Parse a single raw input dict into a FuzzInput."""
    target_function = raw_input.get("target_function", "")
    args_raw = raw_input.get("args", [])
    kwargs_raw = raw_input.get("kwargs", {})
    rationale = raw_input.get("rationale", "")

    if not isinstance(args_raw, list):
        logger.warning("Input %d: 'args' is not a list, skipping", index)
        return None

    validated_args: list[str] = []
    for j, arg_expr in enumerate(args_raw):
        if not isinstance(arg_expr, str):
            arg_expr = repr(arg_expr)
        if not validate_expression(arg_expr):
            logger.warning(
                "Input %d arg %d: invalid expression %r, skipping input", index, j, arg_expr
            )
            return None
        validated_args.append(arg_expr)

    if not isinstance(kwargs_raw, dict):
        logger.warning("Input %d: 'kwargs' is not a dict, skipping", index)
        return None

    validated_kwargs: dict[str, str] = {}
    for key, val_expr in kwargs_raw.items():
        if not isinstance(key, str):
            logger.warning("Input %d: kwarg key is not a string, skipping input", index)
            return None
        if not isinstance(val_expr, str):
            val_expr = repr(val_expr)
        if not validate_expression(val_expr):
            logger.warning(
                "Input %d kwarg %r: invalid expression %r, skipping input",
                index,
                key,
                val_expr,
            )
            return None
        validated_kwargs[key] = val_expr

    return FuzzInput(
        target_function=target_function,
        args=tuple(validated_args),
        kwargs=validated_kwargs,
        metadata={"rationale": rationale, "source": "ai"},
    )


def _extract_json(text: str) -> str | None:
    """Extract JSON from a response that may contain markdown code blocks."""
    code_block_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if code_block_match:
        return code_block_match.group(1)

    json_match = re.search(r"\{.*\}", text, re.DOTALL)
    if json_match:
        return json_match.group(0)

    return None
