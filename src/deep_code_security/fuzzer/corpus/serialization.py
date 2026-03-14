"""Input serialization and deserialization for the corpus.

Inputs are stored as Python expression strings with schema_version: 1.
Preserves manual serialization logic (truncation, schema_version).
Does NOT use model_dump() for serialization.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from deep_code_security.fuzzer.ai.expression_validator import validate_expression
from deep_code_security.fuzzer.exceptions import CorpusError
from deep_code_security.fuzzer.models import FuzzInput, FuzzResult

__all__ = [
    "SCHEMA_VERSION",
    "deserialize_fuzz_result",
    "load_from_file",
    "save_to_file",
    "serialize_fuzz_result",
]

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


def serialize_fuzz_result(result: FuzzResult) -> dict:
    """Serialize a FuzzResult to a dict suitable for JSON storage.

    Preserves manual serialization logic: truncates stdout/stderr to 1000 chars,
    stores coverage summary instead of raw data, adds schema_version.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": time.time(),
        "input": {
            "target_function": result.input.target_function,
            "args": list(result.input.args),
            "kwargs": dict(result.input.kwargs),
            "metadata": dict(result.input.metadata),
        },
        "success": result.success,
        "exception": result.exception,
        "traceback": result.traceback,
        "duration_ms": result.duration_ms,
        "timed_out": result.timed_out,
        "coverage_summary": _summarize_coverage(result.coverage_data),
        "stdout": result.stdout[:1000] if result.stdout else "",
        "stderr": result.stderr[:1000] if result.stderr else "",
    }


def deserialize_fuzz_result(data: dict) -> FuzzResult:
    """Deserialize a stored dict into a FuzzResult.

    Expression strings are re-validated through the AST allowlist to close
    the TOCTOU gap where tampered corpus files could bypass the response
    parser's validation.
    """
    version = data.get("schema_version", 0)
    if version != SCHEMA_VERSION:
        raise CorpusError(
            f"Unsupported corpus schema version: {version}. Expected: {SCHEMA_VERSION}"
        )

    try:
        input_data = data["input"]
        args_list = input_data.get("args", [])
        kwargs_dict = input_data.get("kwargs", {})

        # Expression re-validation on corpus replay load
        for i, expr in enumerate(args_list):
            if isinstance(expr, str) and not validate_expression(expr):
                raise CorpusError(f"Corpus arg {i} failed expression validation: {expr!r}")

        for key, expr in kwargs_dict.items():
            if isinstance(expr, str) and not validate_expression(expr):
                raise CorpusError(f"Corpus kwarg {key!r} failed expression validation: {expr!r}")

        fuzz_input = FuzzInput(
            target_function=input_data["target_function"],
            args=tuple(args_list),
            kwargs=dict(kwargs_dict),
            metadata=dict(input_data.get("metadata", {})),
        )
        return FuzzResult(
            input=fuzz_input,
            success=data.get("success", False),
            exception=data.get("exception"),
            traceback=data.get("traceback"),
            duration_ms=data.get("duration_ms", 0.0),
            coverage_data=data.get("coverage_summary", {}),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            timed_out=data.get("timed_out", False),
        )
    except KeyError as e:
        raise CorpusError(f"Missing required field in corpus data: {e}") from e


def _summarize_coverage(coverage_data: dict) -> dict:
    if not coverage_data:
        return {}

    totals = coverage_data.get("totals", {})
    return {
        "percent_covered": totals.get("percent_covered", 0.0),
        "covered_lines": totals.get("covered_lines", 0),
        "num_statements": totals.get("num_statements", 0),
    }


def save_to_file(result: FuzzResult, path: Path) -> None:
    data = serialize_fuzz_result(result)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_from_file(path: Path) -> FuzzResult:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return deserialize_fuzz_result(data)
    except json.JSONDecodeError as e:
        raise CorpusError(f"Invalid JSON in corpus file {path}: {e}") from e
    except OSError as e:
        raise CorpusError(f"Cannot read corpus file {path}: {e}") from e
