"""Input validation for RawFinding fields before exploit template interpolation.

All fields must pass strict regex validation before being used in any template.
This prevents injection attacks via crafted finding fields.
"""

from __future__ import annotations

import re

from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath

__all__ = [
    "InputValidationError",
    "validate_crash_data",
    "validate_file_path",
    "validate_function_name",
    "validate_raw_finding",
    "validate_variable_name",
]

# Strict regex patterns for field validation
_FUNCTION_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.]*$")
_VARIABLE_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_FILE_PATH_RE = re.compile(r"^[a-zA-Z0-9_/.\-]+$")
_LANGUAGE_RE = re.compile(r"^[a-z]+$")
_SEVERITY_RE = re.compile(r"^(critical|high|medium|low)$")
_CWE_RE = re.compile(r"^CWE-\d+")

# Maximum lengths for field values
_MAX_FUNCTION_NAME_LEN = 256
_MAX_VARIABLE_NAME_LEN = 128
_MAX_FILE_PATH_LEN = 4096


class InputValidationError(Exception):
    """Raised when an input field fails validation."""


def validate_function_name(name: str) -> str:
    """Validate a function or attribute name for safe template use.

    Accepts: alphanumeric characters, underscores, and dots (for attribute access).
    Rejects: shell metacharacters, quotes, semicolons, backticks, etc.

    Args:
        name: Function name to validate.

    Returns:
        The validated name if valid.

    Raises:
        InputValidationError: If the name fails validation.
    """
    if not name:
        raise InputValidationError("Function name cannot be empty")

    if len(name) > _MAX_FUNCTION_NAME_LEN:
        raise InputValidationError(
            f"Function name too long: {len(name)} > {_MAX_FUNCTION_NAME_LEN}"
        )

    if not _FUNCTION_NAME_RE.match(name):
        raise InputValidationError(
            f"Invalid function name {name!r}: must match ^[a-zA-Z_][a-zA-Z0-9_.]*$"
        )

    return name


def validate_variable_name(name: str) -> str:
    """Validate a variable name for safe template use.

    Accepts: alphanumeric characters and underscores.
    Rejects: dots, hyphens, shell metacharacters, quotes, etc.

    Args:
        name: Variable name to validate.

    Returns:
        The validated name if valid.

    Raises:
        InputValidationError: If the name fails validation.
    """
    if not name:
        raise InputValidationError("Variable name cannot be empty")

    if len(name) > _MAX_VARIABLE_NAME_LEN:
        raise InputValidationError(
            f"Variable name too long: {len(name)} > {_MAX_VARIABLE_NAME_LEN}"
        )

    if not _VARIABLE_NAME_RE.match(name):
        raise InputValidationError(
            f"Invalid variable name {name!r}: must match ^[a-zA-Z_][a-zA-Z0-9_]*$"
        )

    return name


def validate_file_path(path: str) -> str:
    """Validate a file path for safe use in templates and commands.

    Accepts: alphanumeric characters, slashes, dots, hyphens, underscores.
    Rejects: spaces, shell metacharacters, null bytes, etc.

    Args:
        path: File path to validate.

    Returns:
        The validated path if valid.

    Raises:
        InputValidationError: If the path fails validation.
    """
    if not path:
        raise InputValidationError("File path cannot be empty")

    if len(path) > _MAX_FILE_PATH_LEN:
        raise InputValidationError(
            f"File path too long: {len(path)} > {_MAX_FILE_PATH_LEN}"
        )

    if "\x00" in path:
        raise InputValidationError("Null byte in file path")

    if not _FILE_PATH_RE.match(path):
        raise InputValidationError(
            f"Invalid file path {path!r}: must match ^[a-zA-Z0-9_/.\\-]+$"
        )

    return path


def validate_source(source: Source) -> Source:
    """Validate all fields of a Source model.

    Args:
        source: Source to validate.

    Returns:
        The source if all fields are valid.

    Raises:
        InputValidationError: If any field fails validation.
    """
    validate_function_name(source.function)
    validate_file_path(source.file)

    if not _LANGUAGE_RE.match(source.language):
        raise InputValidationError(f"Invalid language: {source.language!r}")

    return source


def validate_sink(sink: Sink) -> Sink:
    """Validate all fields of a Sink model.

    Args:
        sink: Sink to validate.

    Returns:
        The sink if all fields are valid.

    Raises:
        InputValidationError: If any field fails validation.
    """
    validate_function_name(sink.function)
    validate_file_path(sink.file)

    if not _LANGUAGE_RE.match(sink.language):
        raise InputValidationError(f"Invalid language: {sink.language!r}")

    if not _CWE_RE.match(sink.cwe):
        raise InputValidationError(f"Invalid CWE: {sink.cwe!r}")

    return sink


def validate_taint_steps(taint_path: TaintPath) -> TaintPath:
    """Validate all taint steps in a path.

    Args:
        taint_path: TaintPath to validate.

    Returns:
        The taint_path if all steps are valid.

    Raises:
        InputValidationError: If any step fails validation.
    """
    for step in taint_path.steps:
        validate_file_path(step.file)
        # Variable names in steps may be synthetic (e.g., "source") — use relaxed check
        if step.variable and len(step.variable) > _MAX_VARIABLE_NAME_LEN:
            raise InputValidationError(
                f"Variable name too long: {step.variable!r}"
            )
    return taint_path


def validate_raw_finding(finding: RawFinding) -> RawFinding:
    """Validate all fields of a RawFinding for safe template interpolation.

    This is the main entry point called before any exploit generation.
    Validates source, sink, and taint path fields against strict patterns.

    Args:
        finding: RawFinding to validate.

    Returns:
        The finding if all fields are valid.

    Raises:
        InputValidationError: If any field fails validation.
    """
    # Validate source
    try:
        validate_source(finding.source)
    except InputValidationError as e:
        raise InputValidationError(f"Invalid source field: {e}") from e

    # Validate sink
    try:
        validate_sink(finding.sink)
    except InputValidationError as e:
        raise InputValidationError(f"Invalid sink field: {e}") from e

    # Validate taint path
    try:
        validate_taint_steps(finding.taint_path)
    except InputValidationError as e:
        raise InputValidationError(f"Invalid taint path: {e}") from e

    # Validate language
    if not _LANGUAGE_RE.match(finding.language):
        raise InputValidationError(f"Invalid language: {finding.language!r}")

    # Validate severity
    if not _SEVERITY_RE.match(finding.severity):
        raise InputValidationError(f"Invalid severity: {finding.severity!r}")

    # Validate vulnerability class starts with CWE
    if not _CWE_RE.match(finding.vulnerability_class):
        raise InputValidationError(
            f"Invalid vulnerability_class: {finding.vulnerability_class!r} "
            "must start with CWE-NNN"
        )

    return finding


# ---------- Fuzz crash data validation ----------

_MAX_EXCEPTION_LEN = 2048
_MAX_TRACEBACK_LEN = 8192


def validate_crash_data(
    exception: str | None,
    traceback_str: str | None,
    target_function: str | None,
) -> dict[str, str | None]:
    """Validate fuzz crash data for safe inclusion in MCP responses.

    Sanitizes exception messages, tracebacks, and function names from
    target code execution (untrusted content).

    Args:
        exception: Exception string from crash.
        traceback_str: Traceback string from crash.
        target_function: Target function name.

    Returns:
        Dict with sanitized values.

    Raises:
        InputValidationError: If target_function fails validation.
    """
    result: dict[str, str | None] = {}

    # Truncate exception message
    if exception:
        result["exception"] = exception[:_MAX_EXCEPTION_LEN]
    else:
        result["exception"] = None

    # Truncate traceback
    if traceback_str:
        result["traceback"] = traceback_str[:_MAX_TRACEBACK_LEN]
    else:
        result["traceback"] = None

    # Validate function name
    if target_function:
        validate_function_name(target_function)
        result["target_function"] = target_function
    else:
        result["target_function"] = None

    return result
