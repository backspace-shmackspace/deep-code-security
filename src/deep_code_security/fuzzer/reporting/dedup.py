"""Crash deduplication for fuzzer reports."""

from __future__ import annotations

from deep_code_security.fuzzer.corpus.manager import crash_signature, parse_traceback_location
from deep_code_security.fuzzer.models import FuzzResult, UniqueCrash

__all__ = ["deduplicate_crashes"]


def _parse_exception(exception: str | None) -> tuple[str, str]:
    """Split an exception string into (type, message)."""
    if not exception:
        return ("", "")
    parts = exception.split(":", 1)
    exc_type = parts[0].strip()
    exc_msg = parts[1].strip() if len(parts) > 1 else ""
    return (exc_type, exc_msg)


def deduplicate_crashes(crashes: list[FuzzResult]) -> list[UniqueCrash]:
    """Group crashes by signature and return a list of UniqueCrash objects."""
    seen: dict[str, UniqueCrash] = {}

    for result in crashes:
        sig = crash_signature(result)
        exc_type, exc_msg = _parse_exception(result.exception)

        file_path, line_number = parse_traceback_location(result.traceback)
        if file_path != "unknown":
            location = f'File "{file_path}", line {line_number}'
        else:
            location = ""

        if sig not in seen:
            seen[sig] = UniqueCrash(
                signature=sig,
                exception_type=exc_type,
                exception_message=exc_msg,
                location=location,
                representative=result,
                count=1,
                target_functions=[result.input.target_function],
            )
        else:
            unique = seen[sig]
            unique.count += 1
            if result.input.target_function not in unique.target_functions:
                unique.target_functions.append(result.input.target_function)

    return list(seen.values())
