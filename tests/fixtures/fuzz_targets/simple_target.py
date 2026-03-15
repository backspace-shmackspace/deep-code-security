"""Simple fuzzable target for integration and unit testing.

This module provides a minimal function that the fuzzer can exercise.
It is intentionally simple and does not import any external dependencies.
"""


def parse_input(data: str) -> dict:
    """Parse a simple key=value string. Crashes on malformed input."""
    result = {}
    for part in data.split(","):
        key, _, value = part.partition("=")
        result[key.strip()] = value.strip()
    return result
