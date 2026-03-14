"""Exception hierarchy for the fuzzer phase.

All custom exceptions inherit from FuzzerError.
"""

__all__ = [
    "AIEngineError",
    "CircuitBreakerError",
    "ConsentRequiredError",
    "CorpusError",
    "CoverageError",
    "ExecutionError",
    "FuzzerError",
    "InputValidationError",
    "PluginError",
]


class FuzzerError(Exception):
    """Base exception for all fuzzer errors."""


class PluginError(FuzzerError):
    """Error in plugin discovery, loading, or execution."""


class ExecutionError(FuzzerError):
    """Error during fuzz target execution."""


class AIEngineError(FuzzerError):
    """Error in AI engine (API calls, response parsing)."""


class CoverageError(FuzzerError):
    """Error in coverage collection or processing."""


class CorpusError(FuzzerError):
    """Error in corpus management (storage, retrieval, serialization)."""


class InputValidationError(FuzzerError):
    """AI-generated input failed validation (e.g., target function mismatch)."""


class ConsentRequiredError(FuzzerError):
    """User has not consented to source code transmission to the Anthropic API."""


class CircuitBreakerError(AIEngineError):
    """Too many consecutive API failures; run aborted."""
