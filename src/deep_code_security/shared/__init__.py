"""Shared utilities for deep-code-security."""

from deep_code_security.shared.config import Config
from deep_code_security.shared.file_discovery import FileDiscovery
from deep_code_security.shared.json_output import serialize_model, serialize_models
from deep_code_security.shared.language import Language, detect_language

__all__ = [
    "Config",
    "FileDiscovery",
    "Language",
    "detect_language",
    "get_formatter",
    "get_supported_formats",
    "serialize_model",
    "serialize_models",
]


def get_formatter(name: str):  # noqa: ANN201
    """Get a formatter instance by name. Lazy import to avoid circular imports."""
    from deep_code_security.shared.formatters import get_formatter as _get_formatter

    return _get_formatter(name)


def get_supported_formats() -> list[str]:
    """Return sorted list of registered format names. Lazy import to avoid circular imports."""
    from deep_code_security.shared.formatters import (
        get_supported_formats as _get_supported_formats,
    )

    return _get_supported_formats()
