"""Language detection from file extensions."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

__all__ = ["Language", "detect_language", "EXTENSION_MAP"]


class Language(str, Enum):
    """Supported programming languages."""

    PYTHON = "python"
    GO = "go"
    C = "c"

    def __str__(self) -> str:
        return self.value


# Map from file extension to Language
EXTENSION_MAP: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".pyw": Language.PYTHON,
    ".go": Language.GO,
    ".c": Language.C,
    ".h": Language.C,
}


def detect_language(path: str | Path) -> Language | None:
    """Detect the programming language from a file path.

    Args:
        path: File path to check.

    Returns:
        Language enum value if detected, None if unknown.
    """
    suffix = Path(path).suffix.lower()
    return EXTENSION_MAP.get(suffix)


def is_supported(path: str | Path) -> bool:
    """Check if a file's language is supported for analysis.

    Args:
        path: File path to check.

    Returns:
        True if the file's language is supported.
    """
    return detect_language(path) is not None


def get_supported_extensions() -> list[str]:
    """Return all supported file extensions.

    Returns:
        Sorted list of file extensions (e.g., ['.c', '.go', '.py']).
    """
    return sorted(EXTENSION_MAP.keys())
