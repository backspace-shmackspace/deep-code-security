"""Formatter registry for output format selection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from deep_code_security.shared.formatters.protocol import Formatter

__all__ = [
    "get_formatter",
    "get_supported_formats",
    "register_formatter",
    "supports_fuzz",
]

_FORMATTERS: dict[str, type[Formatter]] = {}


def register_formatter(name: str, cls: type[Formatter]) -> None:
    """Register a formatter class by name.

    Raises ValueError if the name is already registered.
    Raises TypeError if the class lacks required methods.
    """
    if name in _FORMATTERS:
        raise ValueError(
            f"Formatter {name!r} is already registered."
        )
    # Validate that cls implements the Formatter protocol
    for method in ("format_hunt", "format_full_scan"):
        if not callable(getattr(cls, method, None)):
            raise TypeError(
                f"Formatter class {cls.__name__} must implement {method}()"
            )
    _FORMATTERS[name] = cls


def get_formatter(name: str) -> Formatter:
    """Get a formatter instance by name. Raises ValueError for unknown formats."""
    if name not in _FORMATTERS:
        raise ValueError(
            f"Unknown output format: {name!r}. "
            f"Available: {', '.join(sorted(_FORMATTERS))}"
        )
    return _FORMATTERS[name]()


def get_supported_formats() -> list[str]:
    """Return sorted list of registered format names.

    Computed dynamically from the registry to avoid stale module-level state.
    """
    return sorted(_FORMATTERS.keys())


def supports_fuzz(formatter: Any) -> bool:
    """Check whether a formatter supports fuzz/replay output.

    Uses runtime_checkable FuzzFormatter protocol to test structural compatibility.

    Args:
        formatter: A formatter instance.

    Returns:
        True if the formatter has format_fuzz() and format_replay() methods.
    """
    from deep_code_security.shared.formatters.protocol import FuzzFormatter

    return isinstance(formatter, FuzzFormatter)


def _register_builtins() -> None:
    from deep_code_security.shared.formatters.html import HtmlFormatter
    from deep_code_security.shared.formatters.json import JsonFormatter
    from deep_code_security.shared.formatters.sarif import SarifFormatter
    from deep_code_security.shared.formatters.text import TextFormatter

    register_formatter("text", TextFormatter)
    register_formatter("json", JsonFormatter)
    register_formatter("sarif", SarifFormatter)
    register_formatter("html", HtmlFormatter)


_register_builtins()
