"""Fuzzer plugin system for language-specific target execution."""

__all__ = ["PluginRegistry", "TargetPlugin"]


def __getattr__(name: str):  # type: ignore[no-untyped-def]
    if name == "PluginRegistry":
        from deep_code_security.fuzzer.plugins.registry import PluginRegistry

        return PluginRegistry
    if name == "TargetPlugin":
        from deep_code_security.fuzzer.plugins.base import TargetPlugin

        return TargetPlugin
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
