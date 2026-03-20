"""Execution isolation and sandboxed subprocess management."""

__all__ = ["CContainerBackend", "CFuzzRunner", "FuzzRunner", "SandboxManager"]


def __getattr__(name: str):  # type: ignore[no-untyped-def]
    if name == "FuzzRunner":
        from deep_code_security.fuzzer.execution.runner import FuzzRunner

        return FuzzRunner
    if name == "CFuzzRunner":
        from deep_code_security.fuzzer.execution.c_runner import CFuzzRunner

        return CFuzzRunner
    if name == "SandboxManager":
        from deep_code_security.fuzzer.execution.sandbox import SandboxManager

        return SandboxManager
    if name == "CContainerBackend":
        from deep_code_security.fuzzer.execution.sandbox import CContainerBackend

        return CContainerBackend
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
