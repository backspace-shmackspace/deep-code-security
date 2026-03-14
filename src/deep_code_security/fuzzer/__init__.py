"""Dynamic analysis backend: AI-powered fuzzer with coverage-guided feedback."""

__all__ = ["FuzzOrchestrator"]


def __getattr__(name: str):  # type: ignore[no-untyped-def]
    if name == "FuzzOrchestrator":
        from deep_code_security.fuzzer.orchestrator import FuzzOrchestrator

        return FuzzOrchestrator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
