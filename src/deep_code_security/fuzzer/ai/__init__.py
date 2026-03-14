"""AI engine for intelligent fuzz input generation."""

__all__ = ["AIEngine"]


def __getattr__(name: str):  # type: ignore[no-untyped-def]
    if name == "AIEngine":
        from deep_code_security.fuzzer.ai.engine import AIEngine

        return AIEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
