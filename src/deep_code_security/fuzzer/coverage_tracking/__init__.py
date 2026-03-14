"""Coverage tracking and delta computation for fuzzing iterations."""

__all__ = ["DeltaTracker"]


def __getattr__(name: str):  # type: ignore[no-untyped-def]
    if name == "DeltaTracker":
        from deep_code_security.fuzzer.coverage_tracking.delta import DeltaTracker

        return DeltaTracker
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
