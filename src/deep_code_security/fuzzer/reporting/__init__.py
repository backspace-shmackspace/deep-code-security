"""Crash deduplication and report data generation."""

__all__ = ["deduplicate_crashes"]


def __getattr__(name: str):  # type: ignore[no-untyped-def]
    if name == "deduplicate_crashes":
        from deep_code_security.fuzzer.reporting.dedup import deduplicate_crashes

        return deduplicate_crashes
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
