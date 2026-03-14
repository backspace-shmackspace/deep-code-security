"""Replay command support for re-executing saved crash inputs.

Provides ReplayRunner for verifying fixes without requiring the AI engine.
"""

__all__ = ["ReplayRunner"]


def __getattr__(name: str):  # type: ignore[no-untyped-def]
    if name == "ReplayRunner":
        from deep_code_security.fuzzer.replay.runner import ReplayRunner

        return ReplayRunner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
