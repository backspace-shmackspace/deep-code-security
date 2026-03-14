"""Corpus management for interesting inputs and crashes."""

__all__ = ["CorpusManager"]


def __getattr__(name: str):  # type: ignore[no-untyped-def]
    if name == "CorpusManager":
        from deep_code_security.fuzzer.corpus.manager import CorpusManager

        return CorpusManager
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
