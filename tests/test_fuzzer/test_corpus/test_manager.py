"""Tests for corpus manager."""

from __future__ import annotations

from pathlib import Path

from deep_code_security.fuzzer.corpus.manager import (
    CorpusManager,
    crash_signature,
    parse_traceback_location,
)
from deep_code_security.fuzzer.models import FuzzResult


class TestParseTracebackLocation:
    def test_valid_traceback(self) -> None:
        tb = 'File "test.py", line 10, in foo\n    return 1/0'
        file_path, line = parse_traceback_location(tb)
        assert file_path == "test.py"
        assert line == 10

    def test_none(self) -> None:
        assert parse_traceback_location(None) == ("unknown", 0)

    def test_empty(self) -> None:
        assert parse_traceback_location("") == ("unknown", 0)


class TestCrashSignature:
    def test_signature(self, crash_fuzz_result: FuzzResult) -> None:
        sig = crash_signature(crash_fuzz_result)
        assert "ZeroDivisionError" in sig
        assert "test.py" in sig


class TestCorpusManager:
    def test_add_crash(self, tmp_path: Path, crash_fuzz_result: FuzzResult) -> None:
        cm = CorpusManager(tmp_path / "corpus")
        assert cm.add_crash(crash_fuzz_result) is True
        # Duplicate should return False
        assert cm.add_crash(crash_fuzz_result) is False

    def test_add_interesting(self, tmp_path: Path, sample_fuzz_result: FuzzResult) -> None:
        cm = CorpusManager(tmp_path / "corpus")
        assert cm.add_interesting(sample_fuzz_result) is True
        assert cm.add_interesting(sample_fuzz_result) is False

    def test_get_summary(self, tmp_path: Path, crash_fuzz_result: FuzzResult) -> None:
        cm = CorpusManager(tmp_path / "corpus")
        cm.add_crash(crash_fuzz_result)
        summary = cm.get_summary()
        assert summary["crash_count"] >= 1
        assert summary["total_inputs"] >= 1
