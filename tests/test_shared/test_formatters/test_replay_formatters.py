"""Tests for format_replay() on all four formatters."""

from __future__ import annotations

import json

import pytest

from deep_code_security.shared.formatters import get_formatter
from deep_code_security.shared.formatters.protocol import ReplayResultDTO, ReplayResultEntry


@pytest.fixture
def replay_data() -> ReplayResultDTO:
    return ReplayResultDTO(
        results=[
            ReplayResultEntry(
                status="fixed",
                target_function="my_func",
                original_exception="ZeroDivisionError: division by zero",
                replayed_exception=None,
                args=["0"],
            ),
            ReplayResultEntry(
                status="still_failing",
                target_function="other_func",
                original_exception="ValueError: bad",
                replayed_exception="ValueError: bad",
                args=["'x'"],
            ),
        ],
        fixed_count=1,
        still_failing_count=1,
        error_count=0,
        total_count=2,
        target_path="/tmp/test.py",
    )


class TestTextReplayOutput:
    def test_format_replay(self, replay_data: ReplayResultDTO) -> None:
        formatter = get_formatter("text")
        output = formatter.format_replay(replay_data)
        assert "FIXED:" in output
        assert "FAIL:" in output
        assert "1 fixed" in output


class TestJsonReplayOutput:
    def test_format_replay(self, replay_data: ReplayResultDTO) -> None:
        formatter = get_formatter("json")
        output = formatter.format_replay(replay_data)
        data = json.loads(output)
        assert data["summary"]["total"] == 2
        assert data["summary"]["fixed"] == 1


class TestSarifReplayOutput:
    def test_format_replay(self, replay_data: ReplayResultDTO) -> None:
        formatter = get_formatter("sarif")
        output = formatter.format_replay(replay_data, target_path="/tmp/test.py")
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        # Only non-fixed results should appear
        assert len(data["runs"][0]["results"]) == 1

    def test_replay_sarif_only_non_fixed(self, replay_data: ReplayResultDTO) -> None:
        formatter = get_formatter("sarif")
        output = formatter.format_replay(replay_data, target_path="/tmp/test.py")
        data = json.loads(output)
        results = data["runs"][0]["results"]
        for r in results:
            # None should be "fixed"
            assert "still crashes" in r["message"]["text"] or "unexpected" in r["message"]["text"]


class TestHtmlReplayOutput:
    def test_format_replay(self, replay_data: ReplayResultDTO) -> None:
        formatter = get_formatter("html")
        output = formatter.format_replay(replay_data)
        assert "Replay Results" in output
        assert "FIXED" in output
        assert "STILL_FAILING" in output
