"""Tests for AI engine (mocked client)."""

from __future__ import annotations

import pytest

from deep_code_security.fuzzer.ai.engine import APIUsage


class TestAPIUsage:
    def test_record(self) -> None:
        usage = APIUsage()
        usage.record(100, 50)
        assert usage.input_tokens == 100
        assert usage.output_tokens == 50
        assert usage.total_api_calls == 1

    def test_estimate_cost(self) -> None:
        usage = APIUsage()
        usage.record(1_000_000, 1_000_000)
        cost = usage.estimate_cost_usd("claude-sonnet-4-6")
        # input: 1M * 3.0/1M = 3.0, output: 1M * 15.0/1M = 15.0
        assert cost == pytest.approx(18.0)

    def test_estimate_cost_unknown_model(self) -> None:
        usage = APIUsage()
        usage.record(1_000_000, 1_000_000)
        cost = usage.estimate_cost_usd("unknown-model")
        # Falls back to sonnet pricing
        assert cost == pytest.approx(18.0)
