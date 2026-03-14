"""Tests for token budget management."""

from __future__ import annotations

from deep_code_security.fuzzer.ai.context_manager import ContextManager


class TestContextManager:
    def test_estimate_tokens(self) -> None:
        cm = ContextManager("claude-sonnet-4-6")
        tokens = cm.estimate_tokens("a" * 400)
        assert tokens == 100

    def test_fits_in_budget(self) -> None:
        cm = ContextManager("claude-sonnet-4-6")
        assert cm.fits_in_budget("short text") is True

    def test_build_prompt(self) -> None:
        cm = ContextManager("claude-sonnet-4-6")
        prompt = cm.build_prompt(
            target_source="def f(): pass",
            uncovered_regions=[],
            recent_crashes=[],
            corpus_summary={"total_inputs": 0, "crash_count": 0, "coverage_percent": 0.0},
        )
        assert "def f(): pass" in prompt
