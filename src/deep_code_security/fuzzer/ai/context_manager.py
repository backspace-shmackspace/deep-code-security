"""Token budget and context window management for AI engine calls."""

from __future__ import annotations

import logging

__all__ = ["ContextManager"]

logger = logging.getLogger(__name__)

# Approximate token limits per model
MODEL_CONTEXT_WINDOWS: dict[str, int] = {
    "claude-sonnet-4-6": 200_000,
    "claude-opus-4-6": 200_000,
    "claude-haiku-3-5": 200_000,
    "claude-3-5-sonnet-20241022": 200_000,
    "claude-3-5-haiku-20241022": 200_000,
    "claude-3-opus-20240229": 200_000,
    "claude-3-haiku-20240307": 200_000,
}

DEFAULT_CONTEXT_WINDOW = 200_000
CHARS_PER_TOKEN_ESTIMATE = 4


class ContextManager:
    """Manages token budget and context window for AI engine calls."""

    def __init__(self, model: str, max_budget_ratio: float = 0.8) -> None:
        self.model = model
        self.max_budget_ratio = max_budget_ratio
        context_window = MODEL_CONTEXT_WINDOWS.get(model, DEFAULT_CONTEXT_WINDOW)
        self.max_tokens = int(context_window * max_budget_ratio)
        logger.debug(
            "ContextManager initialized: model=%s, max_tokens=%d",
            model,
            self.max_tokens,
        )

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for a text string."""
        return max(1, len(text) // CHARS_PER_TOKEN_ESTIMATE)

    def fits_in_budget(self, text: str) -> bool:
        """Check if text fits within the token budget."""
        return self.estimate_tokens(text) <= self.max_tokens

    def build_prompt(
        self,
        target_source: str,
        uncovered_regions: list[dict],
        recent_crashes: list[dict],
        corpus_summary: dict,
    ) -> str:
        """Build a prompt that fits within the token budget."""
        budget_remaining = self.max_tokens
        parts = []

        # Priority 1: Target source (always included)
        source_tokens = self.estimate_tokens(target_source)
        if source_tokens > budget_remaining:
            max_chars = budget_remaining * CHARS_PER_TOKEN_ESTIMATE
            target_source = target_source[:max_chars] + "\n... [truncated]"
            logger.warning("Target source truncated to fit token budget")
        parts.append(target_source)
        budget_remaining -= self.estimate_tokens(target_source)

        # Priority 2: Uncovered regions (top-N)
        if uncovered_regions and budget_remaining > 100:
            regions_text = self._format_uncovered_regions(uncovered_regions, budget_remaining // 2)
            if regions_text:
                parts.append(regions_text)
                budget_remaining -= self.estimate_tokens(regions_text)

        # Priority 3: Recent crashes
        if recent_crashes and budget_remaining > 50:
            crashes_text = self._format_crashes(recent_crashes, budget_remaining // 3)
            if crashes_text:
                parts.append(crashes_text)
                budget_remaining -= self.estimate_tokens(crashes_text)

        # Priority 4: Corpus summary
        if corpus_summary and budget_remaining > 20:
            summary_text = self._format_corpus_summary(corpus_summary)
            summary_tokens = self.estimate_tokens(summary_text)
            if summary_tokens <= budget_remaining:
                parts.append(summary_text)

        return "\n\n".join(parts)

    def _format_uncovered_regions(self, regions: list[dict], token_budget: int) -> str:
        lines = ["Uncovered regions (target these):"]
        char_budget = token_budget * CHARS_PER_TOKEN_ESTIMATE

        for region in regions:
            snippet = region.get("code_snippet", "")[:200]
            line = (
                f"  {region.get('file', '?')}:{region.get('start_line', '?')}-"
                f"{region.get('end_line', '?')}: {snippet}"
            )
            if len("\n".join(lines)) + len(line) > char_budget:
                lines.append("  ... [more regions omitted]")
                break
            lines.append(line)

        return "\n".join(lines) if len(lines) > 1 else ""

    def _format_crashes(self, crashes: list[dict], token_budget: int) -> str:
        lines = ["Recent crashes (avoid repeating, but explore related):"]
        char_budget = token_budget * CHARS_PER_TOKEN_ESTIMATE

        for crash in crashes[:5]:
            exc = crash.get("exception", "?")[:100]
            inp = crash.get("input_repr", "?")[:100]
            line = f"  {exc} with input: {inp}"
            if len("\n".join(lines)) + len(line) > char_budget:
                break
            lines.append(line)

        return "\n".join(lines) if len(lines) > 1 else ""

    def _format_corpus_summary(self, corpus_summary: dict) -> str:
        return (
            f"Corpus stats: {corpus_summary.get('total_inputs', 0)} inputs, "
            f"{corpus_summary.get('crash_count', 0)} unique crashes, "
            f"{corpus_summary.get('coverage_percent', 0.0):.1f}% coverage"
        )
