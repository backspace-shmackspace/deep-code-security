"""Claude API integration with circuit breaker and retry logic.

Supports two backends:
- Direct Anthropic API: API key via ANTHROPIC_API_KEY env var or config file
- Vertex AI: Uses Google ADC with project ID and region

No --api-key CLI flag. The circuit breaker aborts after 3 consecutive failures.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any

try:
    import anthropic
except ImportError:
    anthropic = None  # type: ignore[assignment]

from typing import TYPE_CHECKING

from deep_code_security.fuzzer.ai.context_manager import ContextManager
from deep_code_security.fuzzer.ai.prompts import (
    SYSTEM_PROMPT,
    build_initial_prompt,
    build_refinement_prompt,
    build_sast_enriched_prompt,
)
from deep_code_security.fuzzer.ai.response_parser import parse_ai_response
from deep_code_security.fuzzer.exceptions import (
    AIEngineError,
    CircuitBreakerError,
    InputValidationError,
)
from deep_code_security.fuzzer.models import FuzzInput, FuzzResult, TargetInfo

if TYPE_CHECKING:
    from deep_code_security.bridge.models import SASTContext

__all__ = ["AIEngine", "APIUsage"]

logger = logging.getLogger(__name__)

# Retry configuration
MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 1.0
BACKOFF_MULTIPLIER = 2.0
MAX_BACKOFF_SECONDS = 30.0
JITTER_FACTOR = 0.25

# Circuit breaker: abort after this many consecutive failures
CIRCUIT_BREAKER_THRESHOLD = 3


class APIUsage:
    """Tracks token usage and estimated cost."""

    def __init__(self) -> None:
        self.input_tokens = 0
        self.output_tokens = 0
        self.total_api_calls = 0
        self.failed_calls = 0

    def record(self, input_tokens: int, output_tokens: int) -> None:
        """Record token usage from an API call."""
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.total_api_calls += 1

    def estimate_cost_usd(self, model: str) -> float:
        """Estimate cost in USD based on token usage.

        Uses conservative estimates. Actual pricing may vary.
        """
        # Approximate pricing per million tokens
        pricing = {
            "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
            "claude-opus-4-6": {"input": 15.0, "output": 75.0},
            "claude-haiku-3-5": {"input": 0.80, "output": 4.0},
        }
        rates = pricing.get(model, {"input": 3.0, "output": 15.0})
        return (
            self.input_tokens / 1_000_000 * rates["input"]
            + self.output_tokens / 1_000_000 * rates["output"]
        )


class AIEngine:
    """Manages Claude API interactions for intelligent input generation.

    Supports two backends:
    - Direct Anthropic API (default): uses ANTHROPIC_API_KEY
    - Vertex AI: uses Google ADC with project ID and region

    Implements:
    - Exponential backoff with jitter on failures
    - Circuit breaker: aborts after CIRCUIT_BREAKER_THRESHOLD consecutive failures
    - Token usage tracking for cost budgeting
    - Prompt injection mitigation via source code delimiters
    """

    def __init__(
        self,
        model: str = "claude-sonnet-4-6",
        api_key: str | None = None,
        max_cost_usd: float = 5.0,
        redact_strings: bool = False,
        use_vertex: bool = False,
        gcp_project: str = "",
        gcp_region: str = "us-east5",
    ) -> None:
        self.model = model
        self.max_cost_usd = max_cost_usd
        self.redact_strings = redact_strings
        self.use_vertex = use_vertex
        self.usage = APIUsage()
        self.context_manager = ContextManager(model)

        # Circuit breaker state
        self._consecutive_failures = 0

        # Initialize Anthropic client
        try:
            if anthropic is None:
                raise ImportError("anthropic package not installed")
            if use_vertex:
                self._client = anthropic.AnthropicVertex(
                    project_id=gcp_project,
                    region=gcp_region,
                )
                logger.info(
                    "Using Vertex AI backend (project=%s, region=%s)",
                    gcp_project,
                    gcp_region,
                )
            else:
                self._client = anthropic.Anthropic(api_key=api_key)
        except ImportError as e:
            raise AIEngineError(
                "anthropic package not installed. Run: pip install 'deep-code-security[fuzz]'"
            ) from e
        except Exception as e:
            raise AIEngineError(f"Failed to initialize Anthropic client: {e}") from e

    def generate_initial_inputs(
        self,
        targets: list[TargetInfo],
        count: int = 10,
    ) -> list[FuzzInput]:
        """Generate initial batch of adversarial inputs from source analysis."""
        self._check_cost_budget()
        valid_targets = {t.qualified_name for t in targets}
        prompt = build_initial_prompt(targets, count, redact_strings=self.redact_strings)

        return self._call_with_retry(prompt, valid_targets)

    def generate_sast_guided_inputs(
        self,
        targets: list[TargetInfo],
        sast_contexts: dict[str, "SASTContext"],
        count: int = 10,
    ) -> list[FuzzInput]:
        """Generate initial inputs guided by SAST analysis context.

        Uses build_sast_enriched_prompt() instead of build_initial_prompt().
        SAST context is injected on iteration 1 only; subsequent iterations
        use the standard coverage-guided refinement prompt.

        Args:
            targets: Fuzz targets to generate inputs for.
            sast_contexts: Dict keyed by qualified_name -> SASTContext.
            count: Number of inputs to generate.

        Returns:
            List of FuzzInput objects.
        """
        self._check_cost_budget()
        valid_targets = {t.qualified_name for t in targets}
        prompt = build_sast_enriched_prompt(
            targets, sast_contexts, count, redact_strings=self.redact_strings
        )
        return self._call_with_retry(prompt, valid_targets)

    def refine_inputs(
        self,
        targets: list[TargetInfo],
        coverage: Any,
        previous_results: list[FuzzResult],
        corpus_summary: dict,
        iteration: int,
        count: int = 10,
    ) -> list[FuzzInput]:
        """Generate refined inputs based on coverage feedback."""
        self._check_cost_budget()
        valid_targets = {t.qualified_name for t in targets}

        coverage_summary = self._build_coverage_summary(coverage)

        recent_crashes = [
            {
                "exception": r.exception,
                "input_repr": str(r.input.args[:2]),
            }
            for r in previous_results
            if not r.success and r.exception
        ][-5:]

        prompt = build_refinement_prompt(
            targets=targets,
            coverage_summary=coverage_summary,
            recent_crashes=recent_crashes,
            corpus_summary=corpus_summary,
            count=count,
            iteration=iteration,
            redact_strings=self.redact_strings,
        )

        return self._call_with_retry(prompt, valid_targets)

    def _call_with_retry(
        self,
        prompt: str,
        valid_targets: set[str],
    ) -> list[FuzzInput]:
        """Call Claude API with exponential backoff retry."""
        self._check_circuit_breaker()

        last_error: Exception | None = None

        for attempt in range(MAX_RETRIES):
            try:
                response_text = self._call_api(prompt)
                inputs = self._parse_with_validation(response_text, valid_targets)
                self._consecutive_failures = 0
                return inputs

            except InputValidationError as e:
                logger.warning(
                    "Attempt %d: Input validation failed: %s. Retrying...",
                    attempt + 1,
                    e,
                )
                last_error = e
                if attempt < MAX_RETRIES - 1:
                    self._sleep_with_backoff(attempt)

            except Exception as e:
                logger.warning(
                    "Attempt %d: API call failed: %s. Retrying...",
                    attempt + 1,
                    e,
                )
                last_error = e
                self._consecutive_failures += 1
                self.usage.failed_calls += 1

                if self._consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD:
                    raise CircuitBreakerError(
                        f"Circuit breaker tripped after {self._consecutive_failures} "
                        f"consecutive API failures. Last error: {last_error}"
                    ) from e

                if attempt < MAX_RETRIES - 1:
                    self._sleep_with_backoff(attempt)

        logger.error("All %d retries exhausted. Last error: %s", MAX_RETRIES, last_error)
        return []

    def _call_api(self, prompt: str) -> str:
        """Make a single Claude API call."""
        try:
            message = self._client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            if hasattr(message, "usage"):
                self.usage.record(
                    input_tokens=getattr(message.usage, "input_tokens", 0),
                    output_tokens=getattr(message.usage, "output_tokens", 0),
                )
            return message.content[0].text
        except Exception as e:
            rate_limit_cls = getattr(anthropic, "RateLimitError", None) if anthropic else None
            if rate_limit_cls and isinstance(e, rate_limit_cls):
                retry_after = getattr(e, "retry_after", None)
                if retry_after:
                    logger.info("Rate limited. Waiting %s seconds...", retry_after)
                    time.sleep(float(retry_after))
            raise

    def _parse_with_validation(
        self,
        response_text: str,
        valid_targets: set[str],
    ) -> list[FuzzInput]:
        """Parse AI response and validate all inputs."""
        return parse_ai_response(response_text, valid_targets)

    def _check_cost_budget(self) -> None:
        """Check if we're within the cost budget."""
        estimated_cost = self.usage.estimate_cost_usd(self.model)
        if estimated_cost >= self.max_cost_usd:
            raise AIEngineError(
                f"API cost budget exceeded: ${estimated_cost:.4f} >= ${self.max_cost_usd:.2f}. "
                "Use --max-cost to increase the budget."
            )

    def _check_circuit_breaker(self) -> None:
        """Check circuit breaker state."""
        if self._consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD:
            raise CircuitBreakerError(
                f"Circuit breaker is open after {self._consecutive_failures} consecutive failures. "
                "The fuzzing run has been aborted."
            )

    def _sleep_with_backoff(self, attempt: int) -> None:
        """Sleep with exponential backoff and jitter."""
        base_sleep = BASE_BACKOFF_SECONDS * (BACKOFF_MULTIPLIER**attempt)
        jitter = base_sleep * JITTER_FACTOR * (2 * random.random() - 1)
        sleep_time = min(base_sleep + jitter, MAX_BACKOFF_SECONDS)
        logger.debug("Backing off for %.2f seconds...", sleep_time)
        time.sleep(max(0, sleep_time))

    def _build_coverage_summary(self, coverage: Any) -> dict:
        """Build a coverage summary dict for use in prompts."""
        if coverage is None:
            return {"coverage_percent": 0.0, "uncovered_regions": []}

        return {
            "coverage_percent": getattr(coverage, "coverage_percent", 0.0),
            "uncovered_regions": getattr(coverage, "uncovered_regions", []),
        }
