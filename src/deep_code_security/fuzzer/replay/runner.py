"""Replay runner for re-executing saved crash inputs.

Re-validates expressions before replay to close TOCTOU gap.
"""

from __future__ import annotations

import logging

from deep_code_security.fuzzer.ai.expression_validator import validate_expression
from deep_code_security.fuzzer.exceptions import CorpusError, ExecutionError
from deep_code_security.fuzzer.models import FuzzResult, ReplayResultModel
from deep_code_security.fuzzer.plugins.registry import registry

__all__ = ["ReplayRunner"]

logger = logging.getLogger(__name__)


def _exception_type(exception: str | None) -> str:
    if not exception:
        return ""
    return exception.split(":", 1)[0].strip()


def _validate_fuzz_input_expressions(result: FuzzResult) -> None:
    """Re-validate expression strings in a FuzzInput before replay.

    Closes the TOCTOU gap where tampered corpus files could bypass
    the response parser's validation.

    Raises:
        CorpusError: If any expression fails AST validation.
    """
    for i, expr in enumerate(result.input.args):
        if not validate_expression(expr):
            raise CorpusError(f"Replay arg {i} failed expression validation: {expr!r}")
    for key, expr in result.input.kwargs.items():
        if not validate_expression(expr):
            raise CorpusError(f"Replay kwarg {key!r} failed expression validation: {expr!r}")


class ReplayRunner:
    """Re-executes corpus crash inputs against a target to verify fixes."""

    def __init__(
        self,
        target_path: str,
        plugin_name: str = "python",
        timeout_ms: int = 5000,
    ) -> None:
        self.target_path = target_path
        self.timeout_ms = timeout_ms
        self._plugin = registry.get_plugin(plugin_name)

        targets = self._plugin.discover_targets(target_path, allow_side_effects=True)
        if not targets:
            raise ExecutionError(
                f"No fuzzable functions discovered in '{target_path}'. "
                "Verify the target file contains functions matching the "
                "plugin's discovery criteria."
            )

        logger.debug("Replay: discovered %d target(s) in %s", len(targets), target_path)

    def replay_crash(self, crash: FuzzResult) -> ReplayResultModel:
        """Re-execute a single crash input and classify the outcome.

        Validates expressions before execution.
        """
        # Expression re-validation before replay
        _validate_fuzz_input_expressions(crash)

        original_exc_type = _exception_type(crash.exception)
        logger.debug(
            "Replaying %s (%s)",
            crash.input.target_function,
            original_exc_type,
        )

        replayed = self._plugin.execute(
            crash.input,
            timeout_ms=self.timeout_ms,
            collect_coverage=False,
        )

        replayed_exc_type = _exception_type(replayed.exception)

        if replayed.success:
            status = "fixed"
        elif replayed_exc_type == original_exc_type:
            status = "still_failing"
        else:
            status = "error"

        logger.debug("Replay result for %s: %s", crash.input.target_function, status)

        return ReplayResultModel(
            original=crash,
            replayed=replayed,
            status=status,
            original_exception=crash.exception or "",
            replayed_exception=replayed.exception,
        )

    def replay_all(
        self,
        crashes: list[FuzzResult],
        fail_fast: bool = False,
    ) -> list[ReplayResultModel]:
        results: list[ReplayResultModel] = []

        for crash in crashes:
            try:
                result = self.replay_crash(crash)
            except CorpusError as e:
                logger.warning("Skipping crash due to expression validation failure: %s", e)
                continue

            results.append(result)

            if fail_fast and result.status != "fixed":
                logger.debug(
                    "fail_fast: stopping after %s result for %s",
                    result.status,
                    crash.input.target_function,
                )
                break

        return results
