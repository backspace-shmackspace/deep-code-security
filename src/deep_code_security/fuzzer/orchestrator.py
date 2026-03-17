"""Main fuzz loop orchestration with consent flow and graceful shutdown."""

from __future__ import annotations

import logging
import signal
import time
from pathlib import Path
from typing import Any

from deep_code_security.fuzzer.ai.engine import AIEngine
from deep_code_security.fuzzer.config import FuzzerConfig
from deep_code_security.fuzzer.consent import record_consent, verify_consent
from deep_code_security.fuzzer.corpus.manager import CorpusManager
from deep_code_security.fuzzer.coverage_tracking.delta import DeltaTracker
from deep_code_security.fuzzer.exceptions import (
    AIEngineError,
    CircuitBreakerError,
)
from deep_code_security.fuzzer.execution.sandbox import ContainerBackend
from deep_code_security.fuzzer.models import CoverageReport, FuzzReport, FuzzResult
from deep_code_security.fuzzer.plugins.registry import registry

__all__ = ["FuzzOrchestrator"]

logger = logging.getLogger(__name__)

PLATEAU_WINDOW = 3


class FuzzOrchestrator:
    """Orchestrates the main fuzzing loop.

    Args:
        config: FuzzerConfig instance.
        install_signal_handlers: If True (default), install SIGINT/SIGTERM handlers.
            Set to False when called from MCP server to avoid overriding the
            server's own signal handlers.
        backend: Optional execution backend to inject into the plugin. When
            provided (e.g. ContainerBackend for MCP runs), the backend is passed
            to plugin.set_backend() after the plugin is retrieved from the registry.
            When None (default), the plugin uses its own default backend.
    """

    def __init__(
        self,
        config: FuzzerConfig,
        install_signal_handlers: bool = True,
        backend: Any | None = None,
    ) -> None:
        self.config = config
        self._backend = backend
        self._shutdown_requested = False
        self._partial_results: list[FuzzResult] = []
        # SAST contexts injected by BridgeOrchestrator (iteration 1 only)
        self._sast_contexts: Any | None = config.sast_contexts
        if install_signal_handlers:
            self._setup_signal_handlers()

    def _setup_signal_handlers(self) -> None:
        """Set up SIGINT/SIGTERM handlers for graceful shutdown."""

        def handle_signal(signum: int, frame: Any) -> None:
            logger.warning("Shutdown signal received. Saving partial results...")
            self._shutdown_requested = True

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

    def run(self) -> FuzzReport:
        """Execute the full fuzzing loop.

        Returns:
            FuzzReport with all results, crashes, and coverage data.
        """
        config = self.config

        # Verify consent before any API calls
        verify_consent(config.consent)

        # Record consent if --consent flag was given
        if config.consent:
            record_consent()

        # Validate credentials (unless dry-run)
        if not config.dry_run and not config.has_valid_credentials:
            if config.use_vertex:
                raise ValueError(
                    "No GCP project configured for Vertex AI. Set GOOGLE_CLOUD_PROJECT "
                    "environment variable or use --gcp-project flag."
                )
            else:
                raise ValueError(
                    "No API key configured. Set the ANTHROPIC_API_KEY environment variable, "
                    "add api_key to ~/.config/deep-code-security/config.toml, or use --vertex "
                    "for Vertex AI with Application Default Credentials."
                )

        # Get plugin
        plugin = registry.get_plugin(config.plugin_name)

        # Inject backend if one was specified (e.g. ContainerBackend from MCP)
        if self._backend is not None:
            plugin.set_backend(self._backend)
            logger.debug(
                "FuzzOrchestrator: injected %s into plugin %s",
                type(self._backend).__name__,
                plugin.name,
            )

        # Discover targets
        logger.info("Discovering targets in %s...", config.target_path)
        all_targets = plugin.discover_targets(
            config.target_path,
            allow_side_effects=config.allow_side_effects,
        )

        # Filter to specific functions if requested
        if config.target_functions:
            targets = [
                t
                for t in all_targets
                if t.function_name in config.target_functions
                or t.qualified_name in config.target_functions
            ]
            if not targets:
                logger.warning("No targets found matching: %s", config.target_functions)
                targets = all_targets
        else:
            targets = all_targets

        if not targets:
            logger.error("No fuzzable targets found in %s", config.target_path)
            return FuzzReport(
                targets=targets,
                all_results=[],
                crashes=[],
                total_iterations=0,
                config_summary=self._build_config_summary(),
            )

        logger.info("Found %d fuzzable targets", len(targets))

        # Dry-run mode
        if config.dry_run:
            return self._dry_run(targets)

        # Initialize components
        corpus_dir = Path(config.output_dir) / "corpus"
        corpus = CorpusManager(corpus_dir)
        delta_tracker = DeltaTracker()

        if config.seed_corpus_path:
            corpus.load_seed_corpus(config.seed_corpus_path)

        ai_engine = None
        ai_engine = AIEngine(
            model=config.model,
            api_key=config.api_key,
            max_cost_usd=config.max_cost_usd,
            redact_strings=config.redact_strings,
            use_vertex=config.use_vertex,
            gcp_project=config.gcp_project,
            gcp_region=config.gcp_region,
        )

        all_results: list[FuzzResult] = []
        current_coverage: CoverageReport | None = None
        iteration = 0
        _plateau_consecutive = 0

        try:
            for iteration in range(1, config.max_iterations + 1):
                if self._shutdown_requested:
                    logger.info("Shutdown requested, stopping after iteration %d", iteration - 1)
                    break

                logger.info("=== Iteration %d/%d ===", iteration, config.max_iterations)

                try:
                    if iteration == 1 and self._sast_contexts:
                        inputs = ai_engine.generate_sast_guided_inputs(
                            targets=targets,
                            sast_contexts=self._sast_contexts,
                            count=config.inputs_per_iteration,
                        )
                    elif iteration == 1:
                        inputs = ai_engine.generate_initial_inputs(
                            targets=targets,
                            count=config.inputs_per_iteration,
                        )
                    else:
                        corpus_summary = corpus.get_summary()
                        corpus_summary["coverage_percent"] = getattr(
                            current_coverage, "coverage_percent", 0.0
                        )
                        inputs = ai_engine.refine_inputs(
                            targets=targets,
                            coverage=current_coverage,
                            previous_results=all_results[-config.inputs_per_iteration :],
                            corpus_summary=corpus_summary,
                            iteration=iteration,
                            count=config.inputs_per_iteration,
                        )
                except CircuitBreakerError as e:
                    logger.error("Circuit breaker tripped: %s", e)
                    break
                except AIEngineError as e:
                    logger.error("AI engine error: %s", e)
                    break

                if not inputs:
                    logger.warning("AI generated no valid inputs for iteration %d", iteration)
                    continue

                logger.info("Generated %d inputs for iteration %d", len(inputs), iteration)

                iteration_results: list[FuzzResult] = []
                coverage_data_list: list[dict] = []

                # Coverage collection inside containers is deferred (plan SD-01).
                # The container worker cannot write to host-side .coverage paths.
                collect_coverage = not isinstance(self._backend, ContainerBackend)

                for fuzz_input in inputs:
                    if self._shutdown_requested:
                        break

                    result = plugin.execute(
                        fuzz_input=fuzz_input,
                        timeout_ms=config.timeout_ms,
                        collect_coverage=collect_coverage,
                    )
                    iteration_results.append(result)
                    all_results.append(result)
                    self._partial_results.append(result)

                    if result.coverage_data:
                        coverage_data_list.append(result.coverage_data)

                    if not result.success:
                        if result.timed_out:
                            logger.warning(
                                "TIMEOUT: %s with args %s",
                                fuzz_input.target_function,
                                fuzz_input.args,
                            )
                        else:
                            logger.warning(
                                "CRASH: %s -> %s",
                                fuzz_input.target_function,
                                result.exception,
                            )
                        corpus.add_crash(result)
                    else:
                        if config.verbose:
                            logger.debug(
                                "OK: %s with args %s (%.1fms)",
                                fuzz_input.target_function,
                                fuzz_input.args,
                                result.duration_ms,
                            )

                if coverage_data_list:
                    delta = delta_tracker.update(coverage_data_list)
                    logger.info("Coverage delta: %d new lines covered", delta.total_new_lines)

                    if delta.has_new_coverage:
                        _plateau_consecutive = 0
                    else:
                        _plateau_consecutive += 1
                        if _plateau_consecutive >= PLATEAU_WINDOW:
                            logger.warning(
                                "Coverage plateau detected: no new lines covered for %d "
                                "consecutive iterations. Stopping early.",
                                PLATEAU_WINDOW,
                            )
                            break

                    if delta.has_new_coverage:
                        for result in iteration_results:
                            if result.success and result.coverage_data:
                                corpus.add_interesting(result)

                    current_coverage = self._build_coverage_report(delta_tracker, iteration_results)

                estimated_cost = ai_engine.usage.estimate_cost_usd(config.model)
                logger.info(
                    "Estimated API cost so far: $%.4f / $%.2f",
                    estimated_cost,
                    config.max_cost_usd,
                )
                if estimated_cost >= config.max_cost_usd:
                    logger.warning("Cost budget of $%.2f reached. Stopping.", config.max_cost_usd)
                    break

        except KeyboardInterrupt:
            logger.warning("Interrupted. Saving partial results...")

        crashes = corpus.get_all_crashes()
        report = FuzzReport(
            targets=targets,
            all_results=all_results,
            crashes=crashes,
            total_iterations=iteration,
            api_usage=ai_engine.usage if ai_engine is not None else None,
            final_coverage=current_coverage,
            timestamp=time.time(),
            config_summary=self._build_config_summary(),
        )

        return report

    def _build_config_summary(self) -> dict:
        """Build config summary dict (avoids storing API key in report)."""
        config = self.config
        return {
            "target_path": config.target_path,
            "plugin": config.plugin_name,
            "model": config.model,
            "max_iterations": config.max_iterations,
            "inputs_per_iteration": config.inputs_per_iteration,
            "timeout_ms": config.timeout_ms,
        }

    def _dry_run(self, targets: list) -> FuzzReport:
        """Show what would be sent to the API without making any calls."""
        from deep_code_security.fuzzer.ai.prompts import build_initial_prompt

        print("\n=== DRY RUN MODE ===")
        print("The following source code would be sent to the Anthropic API:\n")

        for target in targets:
            print(f"Function: {target.qualified_name}")
            print(f"Signature: {target.signature}")
            print("Source code:")
            print("-" * 40)
            print(target.source_code)
            print("-" * 40)
            print()

        prompt = build_initial_prompt(targets, count=5, redact_strings=self.config.redact_strings)
        print("Sample prompt that would be sent:")
        print("=" * 40)
        print(prompt[:2000] + ("..." if len(prompt) > 2000 else ""))
        print("=" * 40)
        print("\nNo API calls were made (--dry-run mode).")

        return FuzzReport(
            targets=targets,
            all_results=[],
            crashes=[],
            total_iterations=0,
            config_summary=self._build_config_summary(),
        )

    def _build_coverage_report(
        self,
        delta_tracker: DeltaTracker,
        results: list[FuzzResult],
    ) -> CoverageReport:
        total_covered = sum(len(lines) for lines in delta_tracker.get_total_coverage().values())

        uncovered_regions: list[dict] = []
        for result in results[-5:]:
            if result.coverage_data and "files" in result.coverage_data:
                for filepath, file_data in result.coverage_data["files"].items():
                    missing = file_data.get("missing_lines", [])
                    if missing:
                        uncovered_regions.append(
                            {
                                "file": filepath,
                                "start_line": missing[0] if missing else 0,
                                "end_line": missing[-1] if missing else 0,
                                "code_snippet": f"Lines {missing[:5]}...",
                            }
                        )

        return CoverageReport(
            total_lines=total_covered + len(uncovered_regions) * 5,
            covered_lines=total_covered,
            coverage_percent=min(
                100.0,
                total_covered / max(1, total_covered + len(uncovered_regions) * 5) * 100,
            ),
            uncovered_regions=uncovered_regions[:10],
            branch_coverage={},
            new_lines_covered=[],
        )
