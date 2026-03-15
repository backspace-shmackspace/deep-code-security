"""Python target plugin for the fuzzer."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from deep_code_security.fuzzer.analyzer.signature_extractor import extract_targets_from_path
from deep_code_security.fuzzer.exceptions import ExecutionError, PluginError
from deep_code_security.fuzzer.execution.runner import FuzzRunner
from deep_code_security.fuzzer.execution.sandbox import SandboxManager
from deep_code_security.fuzzer.models import FuzzInput, FuzzResult, TargetInfo
from deep_code_security.fuzzer.plugins.base import TargetPlugin

__all__ = ["PythonTargetPlugin"]

logger = logging.getLogger(__name__)


class PythonTargetPlugin(TargetPlugin):
    """MVP Python target plugin.

    Discovers module-level functions and @staticmethod methods.
    Skips instance methods and classmethods (not supported in MVP).
    """

    def __init__(self) -> None:
        self._runner = FuzzRunner(sandbox=SandboxManager())
        self._target_modules: dict[str, str] = {}

    @property
    def name(self) -> str:
        return "python"

    @property
    def file_extensions(self) -> list[str]:
        return [".py"]

    def discover_targets(
        self,
        path: str,
        allow_side_effects: bool = False,
    ) -> list[TargetInfo]:
        if not self.validate_target(path):
            raise PluginError(f"Not a valid Python target: {path}")

        targets = extract_targets_from_path(path, allow_side_effects=allow_side_effects)

        for target in targets:
            self._target_modules[target.qualified_name] = target.module_path

        logger.info("Discovered %d fuzzable targets in %s", len(targets), path)
        return targets

    def execute(
        self,
        fuzz_input: FuzzInput,
        timeout_ms: int,
        collect_coverage: bool = True,
    ) -> FuzzResult:
        qualified_name = fuzz_input.target_function
        module_path = self._target_modules.get(qualified_name)

        if module_path is None:
            raise ExecutionError(
                f"Unknown target function: {qualified_name}. "
                "Call discover_targets() first or ensure the function name "
                "matches a discovered target."
            )

        return self._runner.run(
            fuzz_input=fuzz_input,
            module_path=module_path,
            timeout_ms=timeout_ms,
            collect_coverage=collect_coverage,
        )

    def validate_target(self, path: str) -> bool:
        p = Path(path)
        if p.is_file():
            return p.suffix == ".py"
        elif p.is_dir():
            return any(p.rglob("*.py"))
        return False

    def set_backend(self, backend: Any) -> None:
        """Set the execution backend on the internal FuzzRunner's SandboxManager.

        Called by FuzzOrchestrator when a specific backend is required (e.g.,
        ContainerBackend for MCP-triggered runs). Replaces the default
        SubprocessBackend on the runner's sandbox.

        Args:
            backend: An ExecutionBackend-compatible object.
        """
        self._runner._sandbox._backend = backend
        logger.debug(
            "PythonTargetPlugin: execution backend set to %s",
            type(backend).__name__,
        )

    def register_module_path(self, qualified_name: str, module_path: str) -> None:
        """Manually register a module path for a function (useful for testing)."""
        self._target_modules[qualified_name] = module_path
