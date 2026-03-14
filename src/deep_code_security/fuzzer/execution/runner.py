"""Fixed worker invocation with data-only JSON IPC.

SECURITY: No dynamic script generation. The worker script is a fixed module.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path

from deep_code_security.fuzzer.exceptions import ExecutionError
from deep_code_security.fuzzer.execution.sandbox import SandboxManager
from deep_code_security.fuzzer.models import FuzzInput, FuzzResult

__all__ = ["FuzzRunner"]

logger = logging.getLogger(__name__)

# Path to the fixed worker module -- updated from fuzzy_wuzzy to new package path
WORKER_MODULE = "deep_code_security.fuzzer.execution._worker"


class FuzzRunner:
    """Executes fuzz inputs in sandboxed subprocesses via JSON IPC."""

    def __init__(
        self,
        sandbox: SandboxManager | None = None,
        python_executable: str | None = None,
    ) -> None:
        self._sandbox = sandbox or SandboxManager()
        self._python = python_executable or sys.executable

    def run(
        self,
        fuzz_input: FuzzInput,
        module_path: str,
        timeout_ms: int,
        collect_coverage: bool = True,
    ) -> FuzzResult:
        """Execute a single fuzz input via the fixed worker subprocess."""
        timeout_seconds = timeout_ms / 1000.0
        start_time = time.monotonic()

        tmp_dir = self._sandbox.create_isolated_dir()
        input_json = os.path.join(tmp_dir, "input.json")
        output_json = os.path.join(tmp_dir, "output.json")
        coverage_data_path = os.path.join(tmp_dir, ".coverage") if collect_coverage else ""

        try:
            params = {
                "module_path": str(Path(module_path).resolve()),
                "qualified_name": fuzz_input.target_function,
                "args": list(fuzz_input.args),
                "kwargs": dict(fuzz_input.kwargs),
                "collect_coverage": collect_coverage,
                "coverage_data_path": coverage_data_path,
            }
            with open(input_json, "w") as f:
                json.dump(params, f)

            cmd = [self._python, "-m", WORKER_MODULE, input_json, output_json]

            returncode, stdout, stderr = self._sandbox._backend.run(
                cmd,
                timeout_seconds=timeout_seconds,
                cwd=tmp_dir,
                env=self._build_env(module_path),
            )

            duration_ms = (time.monotonic() - start_time) * 1000.0

            if stderr == "TIMEOUT" or returncode == -1:
                if not os.path.exists(output_json):
                    return FuzzResult(
                        input=fuzz_input,
                        success=False,
                        exception="TimeoutError: Execution exceeded timeout",
                        traceback=None,
                        duration_ms=duration_ms,
                        coverage_data={},
                        stdout="",
                        stderr="",
                        timed_out=True,
                    )

            if os.path.exists(output_json):
                try:
                    with open(output_json) as f:
                        result_data = json.load(f)
                except (json.JSONDecodeError, OSError) as e:
                    raise ExecutionError(f"Cannot read worker output: {e}") from e
            else:
                return FuzzResult(
                    input=fuzz_input,
                    success=False,
                    exception=f"WorkerCrash: Worker exited with code {returncode}",
                    traceback=stderr if stderr else None,
                    duration_ms=duration_ms,
                    coverage_data={},
                    stdout=stdout,
                    stderr=stderr,
                )

            return FuzzResult(
                input=fuzz_input,
                success=result_data.get("success", False),
                exception=result_data.get("exception"),
                traceback=result_data.get("traceback"),
                duration_ms=duration_ms,
                coverage_data=result_data.get("coverage_data", {}),
                stdout=result_data.get("stdout", ""),
                stderr=result_data.get("stderr", ""),
                timed_out=False,
            )

        finally:
            self._sandbox.cleanup_dir(tmp_dir)
            self._sandbox.reap_zombies()

    def _build_env(self, module_path: str) -> dict[str, str]:
        """Build environment for the worker subprocess.

        Adds PYTHONDONTWRITEBYTECODE=1 and PYTHONSAFEPATH=1 per plan requirements.
        """
        env = dict(os.environ)
        module_dir = str(Path(module_path).resolve().parent)

        existing_path = env.get("PYTHONPATH", "")
        if existing_path:
            env["PYTHONPATH"] = f"{module_dir}{os.pathsep}{existing_path}"
        else:
            env["PYTHONPATH"] = module_dir

        # Security: reduce implicit import side effects
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONSAFEPATH"] = "1"

        return env
