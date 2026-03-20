"""C harness worker invocation with data-only JSON IPC.

CFuzzRunner is a separate class (not a FuzzRunner subclass) because the
Python FuzzRunner is deeply coupled to Python worker semantics (module_path,
qualified_name, args as expression strings, PYTHONPATH). The C runner uses
different input.json fields (harness_source, target_file, compile_flags).

SECURITY: No eval(). No dynamic script generation. The worker script is
a fixed module (_c_worker.py). All variable data is passed as JSON data.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

from deep_code_security.fuzzer.exceptions import ExecutionError
from deep_code_security.fuzzer.execution.sandbox import CContainerBackend, SandboxManager
from deep_code_security.fuzzer.models import FuzzInput, FuzzResult

__all__ = ["CFuzzRunner"]

logger = logging.getLogger(__name__)

# Path to the fixed C worker module
C_WORKER_MODULE = "deep_code_security.fuzzer.execution._c_worker"


class CFuzzRunner:
    """Executes C harnesses in sandboxed subprocesses via JSON IPC.

    Unlike FuzzRunner (Python), CFuzzRunner:
    - Writes harness_source + target_file + compile_flags to input.json
    - Invokes _c_worker.py (not _worker.py)
    - Does NOT use eval() anywhere in the execution path
    - Passes collect_coverage=True regardless of backend type (gcov data is
      returned in output.json, unlike Python coverage.py which requires
      host-side file access)
    """

    def __init__(
        self,
        sandbox: SandboxManager | None = None,
        python_executable: str | None = None,
    ) -> None:
        self._sandbox = sandbox or SandboxManager()
        # python_executable is used only in SubprocessBackend mode
        import sys
        self._python = python_executable or sys.executable

    def run(
        self,
        fuzz_input: FuzzInput,
        target_file: str,
        timeout_ms: int,
        compile_flags: list[str] | None = None,
        collect_coverage: bool = True,
    ) -> FuzzResult:
        """Execute a single C harness via the fixed C worker subprocess.

        Args:
            fuzz_input: FuzzInput whose metadata["harness_source"] contains
                the AI-generated C harness source code.
            target_file: Absolute host path to the .c file being fuzzed.
                In SubprocessBackend mode this is the actual path.
                In CContainerBackend mode this is mounted at /target/<name>.
            timeout_ms: Per-binary execution timeout in milliseconds.
                Compilation has a separate 30-second timeout.
            compile_flags: Additional gcc flags. None means empty list.
            collect_coverage: Whether to request gcov coverage data.
                Unlike the Python runner, C coverage works inside containers
                because gcov output is included in output.json.

        Returns:
            FuzzResult populated from the worker's output.json.
        """
        timeout_seconds = timeout_ms / 1000.0
        start_time = time.monotonic()
        flags = compile_flags or []

        harness_source = fuzz_input.metadata.get("harness_source", "")
        if not harness_source:
            return FuzzResult(
                input=fuzz_input,
                success=False,
                exception="WorkerSetupError: FuzzInput.metadata missing 'harness_source'",
                traceback=None,
                duration_ms=0.0,
                coverage_data={},
                stdout="",
                stderr="",
            )

        tmp_dir = self._sandbox.create_isolated_dir()
        input_json = os.path.join(tmp_dir, "input.json")
        output_json = os.path.join(tmp_dir, "output.json")

        using_container = isinstance(self._sandbox._backend, CContainerBackend)  # read-only introspection
        resolved_target = str(Path(target_file).resolve())

        # In container mode, the target file is mounted at /target/<basename>
        container_target_file = (
            f"/target/{Path(resolved_target).name}"
            if using_container
            else resolved_target
        )

        # Wall-clock container timeout: compilation (30s) + binary execution + buffer
        # Per plan Section 8 / Container Security Policy table
        compile_timeout_s = 30
        container_timeout_s = compile_timeout_s + timeout_seconds + 10

        try:
            params = {
                "harness_source": harness_source,
                "target_file": container_target_file,
                "compile_flags": flags,
                "collect_coverage": collect_coverage,
                "timeout_ms": timeout_ms,
            }
            with open(input_json, "w") as f:
                json.dump(params, f)

            # cmd is used by SubprocessBackend; CContainerBackend ignores it
            # and uses the container ENTRYPOINT (_c_worker.py) instead.
            cmd = [self._python, "-m", C_WORKER_MODULE, input_json, output_json]

            if using_container:
                returncode, stdout, stderr = self._sandbox._backend.run(
                    cmd,
                    container_timeout_s,
                    cwd=tmp_dir,
                    env=None,
                    target_file=resolved_target,
                    input_json=input_json,
                    output_json=output_json,
                    ipc_dir=tmp_dir,
                )
            else:
                returncode, stdout, stderr = self._sandbox._backend.run(
                    cmd,
                    container_timeout_s,
                    cwd=tmp_dir,
                    env=None,
                )

            duration_ms = (time.monotonic() - start_time) * 1000.0

            # Handle backend-level timeout/failure
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
                # Security: reject symlinks and oversized output files before reading
                output_path = Path(output_json)
                if output_path.is_symlink():
                    raise ExecutionError("output.json is a symlink -- rejected")
                if output_path.stat().st_size > 10 * 1024 * 1024:
                    raise ExecutionError("output.json exceeds 10 MB size limit -- rejected")

                try:
                    with open(output_json) as f:
                        result_data = json.load(f)
                except (json.JSONDecodeError, OSError) as exc:
                    raise ExecutionError(f"Cannot read worker output: {exc}") from exc
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
