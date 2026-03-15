"""Unit tests for FuzzRunner path translation when using ContainerBackend.

The runner must rewrite module_path to /target/<basename> in the JSON payload
when the sandbox backend is a ContainerBackend, so the worker can find the
file in its read-only mount.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.fuzzer.execution.runner import FuzzRunner
from deep_code_security.fuzzer.execution.sandbox import (
    ContainerBackend,
    SandboxManager,
    SubprocessBackend,
)
from deep_code_security.fuzzer.models import FuzzInput


@pytest.fixture()
def simple_fuzz_input() -> FuzzInput:
    return FuzzInput(
        target_function="parse_input",
        args=["'hello=world'"],
        kwargs={},
    )


def _make_capturing_run(written_params: list[dict]):
    """Return a fake run() callable that captures the input JSON and writes a fake output."""

    def fake_run(cmd, timeout_seconds, cwd="", env=None, **kwargs):  # noqa: ANN001
        # Locate input.json from cmd args or kwargs
        input_json_path = kwargs.get("input_json") or next(
            (c for c in cmd if c.endswith("input.json")), None
        )
        if input_json_path and os.path.exists(input_json_path):
            with open(input_json_path) as f:
                written_params.append(json.load(f))

        # Write a minimal output.json so FuzzRunner doesn't raise
        output_json_path = kwargs.get("output_json") or next(
            (c for c in cmd if c.endswith("output.json")), None
        )
        if output_json_path:
            with open(output_json_path, "w") as f:
                json.dump(
                    {
                        "success": True,
                        "exception": None,
                        "traceback": None,
                        "stdout": "",
                        "stderr": "",
                        "coverage_data": {},
                    },
                    f,
                )

        return 0, "", ""

    return fake_run


class TestModulePathTranslation:
    def test_module_path_translated_for_container_backend(
        self,
        simple_fuzz_input: FuzzInput,
        tmp_path: Path,
    ) -> None:
        """When the backend is ContainerBackend, module_path in the JSON payload
        must be /target/<basename>, not the host absolute path."""
        target_file = tmp_path / "my_target.py"
        target_file.write_text("def parse_input(data): return {}")

        written_params: list[dict] = []

        # Use a real ContainerBackend instance so isinstance() works correctly
        real_backend = ContainerBackend.__new__(ContainerBackend)
        real_backend._runtime_cmd = ["podman"]
        real_backend._image = "dcs-fuzz-python:latest"
        real_backend._memory_limit = "512m"
        real_backend._pids_limit = 64
        real_backend._cpus = 1.0
        real_backend._tmpfs_size = "64m"
        real_backend._seccomp_profile = "/nonexistent/seccomp.json"
        real_backend.run = _make_capturing_run(written_params)  # type: ignore[method-assign]

        sandbox = SandboxManager(backend=real_backend)
        runner = FuzzRunner(sandbox=sandbox)

        runner.run(
            fuzz_input=simple_fuzz_input,
            module_path=str(target_file),
            timeout_ms=5000,
            collect_coverage=False,
        )

        assert len(written_params) == 1, "Expected FuzzRunner to write input.json once"
        actual_path = written_params[0]["module_path"]
        assert actual_path == f"/target/{target_file.name}", (
            f"Expected /target/{target_file.name}, got {actual_path!r}"
        )

    def test_module_path_unchanged_for_subprocess_backend(
        self,
        simple_fuzz_input: FuzzInput,
        tmp_path: Path,
    ) -> None:
        """When the backend is SubprocessBackend, module_path is the resolved host path."""
        target_file = tmp_path / "my_target.py"
        target_file.write_text("def parse_input(data): return {}")

        written_params: list[dict] = []

        subprocess_backend = SubprocessBackend()
        subprocess_backend.run = _make_capturing_run(written_params)  # type: ignore[method-assign]

        sandbox = SandboxManager(backend=subprocess_backend)
        runner = FuzzRunner(sandbox=sandbox)

        runner.run(
            fuzz_input=simple_fuzz_input,
            module_path=str(target_file),
            timeout_ms=5000,
            collect_coverage=False,
        )

        assert len(written_params) == 1
        actual_path = written_params[0]["module_path"]
        expected_path = str(target_file.resolve())
        assert actual_path == expected_path, (
            f"Expected host path {expected_path!r}, got {actual_path!r}"
        )
