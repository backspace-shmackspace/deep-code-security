"""Unit tests for CFuzzRunner."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.fuzzer.execution.c_runner import CFuzzRunner, C_WORKER_MODULE
from deep_code_security.fuzzer.models import FuzzInput


def _make_input(harness_source: str = "") -> FuzzInput:
    return FuzzInput(
        target_function="test_func",
        args=["x"],
        kwargs={},
        metadata={"harness_source": harness_source} if harness_source else {},
    )


def _make_sandbox(tmp_dir: str, output_data: dict | None = None, returncode: int = 0) -> MagicMock:
    """Return a mock SandboxManager that writes output.json on run()."""
    sandbox = MagicMock()
    sandbox.create_isolated_dir.return_value = tmp_dir
    sandbox.cleanup_dir.return_value = None
    sandbox.reap_zombies.return_value = None

    # Subprocess backend (not container)
    sandbox._backend = MagicMock()
    sandbox._backend.__class__.__name__ = "SubprocessBackend"

    def fake_run(cmd, timeout, **kwargs):
        if output_data is not None:
            output_json = os.path.join(tmp_dir, "output.json")
            with open(output_json, "w") as f:
                json.dump(output_data, f)
        return returncode, "stdout_text", "stderr_text"

    sandbox._backend.run.side_effect = fake_run
    return sandbox


class TestCWorkerModule:
    def test_worker_module_path(self) -> None:
        assert C_WORKER_MODULE == "deep_code_security.fuzzer.execution._c_worker"


class TestCFuzzRunnerMissingHarness:
    def test_missing_harness_returns_failure(self, tmp_path: Path) -> None:
        sandbox = _make_sandbox(str(tmp_path))
        runner = CFuzzRunner(sandbox=sandbox)
        fuzz_input = _make_input(harness_source="")
        result = runner.run(fuzz_input, target_file="/tmp/foo.c", timeout_ms=1000)
        assert not result.success
        assert "harness_source" in (result.exception or "")
        assert result.duration_ms == 0.0


class TestCFuzzRunnerSubprocessBackend:
    def test_successful_run(self, tmp_path: Path) -> None:
        output = {"success": True, "exception": None, "traceback": None,
                  "coverage_data": {"lines": [1, 2]}, "stdout": "ok", "stderr": ""}
        sandbox = _make_sandbox(str(tmp_path), output_data=output)
        runner = CFuzzRunner(sandbox=sandbox)
        fuzz_input = _make_input("int main(){return 0;}")
        result = runner.run(fuzz_input, target_file="/tmp/foo.c", timeout_ms=5000)
        assert result.success
        assert result.coverage_data == {"lines": [1, 2]}
        assert result.stdout == "ok"

    def test_worker_crash_no_output_json(self, tmp_path: Path) -> None:
        sandbox = _make_sandbox(str(tmp_path), output_data=None, returncode=1)
        runner = CFuzzRunner(sandbox=sandbox)
        fuzz_input = _make_input("int main(){return 0;}")
        result = runner.run(fuzz_input, target_file="/tmp/foo.c", timeout_ms=5000)
        assert not result.success
        assert "WorkerCrash" in (result.exception or "")

    def test_timeout_no_output_json(self, tmp_path: Path) -> None:
        sandbox = _make_sandbox(str(tmp_path), output_data=None, returncode=-1)
        sandbox._backend.run.side_effect = None
        sandbox._backend.run.return_value = (-1, "", "TIMEOUT")
        runner = CFuzzRunner(sandbox=sandbox)
        fuzz_input = _make_input("int main(){return 0;}")
        result = runner.run(fuzz_input, target_file="/tmp/foo.c", timeout_ms=5000)
        assert not result.success
        assert result.timed_out

    def test_compile_flags_passed(self, tmp_path: Path) -> None:
        output = {"success": True, "exception": None, "traceback": None,
                  "coverage_data": {}, "stdout": "", "stderr": ""}
        sandbox = _make_sandbox(str(tmp_path), output_data=output)
        runner = CFuzzRunner(sandbox=sandbox)
        fuzz_input = _make_input("int main(){return 0;}")
        runner.run(fuzz_input, target_file="/tmp/foo.c", timeout_ms=5000,
                   compile_flags=["-O2", "-DFOO=1"])
        # Verify the input.json written to the sandbox contained compile_flags
        input_json_path = os.path.join(str(tmp_path), "input.json")
        with open(input_json_path) as f:
            params = json.load(f)
        assert params["compile_flags"] == ["-O2", "-DFOO=1"]

    def test_failed_run_with_exception(self, tmp_path: Path) -> None:
        output = {"success": False, "exception": "SIGSEGV at 0x0", "traceback": "bt here",
                  "coverage_data": {}, "stdout": "", "stderr": ""}
        sandbox = _make_sandbox(str(tmp_path), output_data=output)
        runner = CFuzzRunner(sandbox=sandbox)
        fuzz_input = _make_input("int main(){return 0;}")
        result = runner.run(fuzz_input, target_file="/tmp/foo.c", timeout_ms=5000)
        assert not result.success
        assert result.exception == "SIGSEGV at 0x0"
        assert result.traceback == "bt here"

    def test_symlink_output_json_rejected(self, tmp_path: Path) -> None:
        from deep_code_security.fuzzer.exceptions import ExecutionError

        real_file = tmp_path / "real_output.json"
        real_file.write_text(json.dumps({"success": True, "exception": None,
                                          "traceback": None, "coverage_data": {},
                                          "stdout": "", "stderr": ""}))
        symlink_path = tmp_path / "output.json"
        symlink_path.symlink_to(real_file)

        sandbox = MagicMock()
        sandbox.create_isolated_dir.return_value = str(tmp_path)
        sandbox.cleanup_dir.return_value = None
        sandbox.reap_zombies.return_value = None
        sandbox._backend = MagicMock()
        sandbox._backend.__class__.__name__ = "SubprocessBackend"
        sandbox._backend.run.return_value = (0, "", "")

        runner = CFuzzRunner(sandbox=sandbox)
        fuzz_input = _make_input("int main(){return 0;}")
        with pytest.raises(ExecutionError, match="symlink"):
            runner.run(fuzz_input, target_file="/tmp/foo.c", timeout_ms=5000)

    def test_oversized_output_json_rejected(self, tmp_path: Path) -> None:
        from deep_code_security.fuzzer.exceptions import ExecutionError

        output_file = tmp_path / "output.json"
        output_file.write_bytes(b"x" * (11 * 1024 * 1024))

        sandbox = MagicMock()
        sandbox.create_isolated_dir.return_value = str(tmp_path)
        sandbox.cleanup_dir.return_value = None
        sandbox.reap_zombies.return_value = None
        sandbox._backend = MagicMock()
        sandbox._backend.__class__.__name__ = "SubprocessBackend"
        sandbox._backend.run.return_value = (0, "", "")

        runner = CFuzzRunner(sandbox=sandbox)
        fuzz_input = _make_input("int main(){return 0;}")
        with pytest.raises(ExecutionError, match="10 MB"):
            runner.run(fuzz_input, target_file="/tmp/foo.c", timeout_ms=5000)

    def test_corrupt_output_json_raises(self, tmp_path: Path) -> None:
        from deep_code_security.fuzzer.exceptions import ExecutionError

        output_file = tmp_path / "output.json"
        output_file.write_text("not valid json {{{{")

        sandbox = MagicMock()
        sandbox.create_isolated_dir.return_value = str(tmp_path)
        sandbox.cleanup_dir.return_value = None
        sandbox.reap_zombies.return_value = None
        sandbox._backend = MagicMock()
        sandbox._backend.__class__.__name__ = "SubprocessBackend"
        sandbox._backend.run.return_value = (0, "", "")

        runner = CFuzzRunner(sandbox=sandbox)
        fuzz_input = _make_input("int main(){return 0;}")
        with pytest.raises(ExecutionError, match="Cannot read worker output"):
            runner.run(fuzz_input, target_file="/tmp/foo.c", timeout_ms=5000)


class TestCFuzzRunnerContainerBackend:
    def test_container_backend_uses_container_target_path(self, tmp_path: Path) -> None:
        from deep_code_security.fuzzer.execution.sandbox import CContainerBackend

        output = {"success": True, "exception": None, "traceback": None,
                  "coverage_data": {}, "stdout": "", "stderr": ""}

        sandbox = MagicMock()
        sandbox.create_isolated_dir.return_value = str(tmp_path)
        sandbox.cleanup_dir.return_value = None
        sandbox.reap_zombies.return_value = None
        # Make backend look like CContainerBackend
        sandbox._backend = MagicMock(spec=CContainerBackend)

        def fake_container_run(cmd, timeout, **kwargs):
            out_path = os.path.join(str(tmp_path), "output.json")
            with open(out_path, "w") as f:
                json.dump(output, f)
            return 0, "", ""

        sandbox._backend.run.side_effect = fake_container_run

        runner = CFuzzRunner(sandbox=sandbox)
        fuzz_input = _make_input("int main(){return 0;}")
        result = runner.run(fuzz_input, target_file="/some/path/foo.c", timeout_ms=5000)
        assert result.success

        # Verify container_target_file was passed as /target/<basename>
        call_kwargs = sandbox._backend.run.call_args[1]
        assert call_kwargs.get("target_file") == str(Path("/some/path/foo.c").resolve())

    def test_input_json_uses_container_path(self, tmp_path: Path) -> None:
        from deep_code_security.fuzzer.execution.sandbox import CContainerBackend

        output = {"success": True, "exception": None, "traceback": None,
                  "coverage_data": {}, "stdout": "", "stderr": ""}

        sandbox = MagicMock()
        sandbox.create_isolated_dir.return_value = str(tmp_path)
        sandbox.cleanup_dir.return_value = None
        sandbox.reap_zombies.return_value = None
        sandbox._backend = MagicMock(spec=CContainerBackend)

        def fake_container_run(cmd, timeout, **kwargs):
            out_path = os.path.join(str(tmp_path), "output.json")
            with open(out_path, "w") as f:
                json.dump(output, f)
            return 0, "", ""

        sandbox._backend.run.side_effect = fake_container_run

        runner = CFuzzRunner(sandbox=sandbox)
        fuzz_input = _make_input("int main(){return 0;}")
        runner.run(fuzz_input, target_file="/some/path/foo.c", timeout_ms=5000)

        input_json_path = os.path.join(str(tmp_path), "input.json")
        with open(input_json_path) as f:
            params = json.load(f)
        # In container mode, target_file should be /target/<basename>
        assert params["target_file"] == "/target/foo.c"
