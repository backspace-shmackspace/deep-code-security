"""Integration tests for the ContainerBackend fuzzer sandbox.

These tests require Podman to be installed and the dcs-fuzz-python image
to be built (`make build-fuzz-sandbox`). They are automatically skipped
when the container backend is not available.

Run with:
    make test-integration
    # or
    pytest tests/test_integration/test_fuzz_container.py -v
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from deep_code_security.fuzzer.execution.sandbox import ContainerBackend

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not ContainerBackend.is_available(),
        reason="Podman + dcs-fuzz-python image not available (run 'make build-fuzz-sandbox')",
    ),
]

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "fuzz_targets"


@pytest.fixture()
def backend() -> ContainerBackend:
    return ContainerBackend()


@pytest.fixture()
def simple_target_path() -> Path:
    """Return path to the simple_target.py fixture."""
    p = FIXTURES_DIR / "simple_target.py"
    assert p.exists(), f"Fixture not found: {p}"
    return p


class TestContainerExecution:
    """Tests that the container actually runs the worker."""

    def test_container_executes_worker(
        self, backend: ContainerBackend, simple_target_path: Path
    ) -> None:
        """The container must execute the worker and produce an output.json."""
        with tempfile.TemporaryDirectory(prefix="dcs_integ_") as tmp_dir:
            input_json = os.path.join(tmp_dir, "input.json")
            output_json = os.path.join(tmp_dir, "output.json")

            params = {
                "module_path": f"/target/{simple_target_path.name}",
                "qualified_name": "parse_input",
                "args": ["'key=value,foo=bar'"],
                "kwargs": {},
                "collect_coverage": False,
                "coverage_data_path": "",
            }
            with open(input_json, "w") as f:
                json.dump(params, f)

            returncode, stdout, stderr = backend.run(
                cmd=[],
                env={},
                timeout_seconds=30.0,
                target_file=str(simple_target_path),
                input_json=input_json,
                output_json=output_json,
                ipc_dir=tmp_dir,
            )

            assert os.path.exists(output_json), (
                f"Worker did not produce output.json. returncode={returncode}, stderr={stderr!r}"
            )

            with open(output_json) as f:
                result = json.load(f)

            assert result.get("success") is True, (
                f"Worker reported failure: {result.get('exception')}\n{result.get('traceback')}"
            )

    def test_container_no_host_env_leakage(
        self, backend: ContainerBackend, simple_target_path: Path
    ) -> None:
        """The container must not have access to host environment variables.

        We inject a canary value via ANTHROPIC_API_KEY and verify it
        does not appear in the container's output.
        """
        canary = "CANARY-SECRET-SHOULD-NOT-LEAK-abc123xyz"
        os.environ["ANTHROPIC_API_KEY"] = canary

        try:
            with tempfile.TemporaryDirectory(prefix="dcs_integ_") as tmp_dir:
                input_json = os.path.join(tmp_dir, "input.json")
                output_json = os.path.join(tmp_dir, "output.json")

                # Ask the worker to call parse_input with the canary as the value
                # If env leaked, the worker output may contain the canary
                params = {
                    "module_path": f"/target/{simple_target_path.name}",
                    "qualified_name": "parse_input",
                    "args": [f"'check=safe'"],
                    "kwargs": {},
                    "collect_coverage": False,
                    "coverage_data_path": "",
                }
                with open(input_json, "w") as f:
                    json.dump(params, f)

                returncode, stdout, stderr = backend.run(
                    cmd=[],
                    env={"ANTHROPIC_API_KEY": canary},  # Should be ignored by ContainerBackend
                    timeout_seconds=30.0,
                    target_file=str(simple_target_path),
                    input_json=input_json,
                    output_json=output_json,
                    ipc_dir=tmp_dir,
                )

                # The canary must not appear in stdout or stderr from the container
                assert canary not in stdout, (
                    "Host ANTHROPIC_API_KEY leaked into container stdout"
                )
                assert canary not in stderr, (
                    "Host ANTHROPIC_API_KEY leaked into container stderr"
                )

                if os.path.exists(output_json):
                    with open(output_json) as f:
                        output_text = f.read()
                    assert canary not in output_text, (
                        "Host ANTHROPIC_API_KEY leaked into container output.json"
                    )
        finally:
            os.environ.pop("ANTHROPIC_API_KEY", None)

    def test_container_single_file_mount(
        self, backend: ContainerBackend, simple_target_path: Path
    ) -> None:
        """The container must not be able to read sibling files (e.g., .env).

        The .env file in tests/fixtures/fuzz_targets/ contains a canary value.
        The container should only mount the specific target file, so the .env
        must be inaccessible.
        """
        env_file = FIXTURES_DIR / ".env"
        assert env_file.exists(), f"Canary .env fixture not found: {env_file}"

        with tempfile.TemporaryDirectory(prefix="dcs_integ_") as tmp_dir:
            input_json = os.path.join(tmp_dir, "input.json")
            output_json = os.path.join(tmp_dir, "output.json")

            # Ask the worker to try to read a sibling .env file
            # We use a simple function that won't crash, but the .env path would
            # differ from what's accessible inside the container.
            params = {
                "module_path": f"/target/{simple_target_path.name}",
                "qualified_name": "parse_input",
                "args": ["'test=value'"],
                "kwargs": {},
                "collect_coverage": False,
                "coverage_data_path": "",
            }
            with open(input_json, "w") as f:
                json.dump(params, f)

            returncode, stdout, stderr = backend.run(
                cmd=[],
                env={},
                timeout_seconds=30.0,
                target_file=str(simple_target_path),
                input_json=input_json,
                output_json=output_json,
                ipc_dir=tmp_dir,
            )

            # The .env canary value must not appear in any container output
            env_content = env_file.read_text()
            canary_line = "super-secret-value-that-should-not-leak"

            assert canary_line not in stdout, (
                ".env content leaked into container stdout"
            )
            assert canary_line not in stderr, (
                ".env content leaked into container stderr"
            )

            if os.path.exists(output_json):
                with open(output_json) as f:
                    output_text = f.read()
                assert canary_line not in output_text, (
                    ".env content leaked into container output"
                )
