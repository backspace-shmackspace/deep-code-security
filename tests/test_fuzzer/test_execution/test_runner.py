"""Tests for FuzzRunner."""

from __future__ import annotations

from deep_code_security.fuzzer.execution.runner import WORKER_MODULE


class TestFuzzRunner:
    def test_worker_module_path(self) -> None:
        """WORKER_MODULE must use the new package path."""
        assert WORKER_MODULE == "deep_code_security.fuzzer.execution._worker"
