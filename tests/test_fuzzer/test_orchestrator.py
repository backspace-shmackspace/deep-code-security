"""Tests for FuzzOrchestrator."""

from __future__ import annotations

import signal

from deep_code_security.fuzzer.config import FuzzerConfig
from deep_code_security.fuzzer.orchestrator import FuzzOrchestrator


class TestFuzzOrchestrator:
    def test_no_signal_handlers(self) -> None:
        """FuzzOrchestrator with install_signal_handlers=False does not install handlers."""
        original_handler = signal.getsignal(signal.SIGINT)
        config = FuzzerConfig(target_path="/tmp/test.py", consent=True)
        orchestrator = FuzzOrchestrator(config, install_signal_handlers=False)
        # Signal handler should be unchanged
        assert signal.getsignal(signal.SIGINT) is original_handler

    def test_default_installs_handlers(self) -> None:
        """Default behavior installs signal handlers."""
        config = FuzzerConfig(target_path="/tmp/test.py", consent=True)
        original_handler = signal.getsignal(signal.SIGINT)
        orchestrator = FuzzOrchestrator(config, install_signal_handlers=True)
        # Handler should have changed
        new_handler = signal.getsignal(signal.SIGINT)
        assert new_handler is not original_handler
        # Restore
        signal.signal(signal.SIGINT, original_handler)
