"""Tests for plugin discovery in the auditor orchestrator."""

from __future__ import annotations

import sys
from unittest.mock import patch

from deep_code_security.auditor.noop import NoOpExploitGenerator, NoOpSandbox
from deep_code_security.auditor.orchestrator import AuditorOrchestrator, _load_plugins
from deep_code_security.shared.config import Config


class TestPluginDiscovery:
    """Tests for _load_plugins plugin discovery."""

    def test_falls_back_to_noop_when_no_plugin(self) -> None:
        """Falls back to NoOp when dcs-verification is not installed."""
        config = Config()
        with patch.dict(sys.modules, {"dcs_verification": None}):
            sandbox, generator = _load_plugins(None, None, config)
        assert isinstance(sandbox, NoOpSandbox)
        assert isinstance(generator, NoOpExploitGenerator)

    def test_explicit_args_take_precedence(self) -> None:
        """Explicit sandbox/generator args are used over plugin discovery."""
        config = Config()
        custom_sandbox = NoOpSandbox()
        custom_gen = NoOpExploitGenerator()
        sandbox, generator = _load_plugins(custom_sandbox, custom_gen, config)
        assert sandbox is custom_sandbox
        assert generator is custom_gen

    def test_orchestrator_uses_noop_when_no_plugin(self) -> None:
        """AuditorOrchestrator defaults to NoOp when no plugin installed."""
        with patch.dict(sys.modules, {"dcs_verification": None}):
            orch = AuditorOrchestrator()
        assert isinstance(orch.sandbox, NoOpSandbox)
