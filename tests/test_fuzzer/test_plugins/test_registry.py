"""Tests for plugin registry with allowlist and lazy loading."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from deep_code_security.fuzzer.exceptions import PluginError
from deep_code_security.fuzzer.plugins.base import TargetPlugin
from deep_code_security.fuzzer.plugins.registry import PluginRegistry


class _DummyPlugin(TargetPlugin):
    @property
    def name(self) -> str:
        return "dummy"

    @property
    def file_extensions(self) -> list[str]:
        return [".dum"]

    def discover_targets(self, path: str, allow_side_effects: bool = False) -> list:
        return []

    def execute(self, fuzz_input, timeout_ms: int, collect_coverage: bool = True):
        raise NotImplementedError

    def validate_target(self, path: str) -> bool:
        return True


class TestPluginRegistry:
    def test_register_and_get(self) -> None:
        reg = PluginRegistry()
        reg.register(_DummyPlugin)
        with patch.dict("os.environ", {"DCS_FUZZ_ALLOWED_PLUGINS": "dummy"}):
            plugin = reg.get_plugin("dummy")
            assert plugin.name == "dummy"

    def test_list_plugins_lazy(self) -> None:
        """list_plugins does not instantiate (we just check it returns names)."""
        reg = PluginRegistry()
        reg.register(_DummyPlugin)
        names = reg.list_plugins()
        assert "dummy" in names

    def test_unknown_plugin(self) -> None:
        reg = PluginRegistry()
        reg._loaded = True
        with patch.dict("os.environ", {"DCS_FUZZ_ALLOWED_PLUGINS": "nonexistent"}):
            with pytest.raises(PluginError, match="No plugin named"):
                reg.get_plugin("nonexistent")

    def test_allowlist_rejects_unknown(self) -> None:
        """Plugin not in allowlist is rejected."""
        reg = PluginRegistry()
        reg.register(_DummyPlugin)
        with patch.dict("os.environ", {"DCS_FUZZ_ALLOWED_PLUGINS": "python"}):
            with pytest.raises(PluginError, match="allowlist"):
                reg.get_plugin("dummy")

    def test_allowlist_default_python(self) -> None:
        """Default allowlist includes 'python'."""
        reg = PluginRegistry()
        allowed = reg._get_allowed_plugins()
        assert "python" in allowed

    def test_reset(self) -> None:
        reg = PluginRegistry()
        reg.register(_DummyPlugin)
        reg.reset()
        # After reset, _loaded is False and _plugin_classes is empty
        assert reg._plugin_classes == {}
        assert reg._loaded is False
