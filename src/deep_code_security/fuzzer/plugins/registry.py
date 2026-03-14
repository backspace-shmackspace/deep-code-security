"""Plugin discovery and registration with lazy loading and allowlist.

Plugins are discovered via Python entry points registered under
"deep_code_security.fuzzer_plugins". The old "fuzzy_wuzzy.plugins"
group is supported as a fallback with a deprecation warning.
"""

from __future__ import annotations

import importlib.metadata
import logging
import os
import warnings

from deep_code_security.fuzzer.exceptions import PluginError
from deep_code_security.fuzzer.plugins.base import TargetPlugin

__all__ = ["PluginRegistry", "registry"]

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "deep_code_security.fuzzer_plugins"
LEGACY_ENTRY_POINT_GROUP = "fuzzy_wuzzy.plugins"


class PluginRegistry:
    """Discovers and manages fuzzer target plugins.

    Lazy-loaded: list_plugins() returns names without instantiation.
    get_plugin(name) instantiates. DCS_FUZZ_ALLOWED_PLUGINS restricts
    which plugins can be loaded.
    """

    def __init__(self) -> None:
        self._plugin_classes: dict[str, type[TargetPlugin]] = {}
        self._entry_points: dict[str, importlib.metadata.EntryPoint] = {}  # deferred loading
        self._plugin_sources: dict[str, str] = {}  # name -> source package
        self._loaded = False

    def _get_allowed_plugins(self) -> set[str]:
        """Get the set of allowed plugin names from DCS_FUZZ_ALLOWED_PLUGINS."""
        allowed = os.environ.get("DCS_FUZZ_ALLOWED_PLUGINS", "python")
        return {name.strip() for name in allowed.split(",") if name.strip()}

    def _load_plugins(self) -> None:
        """Load plugin metadata from entry points (lazy -- classes only)."""
        if self._loaded:
            return

        allowed = self._get_allowed_plugins()

        # Load from new entry point group
        self._load_from_group(ENTRY_POINT_GROUP, allowed, legacy=False)

        # Fallback: load from legacy entry point group with deprecation warning
        self._load_from_group(LEGACY_ENTRY_POINT_GROUP, allowed, legacy=True)

        self._loaded = True

    def _load_from_group(self, group: str, allowed: set[str], legacy: bool) -> None:
        """Load plugins from an entry point group."""
        try:
            eps = importlib.metadata.entry_points(group=group)
        except Exception as e:
            logger.warning("Failed to load entry points from %s: %s", group, e)
            return

        for ep in eps:
            if ep.name in self._plugin_classes:
                # Already loaded from primary group
                continue

            if ep.name not in allowed:
                logger.warning(
                    "Plugin %r not in DCS_FUZZ_ALLOWED_PLUGINS allowlist, skipping",
                    ep.name,
                )
                continue

            if legacy:
                warnings.warn(
                    f"Plugin {ep.name!r} loaded from deprecated entry point group "
                    f"'{LEGACY_ENTRY_POINT_GROUP}'. Migrate to "
                    f"'{ENTRY_POINT_GROUP}'. Legacy support will be removed "
                    "in v2.0.0 or 6 months post-merge.",
                    DeprecationWarning,
                    stacklevel=2,
                )

            # Store entry point metadata without importing (lazy loading)
            self._entry_points[ep.name] = ep
            source_pkg = getattr(ep, "dist", None)
            source_name = source_pkg.name if source_pkg else "unknown"
            self._plugin_sources[ep.name] = source_name
            logger.debug(
                "Discovered plugin: %s from package %s (group=%s)",
                ep.name,
                source_name,
                group,
            )

    def get_plugin(self, name: str) -> TargetPlugin:
        """Get a plugin instance by name.

        Instantiates the plugin class on demand.

        Raises:
            PluginError: If no plugin with the given name is found or not allowed.
        """
        self._load_plugins()

        # Check allowlist at get-time too (in case env changed)
        allowed = self._get_allowed_plugins()
        if name not in allowed:
            raise PluginError(
                f"Plugin '{name}' is not in DCS_FUZZ_ALLOWED_PLUGINS allowlist. "
                f"Allowed: {sorted(allowed)}"
            )

        # Lazy-load the plugin class from entry point if not yet imported
        if name not in self._plugin_classes:
            if name in self._entry_points:
                ep = self._entry_points[name]
                try:
                    plugin_cls = ep.load()
                    if not (isinstance(plugin_cls, type) and issubclass(plugin_cls, TargetPlugin)):
                        raise PluginError(
                            f"Entry point {name!r} did not load a TargetPlugin subclass: {plugin_cls}"
                        )
                    self._plugin_classes[name] = plugin_cls
                except PluginError:
                    raise
                except Exception as e:
                    raise PluginError(f"Failed to load plugin {name!r}: {e}") from e
            else:
                available = sorted(set(self._plugin_classes) | set(self._entry_points))
                raise PluginError(f"No plugin named '{name}'. Available plugins: {available}")

        source = self._plugin_sources.get(name, "unknown")
        logger.info("Instantiating plugin %r from package %s", name, source)
        return self._plugin_classes[name]()

    def list_plugins(self) -> list[str]:
        """List all available plugin names (does not instantiate).

        Returns:
            Sorted list of plugin names.
        """
        self._load_plugins()
        return sorted(set(self._plugin_classes) | set(self._entry_points))

    def register(self, plugin_cls: type[TargetPlugin]) -> None:
        """Manually register a plugin class (useful for testing)."""
        instance = plugin_cls()
        self._plugin_classes[instance.name] = plugin_cls
        self._plugin_sources[instance.name] = "manual"
        self._loaded = True

    def reset(self) -> None:
        """Reset the registry (useful for testing)."""
        self._plugin_classes = {}
        self._entry_points = {}
        self._plugin_sources = {}
        self._loaded = False


# Global registry instance
registry = PluginRegistry()
