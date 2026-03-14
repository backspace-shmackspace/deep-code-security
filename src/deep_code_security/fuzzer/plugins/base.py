"""Abstract base classes for fuzzer plugin interface.

Third-party plugins can implement TargetPlugin and register via entry points:

    [project.entry-points."deep_code_security.fuzzer_plugins"]
    my_plugin = "my_package.my_module:MyPlugin"
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from deep_code_security.fuzzer.models import FuzzInput, FuzzResult, TargetInfo

__all__ = ["TargetPlugin"]


class TargetPlugin(ABC):
    """Abstract base class for language-specific fuzz target plugins.

    The ABC pattern (not Protocol) is used because TargetPlugin is meant to
    be explicitly subclassed by third-party plugins. This enforces the
    inheritance contract.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name (e.g., 'python', 'c', 'go')."""
        ...

    @property
    @abstractmethod
    def file_extensions(self) -> list[str]:
        """File extensions this plugin handles (e.g., ['.py'])."""
        ...

    @abstractmethod
    def discover_targets(self, path: str, allow_side_effects: bool = False) -> list[TargetInfo]:
        """Discover fuzzable targets in the given path."""
        ...

    @abstractmethod
    def execute(
        self, fuzz_input: FuzzInput, timeout_ms: int, collect_coverage: bool = True
    ) -> FuzzResult:
        """Execute a single fuzz input against the target."""
        ...

    @abstractmethod
    def validate_target(self, path: str) -> bool:
        """Check if the given path is a valid target for this plugin."""
        ...
