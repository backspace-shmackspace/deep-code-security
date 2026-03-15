"""Unit tests for the select_backend() factory function."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from deep_code_security.fuzzer.execution.sandbox import (
    ContainerBackend,
    SubprocessBackend,
    select_backend,
)


def test_returns_subprocess_when_container_unavailable() -> None:
    """When ContainerBackend is unavailable and require_container=False, return SubprocessBackend."""
    with patch.object(ContainerBackend, "is_available", return_value=False):
        backend = select_backend(require_container=False)
    assert isinstance(backend, SubprocessBackend)


def test_returns_container_when_available() -> None:
    """When ContainerBackend is available, select_backend returns ContainerBackend."""
    with patch.object(ContainerBackend, "is_available", return_value=True):
        backend = select_backend(require_container=False)
    assert isinstance(backend, ContainerBackend)


def test_raises_when_require_container_and_unavailable() -> None:
    """When require_container=True and ContainerBackend unavailable, raise RuntimeError."""
    with patch.object(ContainerBackend, "is_available", return_value=False):
        with pytest.raises(RuntimeError, match="ContainerBackend is required but not available"):
            select_backend(require_container=True)


def test_returns_container_when_require_container_and_available() -> None:
    """When require_container=True and ContainerBackend is available, return ContainerBackend."""
    with patch.object(ContainerBackend, "is_available", return_value=True):
        backend = select_backend(require_container=True)
    assert isinstance(backend, ContainerBackend)
