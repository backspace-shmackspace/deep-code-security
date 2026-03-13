"""Path validation with allowlist enforcement, symlink resolution, and traversal rejection."""

from __future__ import annotations

import os
import stat
from pathlib import Path

__all__ = ["validate_path", "PathValidationError"]


class PathValidationError(Exception):
    """Raised when a path fails validation."""


def validate_path(path: str, allowed_paths: list[str]) -> str:
    """Validate a filesystem path against the allowlist.

    Validation steps:
    1. Reject paths containing '..' (before resolution)
    2. Resolve symlinks via os.path.realpath()
    3. Verify the resolved path is within one of the allowed paths
    4. Reject special files (/proc, /sys, /dev, block devices, named pipes)

    Args:
        path: The path to validate.
        allowed_paths: List of allowed base directories.

    Returns:
        The resolved absolute path string if validation passes.

    Raises:
        PathValidationError: If the path fails any validation check.
    """
    if not path:
        raise PathValidationError("Empty path is not allowed")

    # Reject paths with '..' components before resolution
    # (defense in depth — realpath would handle it, but we want explicit rejection)
    normalized = os.path.normpath(path)
    if ".." in Path(normalized).parts:
        raise PathValidationError(
            f"Path traversal detected: '..' components not allowed in {path!r}"
        )

    # Resolve symlinks
    try:
        resolved = os.path.realpath(path)
    except OSError as e:
        raise PathValidationError(f"Cannot resolve path {path!r}: {e}") from e

    resolved_path = Path(resolved)

    # Reject special filesystem paths
    # /private/etc is the macOS realpath target for the /etc symlink
    special_prefixes = ["/proc", "/sys", "/dev", "/etc", "/private/etc"]
    for prefix in special_prefixes:
        if resolved.startswith(prefix):
            raise PathValidationError(
                f"Access to special filesystem path denied: {resolved!r}"
            )

    # Reject block devices and named pipes (if the path exists)
    if resolved_path.exists():
        try:
            path_stat = resolved_path.stat()
            mode = path_stat.st_mode
            if stat.S_ISBLK(mode):
                raise PathValidationError(
                    f"Access to block device denied: {resolved!r}"
                )
            if stat.S_ISFIFO(mode):
                raise PathValidationError(
                    f"Access to named pipe denied: {resolved!r}"
                )
        except OSError as e:
            raise PathValidationError(f"Cannot stat path {path!r}: {e}") from e

    # Verify path is within at least one allowed path
    if not allowed_paths:
        raise PathValidationError(
            "No allowed paths configured (DCS_ALLOWED_PATHS is empty)"
        )

    allowed = False
    for allowed_base in allowed_paths:
        try:
            allowed_resolved = os.path.realpath(allowed_base)
        except OSError:
            continue
        # Path must be equal to or a subdirectory of the allowed base
        if resolved == allowed_resolved or resolved.startswith(allowed_resolved + os.sep):
            allowed = True
            break

    if not allowed:
        raise PathValidationError(
            f"Path {path!r} is not within any allowed directory. "
            f"Allowed paths: {allowed_paths}"
        )

    return resolved
