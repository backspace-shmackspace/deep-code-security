"""Safe Python code for command execution — should produce ZERO confirmed findings.

This file demonstrates secure command execution patterns.
"""

import os
import subprocess
from pathlib import Path

from flask import request


def list_directory_safe() -> list[str]:
    """Safe: use Python built-in instead of shell command."""
    user_path = request.form.get("path", "/tmp")
    # SAFE: Python's os.listdir — no shell involved
    base = Path("/var/www/uploads").resolve()
    requested = (base / user_path).resolve()
    if not str(requested).startswith(str(base)):
        raise PermissionError("Access denied")
    return os.listdir(requested)


def ping_host_safe(host: str) -> bool:
    """Safe: subprocess with list arguments (no shell interpolation)."""
    # SAFE: List form — user input cannot inject shell metacharacters
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        timeout=5,
        check=False,
    )
    return result.returncode == 0


def get_file_safe(filename: str) -> str:
    """Safe: explicit path validation before file access."""
    base_dir = Path("/var/www/static").resolve()
    requested = (base_dir / filename).resolve()
    # SAFE: Validate path is within allowed directory
    if not str(requested).startswith(str(base_dir)):
        raise PermissionError("Path traversal detected")
    return requested.read_text()
