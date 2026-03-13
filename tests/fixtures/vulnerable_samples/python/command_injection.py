"""Vulnerable Python code with command injection — for testing purposes ONLY.

This file intentionally contains security vulnerabilities for testing the Hunter.
Do NOT use this pattern in production code.
"""

import os
import sys

from flask import request


def ping_host_vulnerable() -> str:
    """Vulnerable: OS command injection via request.form."""
    host = request.form["host"]
    # VULNERABLE: User input directly concatenated into shell command
    result = os.system("ping -c 1 " + host)  # noqa: S605 — intentionally vulnerable
    return str(result)


def run_command_vulnerable() -> str:
    """Vulnerable: Command injection from sys.argv."""
    command = sys.argv[1]
    # VULNERABLE: CLI arg used directly in shell command
    os.system(command)  # noqa: S605 — intentionally vulnerable
    return "done"


def process_file_vulnerable() -> str:
    """Vulnerable: Command injection via input()."""
    filename = input("Enter filename: ")
    # VULNERABLE: User input from stdin used in shell command
    os.system("cat " + filename)  # noqa: S605 — intentionally vulnerable
    return "done"
