"""Vulnerable Python code with code injection — for testing purposes ONLY.

This file intentionally contains security vulnerabilities for testing the Hunter.
Do NOT use this pattern in production code.
"""

from flask import request


def evaluate_expression_vulnerable() -> str:
    """Vulnerable: Code injection via eval() with user input."""
    user_expr = request.form["expression"]
    # VULNERABLE: Direct eval of user input allows arbitrary code execution
    result = eval(user_expr)  # noqa: S307 — intentionally vulnerable
    return str(result)


def execute_code_vulnerable() -> str:
    """Vulnerable: Code injection via exec() with user input."""
    code = request.args.get("code", "")
    # VULNERABLE: Direct exec of user-controlled code
    exec(code)  # noqa: S102 — intentionally vulnerable
    return "executed"
