"""Vulnerable Python code with SQL injection — for testing purposes ONLY.

This file intentionally contains security vulnerabilities for testing the Hunter.
Do NOT use this pattern in production code.
"""

import sqlite3
import sys

from flask import request


def get_user_by_name_vulnerable(db_path: str) -> list:
    """Vulnerable function: SQL injection via string concatenation.

    The user input from request.form is directly concatenated into the SQL query.
    Hunter should detect: source=request.form, sink=cursor.execute, CWE-89.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # VULNERABLE: Direct string concatenation with user input
    user_input = request.form["username"]
    query = "SELECT * FROM users WHERE name='" + user_input + "'"
    cursor.execute(query)  # noqa: S608 — intentionally vulnerable for testing

    results = cursor.fetchall()
    conn.close()
    return results


def search_products_vulnerable(db_path: str) -> list:
    """Another SQL injection: using format string with user input."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    search_term = request.args["q"]
    # VULNERABLE: Format string with user input
    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    cursor.execute(query)  # noqa: S608 — intentionally vulnerable for testing

    results = cursor.fetchall()
    conn.close()
    return results


def get_user_cli(db_path: str) -> list:
    """SQL injection from CLI arguments."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    user_id = sys.argv[1]
    # VULNERABLE: Direct CLI arg concatenation
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)  # noqa: S608 — intentionally vulnerable for testing

    results = cursor.fetchall()
    conn.close()
    return results
