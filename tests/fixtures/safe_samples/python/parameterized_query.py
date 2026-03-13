"""Safe Python code using parameterized queries — should produce ZERO findings.

This file demonstrates the secure pattern that the Hunter should NOT flag.
"""

import sqlite3

from flask import request


def get_user_by_name_safe(db_path: str) -> list:
    """Safe: parameterized query prevents SQL injection.

    Hunter should NOT detect this as vulnerable because the query uses
    a placeholder (?) and passes user input separately.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    user_input = request.form["username"]
    # SAFE: Parameterized query — user input cannot modify SQL structure
    query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (user_input,))

    results = cursor.fetchall()
    conn.close()
    return results


def search_products_safe(db_path: str) -> list:
    """Safe: named parameter syntax."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    search_term = request.args["q"]
    # SAFE: Named placeholder
    cursor.execute(
        "SELECT * FROM products WHERE name LIKE :term",
        {"term": f"%{search_term}%"},
    )

    results = cursor.fetchall()
    conn.close()
    return results


def get_hardcoded_users(db_path: str) -> list:
    """Safe: no user input involved, fully static query."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # SAFE: No user input, static query only
    cursor.execute("SELECT * FROM users WHERE active = 1")
    results = cursor.fetchall()
    conn.close()
    return results
