"""Remediation guidance generation.

Produces vulnerability explanations, fix patterns, and illustrative code examples.
Does NOT produce apply-ready diffs or patches.
"""

from __future__ import annotations

import logging
import re

from deep_code_security.architect.models import RemediationGuidance
from deep_code_security.auditor.models import VerifiedFinding

__all__ = ["GuidanceGenerator", "generate_guidance"]

logger = logging.getLogger(__name__)

# Guidance templates by (cwe, language) -> guidance data
_GUIDANCE_TEMPLATES: dict[tuple[str, str], dict] = {
    # --- SQL Injection ---
    ("CWE-89", "python"): {
        "vulnerability_explanation": (
            "SQL injection (CWE-89) occurs when user-supplied input is directly concatenated into "
            "a SQL query string without sanitization. An attacker can manipulate the query structure "
            "to bypass authentication, exfiltrate data, modify records, or execute administrative "
            "database operations. This is one of the most critical and commonly exploited web "
            "application vulnerabilities (OWASP Top 10 #3)."
        ),
        "fix_pattern": (
            "Use parameterized queries (prepared statements) instead of string concatenation. "
            "The database driver keeps SQL structure and data strictly separated, making injection "
            "structurally impossible regardless of the input content."
        ),
        "code_example": """\
# VULNERABLE (do not use):
# query = "SELECT * FROM users WHERE name='" + user_input + "'"
# cursor.execute(query)

# SAFE — parameterized query (works with sqlite3, psycopg2, pymysql, etc.):
query = "SELECT * FROM users WHERE name = ?"
cursor.execute(query, (user_input,))

# For named parameters (psycopg2, SQLAlchemy):
query = "SELECT * FROM users WHERE name = %(name)s"
cursor.execute(query, {"name": user_input})

# With SQLAlchemy ORM (preferred for complex queries):
from sqlalchemy import select, text
results = session.execute(select(User).where(User.name == user_input)).scalars().all()
""",
        "effort_estimate": "trivial",
        "test_suggestions": [
            "Test with SQL metacharacters: ' OR '1'='1', ; DROP TABLE users; --",
            "Verify parameterized queries pass input as data, not SQL structure",
            "Run sqlmap or similar tool after fix to confirm no injection points remain",
            "Add input validation that rejects inputs with unexpected characters",
        ],
        "references": [
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    ("CWE-89", "go"): {
        "vulnerability_explanation": (
            "SQL injection (CWE-89) in Go occurs when string concatenation builds SQL queries "
            "with user-controlled values. The database/sql package supports parameterized queries "
            "natively, and all SQL operations should use placeholder syntax."
        ),
        "fix_pattern": (
            "Use placeholder parameters ($1, ?, or @name) in database/sql calls. "
            "Pass user data as separate arguments, never as part of the query string."
        ),
        "code_example": """\
// VULNERABLE (do not use):
// query := "SELECT * FROM users WHERE name='" + userInput + "'"
// rows, err := db.Query(query)

// SAFE — parameterized query:
rows, err := db.Query("SELECT * FROM users WHERE name = $1", userInput)
if err != nil {
    return err
}
defer rows.Close()

// With multiple parameters:
rows, err = db.Query(
    "SELECT * FROM orders WHERE user_id = $1 AND status = $2",
    userID, status,
)
""",
        "effort_estimate": "trivial",
        "test_suggestions": [
            "Test with SQL metacharacters: ' OR '1'='1'; --",
            "Verify query parameters are passed as separate arguments",
            "Use go-sqlmock for unit testing database interactions",
        ],
        "references": [
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://pkg.go.dev/database/sql#DB.Query",
        ],
    },
    # --- OS Command Injection ---
    ("CWE-78", "python"): {
        "vulnerability_explanation": (
            "OS command injection (CWE-78) occurs when user-controlled input reaches a system "
            "command execution function (os.system, subprocess.call, etc.) without proper "
            "sanitization. An attacker can append additional commands (using ; & | etc.) to "
            "execute arbitrary code with the privileges of the application process. This can "
            "lead to complete system compromise."
        ),
        "fix_pattern": (
            "Avoid passing user input to shell commands. Prefer Python-native implementations "
            "of the required functionality. If a subprocess is truly necessary, use "
            "subprocess.run() with a list of arguments (never shell=True) and validate each "
            "argument independently. Use shlex.quote() as a last resort for shell escaping."
        ),
        "code_example": """\
# VULNERABLE (do not use):
# os.system("ls " + user_input)
# subprocess.run("ls " + user_input, shell=True)

# SAFE option 1 — use Python built-ins instead of shell commands:
import os
files = os.listdir(user_path)  # No shell involved

# SAFE option 2 — subprocess with list arguments (no shell interpolation):
import subprocess
result = subprocess.run(
    ["ls", "-la", user_path],  # List form, never shell=True
    capture_output=True,
    text=True,
    check=True,
)

# SAFE option 3 — if shell is truly required, validate and quote:
import shlex
import subprocess
safe_arg = shlex.quote(user_input)  # Escapes shell metacharacters
result = subprocess.run(f"ls -la {safe_arg}", shell=True, ...)
# Note: shlex.quote is a defense-in-depth measure; list form is preferred
""",
        "effort_estimate": "small",
        "test_suggestions": [
            "Test with shell metacharacters: ; id, && id, | id, $(id), `id`",
            "Verify subprocess calls use list-form arguments",
            "Confirm no shell=True is used with user-controlled data",
            "Consider using Python-native file/directory operations instead",
        ],
        "references": [
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ],
    },
    ("CWE-78", "go"): {
        "vulnerability_explanation": (
            "OS command injection (CWE-78) in Go occurs when user input is passed to exec.Command "
            "or similar functions, especially when combined with 'sh -c' or similar shell invocations. "
            "Attackers can inject shell metacharacters to execute arbitrary commands."
        ),
        "fix_pattern": (
            "Pass each command argument as a separate string to exec.Command. "
            "Never use 'sh -c' with user-controlled strings. "
            "Consider using Go's standard library instead of shelling out."
        ),
        "code_example": """\
// VULNERABLE (do not use):
// cmd := exec.Command("sh", "-c", "ls " + userInput)

// SAFE — separate arguments, no shell interpolation:
cmd := exec.Command("ls", "-la", userPath)
output, err := cmd.Output()

// SAFE — use Go standard library instead of shell commands:
import "os"
entries, err := os.ReadDir(userPath)

// If you must validate input:
import "regexp"
if !regexp.MustCompile(`^[a-zA-Z0-9/_.-]+$`).MatchString(userPath) {
    return errors.New("invalid path")
}
""",
        "effort_estimate": "small",
        "test_suggestions": [
            "Test with shell metacharacters: ; id, && id, | id",
            "Verify exec.Command receives individual arguments, not a shell string",
            "Check for 'sh -c' patterns with user input",
        ],
        "references": [
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://pkg.go.dev/os/exec#Command",
        ],
    },
    # --- Code Injection ---
    ("CWE-94", "python"): {
        "vulnerability_explanation": (
            "Code injection (CWE-94) occurs when user-controlled input is passed to eval() or "
            "exec(), allowing an attacker to execute arbitrary Python code with the permissions "
            "of the application. This is one of the most severe vulnerability types and can lead "
            "to complete application compromise."
        ),
        "fix_pattern": (
            "Never use eval() or exec() with user-supplied input. "
            "Refactor the functionality to use data-driven approaches instead. "
            "For configuration, use JSON/YAML parsing. For mathematical expressions, "
            "use ast.literal_eval() (safe subset) or a dedicated math expression library."
        ),
        "code_example": """\
# VULNERABLE (do not use):
# result = eval(user_expression)

# SAFE option 1 — ast.literal_eval for simple data structures:
import ast
try:
    result = ast.literal_eval(user_input)  # Safe: only literals, no function calls
except (ValueError, SyntaxError):
    raise ValueError("Invalid input")

# SAFE option 2 — dedicated math library for arithmetic:
# pip install simpleeval
from simpleeval import simple_eval
result = simple_eval(user_expression)

# SAFE option 3 — data-driven config instead of eval:
import json
config = json.loads(user_config_string)

# SAFE option 4 — restrict to known values with a lookup table:
OPERATIONS = {
    "add": lambda x, y: x + y,
    "subtract": lambda x, y: x - y,
}
op = OPERATIONS.get(user_operation)
if op is None:
    raise ValueError(f"Unknown operation: {user_operation}")
result = op(x, y)
""",
        "effort_estimate": "medium",
        "test_suggestions": [
            "Test with Python code: __import__('os').system('id')",
            "Test with attribute access: ().__class__.__base__.__subclasses__()",
            "Verify eval/exec are completely removed from user-input code paths",
        ],
        "references": [
            "https://cwe.mitre.org/data/definitions/94.html",
            "https://owasp.org/www-community/attacks/Code_Injection",
        ],
    },
    # --- Path Traversal ---
    ("CWE-22", "python"): {
        "vulnerability_explanation": (
            "Path traversal (CWE-22) occurs when user-controlled input is used to construct "
            "file paths without proper validation. An attacker can use ../ sequences to "
            "navigate outside the intended directory and access sensitive files like "
            "/etc/passwd, .env files, or application secrets."
        ),
        "fix_pattern": (
            "Validate that the resolved path is within the expected base directory. "
            "Use pathlib.Path.resolve() to resolve all symlinks and .. components, "
            "then verify the resolved path starts with the allowed base directory."
        ),
        "code_example": """\
from pathlib import Path

ALLOWED_BASE = Path("/var/www/uploads").resolve()

def safe_open_file(user_filename: str) -> str:
    # Resolve the full path (resolves .., symlinks, etc.)
    requested = (ALLOWED_BASE / user_filename).resolve()

    # Verify the resolved path is within the allowed base
    if not str(requested).startswith(str(ALLOWED_BASE)):
        raise PermissionError(f"Access denied: {user_filename!r}")

    # Additional validation: reject suspicious patterns
    if ".." in user_filename or user_filename.startswith("/"):
        raise ValueError(f"Invalid filename: {user_filename!r}")

    return requested.read_text()
""",
        "effort_estimate": "small",
        "test_suggestions": [
            "Test with: ../../../etc/passwd, ../../.env, ..\\..\\windows\\system32",
            "Test URL-encoded traversal: %2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "Verify resolved path always starts with allowed base directory",
            "Test with symlinks pointing outside the base directory",
        ],
        "references": [
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://owasp.org/www-community/attacks/Path_Traversal",
        ],
    },
    ("CWE-22", "go"): {
        "vulnerability_explanation": (
            "Path traversal (CWE-22) in Go allows attackers to use ../ sequences in "
            "user-supplied paths to access files outside the intended directory."
        ),
        "fix_pattern": (
            "Use filepath.Clean and verify the cleaned path starts with the allowed base. "
            "The os.OpenFile or http.FileServer with http.Dir already handles some cases, "
            "but explicit validation is required for custom file serving."
        ),
        "code_example": """\
import (
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

const allowedBase = "/var/www/uploads"

func safeOpenFile(userPath string) (*os.File, error) {
    // Clean the path to resolve .. components
    cleaned := filepath.Clean(filepath.Join(allowedBase, userPath))

    // Verify it's still within the allowed base
    if !strings.HasPrefix(cleaned, allowedBase+"/") {
        return nil, fmt.Errorf("access denied: %q", userPath)
    }

    return os.Open(cleaned)
}
""",
        "effort_estimate": "small",
        "test_suggestions": [
            "Test with: ../../../etc/passwd, ..\\..\\etc\\passwd",
            "Verify filepath.Clean removes all .. sequences",
            "Test that paths outside allowedBase are rejected",
        ],
        "references": [
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://pkg.go.dev/path/filepath#Clean",
        ],
    },
    # --- Buffer Overflow (C) ---
    ("CWE-120", "c"): {
        "vulnerability_explanation": (
            "Buffer overflow (CWE-120) occurs when data is copied to a buffer without checking "
            "if it fits, overwriting adjacent memory. This can corrupt data, crash the program, "
            "or be exploited to execute arbitrary code. Unsafe functions like strcpy, strcat, "
            "and sprintf do not check destination buffer sizes."
        ),
        "fix_pattern": (
            "Replace unsafe functions with bounded equivalents: strcpy -> strncpy/strlcpy, "
            "strcat -> strncat/strlcat, sprintf -> snprintf. Always specify the maximum "
            "length including space for the null terminator."
        ),
        "code_example": """\
/* VULNERABLE (do not use): */
/* char buf[64]; strcpy(buf, user_input); */

/* SAFE — bounded copy: */
char buf[64];
strncpy(buf, user_input, sizeof(buf) - 1);
buf[sizeof(buf) - 1] = '\\0';  /* Ensure null termination */

/* SAFE — snprintf for formatted output: */
char msg[256];
snprintf(msg, sizeof(msg), "Hello, %s!", user_input);

/* PREFERRED — use strlcpy if available (BSD/Linux with libbsd): */
#include <bsd/string.h>
strlcpy(buf, user_input, sizeof(buf));  /* Always null-terminates */
""",
        "effort_estimate": "small",
        "test_suggestions": [
            "Test with inputs longer than the buffer size",
            "Use AddressSanitizer (-fsanitize=address) during testing",
            "Run valgrind to detect buffer overflows at runtime",
            "Consider using static analysis tools (cppcheck, clang-tidy)",
        ],
        "references": [
            "https://cwe.mitre.org/data/definitions/120.html",
            "https://wiki.sei.cmu.edu/confluence/display/c/STR31-C",
        ],
    },
}

# Default guidance template for unknown CWE/language combinations
_DEFAULT_GUIDANCE: dict = {
    "vulnerability_explanation": (
        "A potential security vulnerability was detected in this code path. "
        "The taint analysis identified that user-controlled input may flow to a "
        "security-sensitive operation without adequate sanitization or validation."
    ),
    "fix_pattern": (
        "Validate and sanitize all user-controlled input before using it in "
        "security-sensitive operations. Apply the principle of least privilege "
        "and prefer safe API alternatives where available."
    ),
    "code_example": "# Review the taint path and apply appropriate input validation.",
    "effort_estimate": "medium",
    "test_suggestions": [
        "Test with boundary values and unexpected input types",
        "Test with special characters relevant to the vulnerability type",
        "Add regression tests to prevent reintroduction",
    ],
    "references": [
        "https://owasp.org/www-community/attacks/",
        "https://cwe.mitre.org/",
    ],
}


class GuidanceGenerator:
    """Generates remediation guidance for verified findings."""

    def generate(self, finding: VerifiedFinding) -> RemediationGuidance:
        """Generate remediation guidance for a verified finding.

        Args:
            finding: The verified finding to generate guidance for.

        Returns:
            RemediationGuidance with explanation, fix pattern, and code example.
        """
        return generate_guidance(finding)


def generate_guidance(finding: VerifiedFinding) -> RemediationGuidance:
    """Generate remediation guidance for a verified finding.

    Args:
        finding: The verified finding.

    Returns:
        RemediationGuidance with explanation, fix pattern, and code example.
    """
    raw = finding.finding
    cwe = _extract_cwe(raw.vulnerability_class)
    language = raw.language.lower()

    # Look up guidance template
    template = (
        _GUIDANCE_TEMPLATES.get((cwe, language))
        or _GUIDANCE_TEMPLATES.get((cwe, "python"))  # Fallback to Python template
        or _DEFAULT_GUIDANCE
    )

    return RemediationGuidance(
        finding_id=raw.id,
        vulnerability_explanation=template["vulnerability_explanation"],
        fix_pattern=template["fix_pattern"],
        code_example=template["code_example"],
        effort_estimate=template.get("effort_estimate", "medium"),
        test_suggestions=list(template.get("test_suggestions", [])),
        references=list(template.get("references", [])),
    )


def _extract_cwe(vulnerability_class: str) -> str:
    """Extract CWE identifier from vulnerability class string.

    Args:
        vulnerability_class: e.g., "CWE-78: OS Command Injection"

    Returns:
        CWE identifier (e.g., "CWE-78") or "DEFAULT".
    """
    match = re.match(r"(CWE-\d+)", vulnerability_class)
    if match:
        return match.group(1)
    return "DEFAULT"
