"""CWE-to-fuzzing-input guidance map.

Maps CWE IDs to plain-text fuzzing strategy hints that are injected into
the AI prompt to guide input generation toward the discovered vulnerability pattern.

This is a static map, not a registry YAML file. The guidance strings are
intentionally generic -- the AI adapts them to the specific function context.
"""

from __future__ import annotations

__all__ = [
    "CWE_FUZZ_GUIDANCE",
    "get_guidance_for_cwes",
]

CWE_FUZZ_GUIDANCE: dict[str, str] = {
    "CWE-78": (
        "Generate inputs containing shell metacharacters: "
        "semicolons (;), pipes (|), backticks (`), "
        "$() command substitution, && and || chains, "
        "newlines, and path traversal sequences."
    ),
    "CWE-89": (
        "Generate inputs containing SQL injection payloads: "
        "single quotes ('), double quotes (\"), "
        "comment sequences (-- , #), UNION SELECT, "
        "OR 1=1, and tautologies."
    ),
    "CWE-94": (
        "Generate inputs that could be interpreted as code: "
        "__import__('os').system('id'), exec(), eval(), "
        "compile(), and code objects."
    ),
    "CWE-22": (
        "Generate inputs containing path traversal sequences: "
        "../, ..\\, /etc/passwd, C:\\, %2e%2e%2f, "
        "null bytes, and symlink paths."
    ),
    "CWE-79": (
        "Generate inputs containing HTML/JavaScript injection: "
        "<script>, <img onerror=>, javascript:, "
        "event handlers, and encoded variants."
    ),
}


def get_guidance_for_cwes(cwes: list[str]) -> str:
    """Look up and combine fuzzing guidance strings for a list of CWE IDs.

    Only CWEs present in CWE_FUZZ_GUIDANCE produce output. Unknown CWEs
    are silently ignored. If no CWEs are recognized, returns an empty string.

    Args:
        cwes: List of CWE ID strings (e.g., ["CWE-78", "CWE-89"]).

    Returns:
        Combined guidance string, or empty string if none found.
    """
    parts: list[str] = []
    seen: set[str] = set()
    for cwe in cwes:
        guidance = CWE_FUZZ_GUIDANCE.get(cwe, "")
        if guidance and cwe not in seen:
            parts.append(f"For {cwe}: {guidance}")
            seen.add(cwe)
    return "\n".join(parts)
