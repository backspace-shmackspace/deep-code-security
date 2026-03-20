"""C-specific AI response parser with tree-sitter-c AST harness validation.

Parses Claude JSON responses containing C harness programs into FuzzInput
objects. Performs a 7-step tree-sitter-c AST validation on each harness
before accepting it (Layer 1, host-side). Does NOT call validate_expression()
because C inputs are never eval()-ed; expression validation is Python-specific.

The sentinel args value ("'__c_harness__'",) is a properly quoted Python
string literal that passes ast.literal_eval() (producing "__c_harness__").
It is never evaluated as a function argument.

Security note: AST validation is defense-in-depth quality control, not the
security boundary. The container security policy (seccomp, network=none,
cap-drop=ALL) is the actual defense boundary.
"""

from __future__ import annotations

import json
import logging
import re

from deep_code_security.fuzzer.exceptions import InputValidationError
from deep_code_security.fuzzer.models import FuzzInput

__all__ = ["parse_c_ai_response", "validate_harness_source"]

logger = logging.getLogger(__name__)

# Maximum allowed harness source size (64 KB)
_MAX_HARNESS_BYTES = 64 * 1024

# Sentinel value placed in FuzzInput.args for C harnesses.
# A properly quoted Python string literal that passes ast.literal_eval().
_C_HARNESS_SENTINEL: tuple[str, ...] = ("'__c_harness__'",)

# Standard headers permitted in generated harnesses (Section 3a, step 6 of plan)
_ALLOWED_INCLUDES: frozenset[str] = frozenset(
    {
        "stdlib.h",
        "string.h",
        "stdint.h",
        "limits.h",
        "stdio.h",
        "math.h",
        "stdbool.h",
        "stddef.h",
        "errno.h",
        "float.h",
        "assert.h",
    }
)

# Function calls prohibited in generated harnesses (Section 3a, step 7 of plan)
_PROHIBITED_CALLS: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        "execl",
        "execle",
        "execlp",
        "execv",
        "execve",
        "execvp",
        "fork",
        "vfork",
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "dlopen",
        "dlsym",
        "ptrace",
        "kill",
        "raise",
        "signal",
        "sigaction",
    }
)


def parse_c_ai_response(
    response_text: str,
    valid_targets: set[str],
) -> list[FuzzInput]:
    """Parse an AI response containing C harnesses into FuzzInput objects.

    Applies strict target validation (same pattern as Python response_parser):
    if ANY input references an invalid target_function, the ENTIRE response
    is rejected via InputValidationError.

    Each harness_source is validated via tree-sitter-c AST analysis (7-step
    procedure from plan Section 3a). Harnesses that fail AST validation are
    skipped individually (not a whole-response rejection) with a warning.

    Does NOT call validate_expression() -- expression validation is Python-
    specific and C inputs are never eval()-ed.

    Args:
        response_text: Raw text returned by the AI API.
        valid_targets: Set of exact C function names that are valid targets.

    Returns:
        List of validated FuzzInput objects with metadata["harness_source"]
        and metadata["plugin"] == "c".

    Raises:
        InputValidationError: If any input references an invalid target_function.
    """
    json_text = _extract_json(response_text)
    if not json_text:
        logger.warning("No JSON found in C AI response")
        return []

    try:
        data = json.loads(json_text)
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse JSON from C AI response: %s", e)
        return []

    if not isinstance(data, dict) or "inputs" not in data:
        logger.warning("C AI response missing 'inputs' key")
        return []

    raw_inputs = data["inputs"]
    if not isinstance(raw_inputs, list):
        logger.warning("'inputs' is not a list in C AI response")
        return []

    # STRICT VALIDATION: Check all target_function values before processing any
    for i, raw_input in enumerate(raw_inputs):
        if not isinstance(raw_input, dict):
            continue
        target_fn = raw_input.get("target_function", "")
        if target_fn not in valid_targets:
            raise InputValidationError(
                f"Input {i}: target_function {target_fn!r} does not match any "
                f"discovered C target. Valid targets: {sorted(valid_targets)}. "
                "Rejecting entire response."
            )

    # Process each input individually
    fuzz_inputs: list[FuzzInput] = []
    for i, raw_input in enumerate(raw_inputs):
        if not isinstance(raw_input, dict):
            logger.warning("C input %d is not a dict, skipping", i)
            continue

        try:
            fuzz_input = _parse_single_c_input(raw_input, i)
            if fuzz_input is not None:
                fuzz_inputs.append(fuzz_input)
        except Exception as e:
            logger.warning("Failed to parse C input %d: %s, skipping", i, e)

    return fuzz_inputs


def validate_harness_source(harness_source: str) -> tuple[bool, str]:
    """Validate a C harness source string via tree-sitter-c AST analysis.

    Implements the 7-step validation procedure from plan Section 3a:
    1. Parse with tree-sitter-c; reject if parsing fails or has ERROR nodes.
    2. Size check: must be under 64 KB.
    3. Require exactly one main() function.
    4. Reject asm_statement / __asm__ / gnu_asm_expression nodes.
    5. Reject #define / #undef preprocessor directives.
    6. Validate #include directives: only allowed standard headers.
    7. Reject prohibited function calls.

    Args:
        harness_source: C source code to validate.

    Returns:
        Tuple of (is_valid: bool, reason: str). reason is empty on success.
    """
    # Step 2: Size check (before parsing -- fast path)
    if len(harness_source.encode("utf-8", errors="replace")) > _MAX_HARNESS_BYTES:
        return False, f"Harness source exceeds 64 KB limit ({len(harness_source)} chars)"

    # Step 1: Parse with tree-sitter-c
    try:
        import tree_sitter_c
        from tree_sitter import Language, Parser

        c_language = Language(tree_sitter_c.language())
        parser = Parser(c_language)
        tree = parser.parse(harness_source.encode("utf-8"))
    except Exception as e:
        return False, f"tree-sitter-c parse error: {e}"

    root = tree.root_node

    # Step 1 continued: reject trees with ERROR nodes
    if _has_node_type(root, "ERROR"):
        return False, "Harness source has syntax errors (ERROR node in AST)"

    # Step 3: Require exactly one main() function
    main_count = _count_function_definitions_named(root, "main")
    if main_count == 0:
        return False, "Harness has no main() function"
    if main_count > 1:
        return False, f"Harness has {main_count} main() functions (exactly one required)"

    # Step 4: Reject asm nodes
    asm_node_types = {"asm_statement", "gnu_asm_expression", "ms_based_clause"}
    for node_type in asm_node_types:
        if _has_node_type(root, node_type):
            return False, f"Harness contains prohibited AST node type: {node_type}"
    # Also check for __asm__ identifier pattern via text search (belt-and-suspenders)
    if b"__asm__" in harness_source.encode("utf-8") or b"__asm" in harness_source.encode(
        "utf-8"
    ):
        return False, "Harness contains __asm__ (inline assembly is prohibited)"

    # Step 5: Reject #define and #undef.
    # tree-sitter-c represents #define as preproc_def / preproc_function_def.
    # #undef is represented as a generic preproc_call node (not preproc_undef).
    for node in _walk(root):
        if node.type in ("preproc_def", "preproc_function_def", "preproc_undef"):
            return (
                False,
                f"Harness contains prohibited preprocessor directive ({node.type})",
            )
        if node.type == "preproc_call":
            # Check whether the directive child is #undef
            for child in node.children:
                if child.type == "preproc_directive":
                    directive_text = child.text
                    if isinstance(directive_text, bytes):
                        directive_text = directive_text.decode("utf-8")
                    if directive_text.strip() == "#undef":
                        return (
                            False,
                            "Harness contains prohibited preprocessor directive (#undef)",
                        )

    # Step 6: Validate #include directives
    for node in _walk(root):
        if node.type == "preproc_include":
            reason = _validate_include_node(node, harness_source)
            if reason:
                return False, reason

    # Step 7: Reject prohibited function calls
    for node in _walk(root):
        if node.type == "call_expression":
            reason = _check_call_expression(node, harness_source)
            if reason:
                return False, reason

    return True, ""


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _parse_single_c_input(raw_input: dict, index: int) -> FuzzInput | None:
    """Parse a single raw C input dict into a FuzzInput.

    Args:
        raw_input: Dict from the parsed AI JSON response.
        index: Position in the inputs list (for log messages).

    Returns:
        FuzzInput on success, None if validation fails.
    """
    target_function = raw_input.get("target_function", "")
    harness_source = raw_input.get("harness_source", "")
    rationale = raw_input.get("rationale", "")

    if not isinstance(harness_source, str) or not harness_source.strip():
        logger.warning("C input %d: missing or empty harness_source, skipping", index)
        return None

    is_valid, reason = validate_harness_source(harness_source)
    if not is_valid:
        logger.warning(
            "C input %d: harness_source failed AST validation: %s, skipping", index, reason
        )
        return None

    return FuzzInput(
        target_function=target_function,
        args=_C_HARNESS_SENTINEL,
        kwargs={},
        metadata={
            "harness_source": harness_source,
            "rationale": rationale,
            "source": "ai",
            "plugin": "c",
        },
    )


def _extract_json(text: str) -> str | None:
    """Extract JSON from a response that may contain markdown code blocks.

    Args:
        text: Raw response text.

    Returns:
        Extracted JSON string or None.
    """
    code_block_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if code_block_match:
        return code_block_match.group(1)

    json_match = re.search(r"\{.*\}", text, re.DOTALL)
    if json_match:
        return json_match.group(0)

    return None


def _walk(node: object) -> list[object]:
    """Walk all nodes in a tree-sitter AST (breadth-first).

    Args:
        node: Root tree-sitter Node.

    Returns:
        Flat list of all nodes in the subtree.
    """
    result = []
    queue = [node]
    while queue:
        current = queue.pop(0)
        result.append(current)
        queue.extend(current.children)
    return result


def _has_node_type(root: object, node_type: str) -> bool:
    """Return True if any node in the tree has the given type.

    Args:
        root: Root tree-sitter Node.
        node_type: The node type string to search for.

    Returns:
        True if found, False otherwise.
    """
    for node in _walk(root):
        if node.type == node_type:
            return True
    return False


def _count_function_definitions_named(root: object, name: str) -> int:
    """Count function_definition nodes whose declarator name matches `name`.

    Args:
        root: Root tree-sitter Node.
        name: Function name to count.

    Returns:
        Count of matching function definitions.
    """
    count = 0
    for node in _walk(root):
        if node.type == "function_definition":
            fn_name = _extract_function_name(node)
            if fn_name == name:
                count += 1
    return count


def _extract_function_name(func_def_node: object) -> str | None:
    """Extract the function name from a function_definition node.

    Handles both simple declarators and pointer declarators:
    - int foo(void) -> declarator is function_declarator -> identifier "foo"
    - int *foo(void) -> declarator is pointer_declarator -> function_declarator -> identifier

    Args:
        func_def_node: A tree-sitter function_definition node.

    Returns:
        Function name string or None if not extractable.
    """
    # Walk direct children of function_definition for the declarator
    for child in func_def_node.children:
        if child.type in ("function_declarator", "pointer_declarator"):
            return _find_declarator_name(child)
    return None


def _find_declarator_name(node: object) -> str | None:
    """Recursively find the identifier inside a declarator chain.

    Args:
        node: A tree-sitter declarator node.

    Returns:
        Identifier text or None.
    """
    for child in node.children:
        if child.type == "identifier":
            return child.text.decode("utf-8") if isinstance(child.text, bytes) else child.text
        if child.type in ("function_declarator", "pointer_declarator"):
            result = _find_declarator_name(child)
            if result:
                return result
    return None


def _validate_include_node(include_node: object, source: str) -> str:
    """Validate a preproc_include node against the allowed header list.

    Args:
        include_node: A tree-sitter preproc_include node.
        source: Full harness source (for extracting text).

    Returns:
        Error reason string if invalid, empty string if valid.
    """
    # The include node's text looks like: #include <stdlib.h>  or  #include "foo.h"
    # Extract the header name from child nodes
    for child in include_node.children:
        if child.type in ("system_lib_string", "string_literal"):
            raw = child.text
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            # Strip surrounding < > or " "
            header = raw.strip().lstrip("<\"").rstrip(">\"")
            if header not in _ALLOWED_INCLUDES:
                return (
                    f"Harness includes prohibited header: {raw!r}. "
                    f"Allowed: {sorted(_ALLOWED_INCLUDES)}"
                )
            return ""
        if child.type == "identifier":
            # Computed include e.g. #include MACRO -- rejected by #define check above,
            # but guard here as well
            raw = child.text
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            return f"Harness uses computed #include (identifier: {raw!r})"
    return ""


def _check_call_expression(call_node: object, source: str) -> str:
    """Check a call_expression node for prohibited function names.

    Only catches direct identifier calls (e.g., system("cmd")).
    Function pointer aliasing is NOT caught here (documented limitation);
    the container security policy is the defense for that case.

    Args:
        call_node: A tree-sitter call_expression node.
        source: Full harness source (unused, kept for interface consistency).

    Returns:
        Error reason string if prohibited call found, empty string otherwise.
    """
    # call_expression children: function (identifier or field_expression), arguments
    for child in call_node.children:
        if child.type == "identifier":
            name = child.text
            if isinstance(name, bytes):
                name = name.decode("utf-8")
            if name in _PROHIBITED_CALLS:
                return f"Harness calls prohibited function: {name!r}"
            break  # function identifier is the first relevant child
    return ""
