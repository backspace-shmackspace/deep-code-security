"""Shared AST-based expression validation.

This module is imported by both response_parser.py (Layer 1: before
serialization to IPC JSON) and _worker.py (Layer 2: before eval()).
This dual-layer defense ensures tampered corpus files or direct worker
invocation cannot bypass validation.

See Security Deviation SD-02 in the merge plan for full rationale.
"""

from __future__ import annotations

import ast
import logging

__all__ = ["SAFE_NAMES", "validate_expression"]

logger = logging.getLogger(__name__)

# Allowed builtins for expression validation.
# memoryview is intentionally excluded (unnecessary for data construction
# and provides a potential memory probing vector).
SAFE_NAMES = frozenset(
    {
        "float",
        "int",
        "str",
        "bytes",
        "bytearray",
        "dict",
        "list",
        "set",
        "frozenset",
        "tuple",
        "complex",
        "range",
        "bool",
        "None",
        "True",
        "False",
    }
)


def validate_expression(expr_str: str) -> bool:
    """Validate that an expression string is safe to evaluate.

    Tries ast.literal_eval first; if that fails, uses an allowlist of
    permitted AST node types. Only nodes in ALLOWED_NODE_TYPES are
    permitted -- everything else is rejected.

    Args:
        expr_str: Python expression string to validate.

    Returns:
        True if the expression is safe, False otherwise.
    """
    if not isinstance(expr_str, str):
        return False

    # Try ast.literal_eval first (safest)
    try:
        ast.literal_eval(expr_str)
        return True
    except (ValueError, SyntaxError):
        pass

    # Parse and validate via an allowlist of permitted node types.
    try:
        tree = ast.parse(expr_str, mode="eval")
    except SyntaxError:
        return False

    # Allowlist: only these AST node types are permitted anywhere in the tree.
    # Anything not on this list -- Lambda, IfExp, NamedExpr, Attribute,
    # Subscript, JoinedStr (f-string), Yield, Await, etc. -- is rejected.
    allowed_node_types = (
        ast.Expression,  # root node of mode="eval" parse
        ast.Constant,  # literals: int, float, str, bytes, bool, None
        ast.List,  # [...]
        ast.Tuple,  # (...)
        ast.Dict,  # {...: ...}
        ast.Set,  # {...}
        ast.Name,  # bare names -- further restricted below
        ast.Call,  # func(...) -- further restricted below
        ast.UnaryOp,  # -x, +x, ~x
        ast.USub,  # unary minus operator
        ast.UAdd,  # unary plus operator
        ast.Invert,  # ~ operator
        ast.BinOp,  # x + y, x * y, etc.
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.FloorDiv,
        ast.Mod,
        ast.Pow,
        ast.LShift,
        ast.RShift,
        ast.BitOr,
        ast.BitXor,
        ast.BitAnd,
        ast.Starred,  # *args in call/collection unpacking
        # Expression-context nodes produced by the parser for every Name/List/etc.
        ast.Load,  # read-context on Name, List, Tuple, Set nodes
    )

    for node in ast.walk(tree):
        if not isinstance(node, allowed_node_types):
            logger.warning(
                "Expression contains disallowed AST node %s: %r",
                type(node).__name__,
                expr_str,
            )
            return False

        # Additional per-node checks
        if isinstance(node, ast.Name):
            # Only names from the safe set are allowed (no __dunder__, no builtins)
            if node.id not in SAFE_NAMES:
                logger.warning(
                    "Expression references disallowed name %r in %r",
                    node.id,
                    expr_str,
                )
                return False

        elif isinstance(node, ast.Call):
            # Only calls to safe ast.Name functions are allowed -- no attribute calls
            if not isinstance(node.func, ast.Name):
                logger.warning(
                    "Expression contains non-name call (e.g., attribute call): %r",
                    expr_str,
                )
                return False
            if node.func.id not in SAFE_NAMES:
                logger.warning(
                    "Expression calls disallowed function %r in %r",
                    node.func.id,
                    expr_str,
                )
                return False

    return True
