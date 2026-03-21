"""C function signature extraction via tree-sitter-c.

Discovers fuzzable function definitions in .c files and returns TargetInfo
objects compatible with the existing fuzzer pipeline.

Exclusion rules (per plan Section 2):
- ``static`` functions: internal linkage, cannot be called from an external harness.
- ``main()``: entry point, not a fuzzing target.
- Functions with no parameters: nothing to fuzz.

Inclusion rules:
- ``inline`` functions: included (external linkage by default, callable from harness).
- ``extern`` functions: included.
- Non-qualified (file-scope, no storage class) functions: included.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from deep_code_security.fuzzer.models import TargetInfo

__all__ = [
    "extract_c_targets_from_file",
    "extract_c_targets_from_source",
]

logger = logging.getLogger(__name__)

# Maximum source size to parse (bytes).
_MAX_SOURCE_BYTES: int = 10 * 1024 * 1024  # 10 MB


def _load_c_parser() -> tuple[Any, Any]:
    """Load the tree-sitter-c parser and Language object.

    Returns:
        (parser, language) tuple.

    Raises:
        ImportError: If tree-sitter or tree-sitter-c is not installed.
    """
    from tree_sitter import Language as TSLanguage
    from tree_sitter import Parser
    import tree_sitter_c as tsc

    language = TSLanguage(tsc.language())
    parser = Parser(language)
    return parser, language


def _node_text(node: Any, source_bytes: bytes) -> str:
    """Extract the UTF-8 text for a tree-sitter node."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _get_storage_class_specifiers(func_def_node: Any, source_bytes: bytes) -> set[str]:
    """Return the set of storage class specifier keywords for a function_definition node.

    Looks at direct children of the function_definition for
    storage_class_specifier nodes (which carry text like 'static', 'inline',
    'extern').
    """
    specifiers: set[str] = set()
    for child in func_def_node.children:
        if child.type == "storage_class_specifier":
            specifiers.add(_node_text(child, source_bytes).strip())
    return specifiers


def _get_type_qualifier_text(node: Any, source_bytes: bytes) -> str:
    """Return the full type text for a type_qualifier or type_specifier node."""
    return _node_text(node, source_bytes).strip()


def _extract_param_type(param_node: Any, source_bytes: bytes) -> str:
    """Extract the C type string from a parameter_declaration node.

    Collects all children except the declarator to form the base type string,
    then appends pointer stars from the declarator.
    """
    parts: list[str] = []
    declarator_node: Any = None

    for child in param_node.children:
        if child.type in (
            "type_specifier",
            "type_qualifier",
            "primitive_type",
            "sized_type_specifier",
            "struct_specifier",
            "union_specifier",
            "enum_specifier",
            "type_identifier",
        ):
            parts.append(_get_type_qualifier_text(child, source_bytes))
        elif child.type in (
            "abstract_declarator",
            "pointer_declarator",
            "array_declarator",
            "function_declarator",
            "identifier",
        ):
            declarator_node = child
        elif child.type == "pointer_declarator":
            declarator_node = child

    base_type = " ".join(parts) if parts else "void"

    # Count pointer stars from the declarator.  A pointer_declarator may
    # itself contain a nested pointer_declarator for double pointers.
    stars = ""
    if declarator_node is not None:
        node = declarator_node
        while node is not None:
            if node.type == "pointer_declarator":
                stars += "*"
                # Descend into the inner declarator
                inner = None
                for child in node.children:
                    if child.type in (
                        "pointer_declarator",
                        "abstract_declarator",
                        "identifier",
                    ):
                        inner = child
                        break
                node = inner
            else:
                break

    if stars:
        return f"{base_type} {stars}".rstrip()
    return base_type


def _extract_param_name(param_node: Any, source_bytes: bytes) -> str:
    """Extract the parameter name from a parameter_declaration node.

    Returns an empty string for unnamed parameters.
    """
    for child in param_node.children:
        if child.type == "identifier":
            return _node_text(child, source_bytes).strip()
        # The name is the terminal identifier inside a pointer_declarator or
        # array_declarator.
        if child.type in ("pointer_declarator", "array_declarator", "function_declarator"):
            for grandchild in child.children:
                if grandchild.type == "identifier":
                    return _node_text(grandchild, source_bytes).strip()
                # Handle double pointer: ** name
                if grandchild.type in ("pointer_declarator", "array_declarator"):
                    for ggchild in grandchild.children:
                        if ggchild.type == "identifier":
                            return _node_text(ggchild, source_bytes).strip()
    return ""


def _parse_parameter_list(
    params_node: Any, source_bytes: bytes
) -> list[dict]:
    """Parse a parameter_list node into a list of parameter dicts.

    Each dict has keys: name, type_hint, default, kind.

    Variadic parameters (``...``) are represented with name ``"..."`` and
    type_hint ``"..."``.
    """
    params: list[dict] = []
    for child in params_node.children:
        if child.type == "parameter_declaration":
            ptype = _extract_param_type(child, source_bytes)
            pname = _extract_param_name(child, source_bytes)
            params.append(
                {
                    "name": pname,
                    "type_hint": ptype,
                    "default": "",
                    "kind": "POSITIONAL_OR_KEYWORD",
                }
            )
        elif child.type == "variadic_parameter":
            params.append(
                {
                    "name": "...",
                    "type_hint": "...",
                    "default": "",
                    "kind": "VAR_POSITIONAL",
                }
            )
    return params


def _build_c_signature(func_name: str, return_type: str, params: list[dict]) -> str:
    """Build a human-readable C function signature string.

    Example: ``int process_input(const char *data, size_t len)``
    """
    if not params:
        return f"{return_type} {func_name}(void)"

    param_strs: list[str] = []
    for p in params:
        if p["name"] == "...":
            param_strs.append("...")
        elif p["name"]:
            param_strs.append(f"{p['type_hint']} {p['name']}")
        else:
            param_strs.append(p["type_hint"])

    return f"{return_type} {func_name}({', '.join(param_strs)})"


def _extract_return_type(func_def_node: Any, source_bytes: bytes) -> str:
    """Extract the return type text from a function_definition node.

    The return type is formed from all non-declarator, non-body children:
    type_specifier, type_qualifier, storage_class_specifier (excluding
    'static'/'inline'/'extern'), primitive_type, etc.
    """
    parts: list[str] = []
    for child in func_def_node.children:
        if child.type in (
            "compound_statement",          # function body
            "function_declarator",
            "pointer_declarator",
            "array_declarator",
        ):
            break
        if child.type == "storage_class_specifier":
            kw = _node_text(child, source_bytes).strip()
            # 'inline' is a storage class in older standards but is meaningful
            # for the return type display -- omit it here, it's not part of the
            # return type.
            if kw not in ("static", "extern", "inline", "auto", "register"):
                parts.append(kw)
        elif child.type in (
            "type_specifier",
            "type_qualifier",
            "primitive_type",
            "sized_type_specifier",
            "struct_specifier",
            "union_specifier",
            "enum_specifier",
            "type_identifier",
        ):
            parts.append(_get_type_qualifier_text(child, source_bytes))

    return " ".join(parts) if parts else "void"


def _get_func_name_from_declarator(declarator_node: Any, source_bytes: bytes) -> str | None:
    """Walk a declarator node to find the function name identifier.

    Handles: function_declarator, pointer_declarator wrapping function_declarator,
    and parenthesized_declarator (e.g. ``void (func_name)(args)``).
    """
    if declarator_node is None:
        return None

    # Direct: (function_declarator declarator: (identifier) ...)
    if declarator_node.type == "function_declarator":
        for child in declarator_node.children:
            if child.type == "identifier":
                return _node_text(child, source_bytes).strip()
            # In function_declarator the declarator field is the function name
        # Named field access
        decl = declarator_node.child_by_field_name("declarator")
        if decl is not None and decl.type == "identifier":
            return _node_text(decl, source_bytes).strip()

    # Pointer: (pointer_declarator * (function_declarator ...))
    if declarator_node.type == "pointer_declarator":
        for child in declarator_node.children:
            if child.type in ("function_declarator", "pointer_declarator", "parenthesized_declarator"):
                name = _get_func_name_from_declarator(child, source_bytes)
                if name:
                    return name

    # Parenthesized: (parenthesized_declarator "(" inner ")")
    # Covers patterns like ``void (func_name)(args)`` and
    # ``type (*func_ptr)(args)`` where parens wrap the declarator.
    if declarator_node.type == "parenthesized_declarator":
        for child in declarator_node.children:
            if child.type == "identifier":
                return _node_text(child, source_bytes).strip()
            if child.type in ("function_declarator", "pointer_declarator", "parenthesized_declarator"):
                name = _get_func_name_from_declarator(child, source_bytes)
                if name:
                    return name

    return None


def _find_params_node(declarator_node: Any) -> Any | None:
    """Find the parameter_list node within a declarator."""
    if declarator_node is None:
        return None

    if declarator_node.type == "function_declarator":
        return declarator_node.child_by_field_name("parameters")

    # Pointer wrapping a function_declarator
    for child in declarator_node.children:
        if child.type in ("function_declarator", "pointer_declarator"):
            result = _find_params_node(child)
            if result is not None:
                return result
    return None


def _should_include_function(
    func_name: str,
    specifiers: set[str],
    params: list[dict],
) -> bool:
    """Return True if the function is a valid fuzzing target.

    Excluded if:
    - Named 'main' (entry point).
    - Has the 'static' storage class (internal linkage).
    - Has no parameters (nothing to fuzz).
    """
    if func_name == "main":
        logger.debug("Skipping main() -- entry point, not a fuzzing target.")
        return False
    if "static" in specifiers:
        logger.debug(
            "Skipping %s() -- static function (internal linkage).", func_name
        )
        return False
    if not params:
        logger.debug("Skipping %s() -- no parameters, nothing to fuzz.", func_name)
        return False
    return True


def _extract_functions_from_tree(tree: Any, source_bytes: bytes) -> list[TargetInfo]:
    """Walk the tree-sitter parse tree and extract fuzzable C functions.

    Args:
        tree: tree-sitter Tree object (root node via tree.root_node).
        source_bytes: Raw source bytes (used for text extraction).

    Returns:
        List of TargetInfo objects for each fuzzable function found.
    """
    targets: list[TargetInfo] = []
    root = tree.root_node

    # Walk top-level declarations.  C does not have nested named functions
    # (GCC extensions aside), so we only need to look at top-level children.
    for node in root.children:
        if node.type != "function_definition":
            continue

        # Extract storage class specifiers (static, inline, extern).
        specifiers = _get_storage_class_specifiers(node, source_bytes)

        # Find the declarator child.
        declarator_node = node.child_by_field_name("declarator")
        if declarator_node is None:
            continue

        # Extract function name.
        func_name = _get_func_name_from_declarator(declarator_node, source_bytes)
        if func_name is None:
            logger.debug("Could not determine function name for node at byte %d", node.start_byte)
            continue

        # Extract parameters.
        params_node = _find_params_node(declarator_node)
        if params_node is None:
            params: list[dict] = []
        else:
            params = _parse_parameter_list(params_node, source_bytes)

        # Apply exclusion rules.
        if not _should_include_function(func_name, specifiers, params):
            continue

        # Extract return type.
        return_type = _extract_return_type(node, source_bytes)

        # Build signature string.
        signature = _build_c_signature(func_name, return_type, params)

        # Extract source code for this function.
        source_code = source_bytes[node.start_byte:node.end_byte].decode(
            "utf-8", errors="replace"
        )

        # Line numbers (tree-sitter is 0-indexed, TargetInfo expects 1-indexed).
        lineno: int = node.start_point[0] + 1
        end_lineno: int = node.end_point[0] + 1

        targets.append(
            TargetInfo(
                module_path="",        # Set by callers that know the file path.
                function_name=func_name,
                qualified_name=func_name,  # No classes in C.
                signature=signature,
                parameters=params,
                docstring=None,
                source_code=source_code,
                decorators=[],
                complexity=0,          # Complexity estimation not needed for C.
                is_static_method=False,
                has_side_effects=False,
                lineno=lineno,
                end_lineno=end_lineno,
                is_instance_method=False,
            )
        )

    return targets


def extract_c_targets_from_source(
    source: str,
    module_path: str = "",
) -> list[TargetInfo]:
    """Extract fuzzable C function targets from a source code string.

    Parses the source with tree-sitter-c and returns one TargetInfo per
    eligible function definition.

    Args:
        source: C source code as a string.
        module_path: Path to the source file (used to populate
            TargetInfo.module_path and for log messages).

    Returns:
        List of TargetInfo objects for each discovered fuzzable function.
        Returns an empty list on parse failure or if no eligible functions
        are found.
    """
    source_bytes = source.encode("utf-8")

    if len(source_bytes) > _MAX_SOURCE_BYTES:
        logger.error(
            "Source too large to parse (%d bytes > %d): %s",
            len(source_bytes),
            _MAX_SOURCE_BYTES,
            module_path,
        )
        return []

    try:
        parser, _language = _load_c_parser()
    except ImportError as exc:
        logger.error("tree-sitter-c not available: %s", exc)
        return []

    try:
        tree = parser.parse(source_bytes)
    except Exception as exc:
        logger.error("tree-sitter-c parse error for %s: %s", module_path, exc)
        return []

    if tree is None or tree.root_node is None:
        logger.error("tree-sitter-c returned None tree for %s", module_path)
        return []

    targets = _extract_functions_from_tree(tree, source_bytes)

    # Stamp each target with the caller-provided module_path.
    for t in targets:
        t.module_path = module_path

    logger.debug(
        "Extracted %d fuzzable C function(s) from %s",
        len(targets),
        module_path or "<source string>",
    )
    return targets


def extract_c_targets_from_file(path: str | Path) -> list[TargetInfo]:
    """Extract fuzzable C function targets from a .c file on disk.

    Args:
        path: Absolute path to the .c file.

    Returns:
        List of TargetInfo objects for each discovered fuzzable function.
        Returns an empty list if the file cannot be read or produces no
        eligible targets.
    """
    path = Path(path)

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.error("Cannot read C source file %s: %s", path, exc)
        return []

    return extract_c_targets_from_source(source, module_path=str(path))
