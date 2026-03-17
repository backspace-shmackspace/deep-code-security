"""Function signature extraction with instance method filtering."""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from deep_code_security.fuzzer.analyzer.source_reader import (
    detect_side_effects,
    find_python_files,
    parse_source,
    read_source_file,
)
from deep_code_security.fuzzer.models import TargetInfo

__all__ = [
    "extract_targets_from_file",
    "extract_targets_from_path",
    "extract_targets_from_source",
]

logger = logging.getLogger(__name__)


def _get_annotation_str(node: ast.expr | None) -> str:
    if node is None:
        return ""
    return ast.unparse(node)


def _estimate_complexity(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    complexity = 1
    for node in ast.walk(func_node):
        if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
            complexity += 1
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            complexity += 1
            if node.ifs:
                complexity += len(node.ifs)
    return complexity


def _extract_parameters(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[dict]:
    params = []
    args = func_node.args

    defaults = args.defaults
    num_plain = len(args.args)
    default_offset = num_plain - len(defaults)

    for i, arg in enumerate(args.posonlyargs):
        default = ""
        d_idx = i - (len(args.posonlyargs) - len(defaults))
        if 0 <= d_idx < len(defaults):
            default = ast.unparse(defaults[d_idx])
        params.append(
            {
                "name": arg.arg,
                "type_hint": _get_annotation_str(arg.annotation),
                "default": default,
                "kind": "POSITIONAL_ONLY",
            }
        )

    for i, arg in enumerate(args.args):
        d_idx = i - default_offset
        default = ast.unparse(defaults[d_idx]) if 0 <= d_idx < len(defaults) else ""
        params.append(
            {
                "name": arg.arg,
                "type_hint": _get_annotation_str(arg.annotation),
                "default": default,
                "kind": "POSITIONAL_OR_KEYWORD",
            }
        )

    if args.vararg:
        params.append(
            {
                "name": args.vararg.arg,
                "type_hint": _get_annotation_str(args.vararg.annotation),
                "default": "",
                "kind": "VAR_POSITIONAL",
            }
        )

    kw_defaults = args.kw_defaults
    for i, arg in enumerate(args.kwonlyargs):
        default = ""
        if i < len(kw_defaults) and kw_defaults[i] is not None:
            default = ast.unparse(kw_defaults[i])  # type: ignore[arg-type]
        params.append(
            {
                "name": arg.arg,
                "type_hint": _get_annotation_str(arg.annotation),
                "default": default,
                "kind": "KEYWORD_ONLY",
            }
        )

    if args.kwarg:
        params.append(
            {
                "name": args.kwarg.arg,
                "type_hint": _get_annotation_str(args.kwarg.annotation),
                "default": "",
                "kind": "VAR_KEYWORD",
            }
        )

    return params


def _build_signature_str(
    func_name: str,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    params: list[dict],
) -> str:
    parts = []
    for p in params:
        part = p["name"]
        if p["type_hint"]:
            part += f": {p['type_hint']}"
        if p["default"]:
            part += f" = {p['default']}"
        if p["kind"] == "VAR_POSITIONAL":
            part = f"*{part}"
        elif p["kind"] == "VAR_KEYWORD":
            part = f"**{part}"
        parts.append(part)

    ret_annotation = ""
    if func_node.returns:
        ret_annotation = f" -> {_get_annotation_str(func_node.returns)}"

    return f"{func_name}({', '.join(parts)}){ret_annotation}"


def _get_decorators(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [ast.unparse(decorator) for decorator in func_node.decorator_list]


def _is_static_method(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in func_node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "staticmethod":
            return True
    return False


def _is_class_method(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in func_node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "classmethod":
            return True
    return False


def _is_instance_method(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    is_in_class: bool,
) -> bool:
    if not is_in_class:
        return False
    if _is_static_method(func_node):
        return False
    if _is_class_method(func_node):
        return False
    return True


def extract_targets_from_source(
    source: str,
    module_path: str,
    allow_side_effects: bool = False,
    include_instance_methods: bool = False,
) -> list[TargetInfo]:
    """Extract fuzzable targets from Python source code.

    Args:
        source: Python source code string.
        module_path: Path to the source file (for logging).
        allow_side_effects: If True, include functions with detected side effects.
        include_instance_methods: If True, include instance methods and classmethods
            with is_instance_method=True set on the returned TargetInfo. When False
            (default), instance methods and classmethods are skipped with warning logs,
            preserving existing behavior for the fuzzer's normal discovery path.
    """
    try:
        tree = parse_source(source, module_path)
    except SyntaxError as e:
        logger.error("Syntax error in %s: %s", module_path, e)
        return []

    targets: list[TargetInfo] = []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            target = _make_target_info(
                node,
                module_path=module_path,
                class_name=None,
                source=source,
                allow_side_effects=allow_side_effects,
                is_instance_method=False,
            )
            if target is not None:
                targets.append(target)

        elif isinstance(node, ast.ClassDef):
            class_name = node.name
            for class_node in ast.iter_child_nodes(node):
                if isinstance(class_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    is_inst = _is_instance_method(class_node, is_in_class=True)
                    is_cls = _is_class_method(class_node)
                    if is_inst or is_cls:
                        if include_instance_methods:
                            target = _make_target_info(
                                class_node,
                                module_path=module_path,
                                class_name=class_name,
                                source=source,
                                allow_side_effects=allow_side_effects,
                                is_instance_method=True,
                            )
                            if target is not None:
                                targets.append(target)
                        else:
                            if is_inst:
                                logger.warning(
                                    "Skipping instance method %s.%s in %s"
                                    " (not supported in MVP)",
                                    class_name,
                                    class_node.name,
                                    module_path,
                                )
                            else:
                                logger.warning(
                                    "Skipping classmethod %s.%s in %s (not supported in MVP)",
                                    class_name,
                                    class_node.name,
                                    module_path,
                                )
                        continue
                    target = _make_target_info(
                        class_node,
                        module_path=module_path,
                        class_name=class_name,
                        source=source,
                        allow_side_effects=allow_side_effects,
                        is_instance_method=False,
                    )
                    if target is not None:
                        targets.append(target)

    return targets


def _make_target_info(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_path: str,
    class_name: str | None,
    source: str,
    allow_side_effects: bool,
    is_instance_method: bool = False,
) -> TargetInfo | None:
    func_name = func_node.name

    if func_name.startswith("__") and func_name.endswith("__"):
        return None

    params = _extract_parameters(func_node)

    if class_name:
        qualified_name = f"{class_name}.{func_name}"
    else:
        qualified_name = func_name

    display_params = [p for p in params if p["name"] not in ("self", "cls")]
    signature = _build_signature_str(func_name, func_node, display_params)

    docstring: str | None = ast.get_docstring(func_node)

    try:
        source_lines = source.splitlines()
        func_source_lines = source_lines[func_node.lineno - 1 : func_node.end_lineno]
        func_source = "\n".join(func_source_lines)
    except (AttributeError, IndexError):
        func_source = ""

    decorators = _get_decorators(func_node)
    is_static = _is_static_method(func_node)

    has_side_effects, side_effect_details = detect_side_effects(func_node)
    if has_side_effects and not allow_side_effects:
        logger.warning(
            "Function %s has potential side effects (%s); include with --allow-side-effects",
            qualified_name,
            ", ".join(side_effect_details[:3]),
        )

    complexity = _estimate_complexity(func_node)

    lineno: int | None = getattr(func_node, "lineno", None)
    end_lineno: int | None = getattr(func_node, "end_lineno", None)

    return TargetInfo(
        module_path=module_path,
        function_name=func_name,
        qualified_name=qualified_name,
        signature=signature,
        parameters=display_params,
        docstring=docstring,
        source_code=func_source,
        decorators=decorators,
        complexity=complexity,
        is_static_method=is_static,
        has_side_effects=has_side_effects,
        lineno=lineno,
        end_lineno=end_lineno,
        is_instance_method=is_instance_method,
    )


def extract_targets_from_file(
    path: str | Path,
    allow_side_effects: bool = False,
    include_instance_methods: bool = False,
) -> list[TargetInfo]:
    """Extract fuzzable targets from a Python file.

    Args:
        path: Path to the Python file.
        allow_side_effects: If True, include functions with detected side effects.
        include_instance_methods: If True, include instance methods and classmethods.
    """
    path = Path(path)
    source = read_source_file(path)
    return extract_targets_from_source(
        source,
        str(path),
        allow_side_effects=allow_side_effects,
        include_instance_methods=include_instance_methods,
    )


def extract_targets_from_path(
    path: str | Path,
    allow_side_effects: bool = False,
) -> list[TargetInfo]:
    python_files = find_python_files(path)
    all_targets: list[TargetInfo] = []
    for py_file in python_files:
        targets = extract_targets_from_file(py_file, allow_side_effects=allow_side_effects)
        all_targets.extend(targets)
    return all_targets
