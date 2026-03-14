"""Fixed subprocess worker for fuzz target execution.

This module is executed as a script in a subprocess. It reads parameters
from a JSON file specified as sys.argv[1], executes the target function,
and writes results to the output JSON file specified as sys.argv[2].

SECURITY: This is a fixed module; it is never generated dynamically.
All variable data (function name, arguments) is passed as data via JSON,
never inlined into script source.

SD-02: eval() is used with restricted globals and is preceded by AST
validation via the shared expression_validator module. See the merge plan
for full rationale.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import re
import sys
import traceback
from pathlib import Path

# Import the shared expression validator for Layer 2 defense
from deep_code_security.fuzzer.ai.expression_validator import validate_expression

# Restricted namespace for evaluating expression strings.
# Only data-constructing builtins are allowed; no I/O or execution.
# memoryview intentionally excluded per plan (potential memory probing vector).
RESTRICTED_BUILTINS: dict = {
    "__builtins__": {},
    "float": float,
    "int": int,
    "str": str,
    "bytes": bytes,
    "bytearray": bytearray,
    "dict": dict,
    "list": list,
    "set": set,
    "frozenset": frozenset,
    "tuple": tuple,
    "complex": complex,
    "range": range,
    "bool": bool,
    "None": None,
    "True": True,
    "False": False,
}


def eval_expression(expr_str: str):  # type: ignore[return]
    """Evaluate a Python expression string in a restricted namespace.

    Layer 2 defense: validates expression via AST allowlist before eval().

    Args:
        expr_str: Python expression string to evaluate.

    Returns:
        Evaluated value.

    Raises:
        ValueError: If the expression fails AST validation or cannot be evaluated.
    """
    # Layer 2: AST validation before eval (see SD-02)
    if not validate_expression(expr_str):
        raise ValueError(f"Expression failed AST validation: {expr_str!r}")

    # Try ast.literal_eval first (handles most cases safely)
    try:
        return ast.literal_eval(expr_str)
    except (ValueError, SyntaxError):
        pass

    # Fall back to restricted eval for cases like float('nan'), float('inf')
    try:
        return eval(expr_str, RESTRICTED_BUILTINS.copy())  # noqa: S307
    except Exception as e:
        raise ValueError(f"Cannot safely evaluate expression: {expr_str!r}: {e}") from e


def load_module_from_file(module_path: str):  # type: ignore[return]
    """Load a Python module from a file path."""
    path = Path(module_path)
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def main() -> None:
    """Main entry point for the worker subprocess."""
    if len(sys.argv) != 3:
        print(
            "Usage: python -m deep_code_security.fuzzer.execution._worker <input_json> <output_json>",
            file=sys.stderr,
        )
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    # Read parameters from JSON file
    try:
        with open(input_path) as f:
            params = json.load(f)
    except Exception as e:
        result = {
            "success": False,
            "exception": f"WorkerSetupError: Cannot read input file: {e}",
            "traceback": traceback.format_exc(),
            "stdout": "",
            "stderr": "",
            "coverage_data": {},
        }
        with open(output_path, "w") as f:
            json.dump(result, f)
        return

    module_path = params.get("module_path", "")
    qualified_name = params.get("qualified_name", "")
    args_exprs = params.get("args", [])
    kwargs_exprs = params.get("kwargs", {})
    collect_coverage = params.get("collect_coverage", True)
    coverage_data_path = params.get("coverage_data_path", "")

    # Capture stdout/stderr
    import io
    from contextlib import redirect_stderr, redirect_stdout

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    result: dict = {
        "success": False,
        "exception": None,
        "traceback": None,
        "stdout": "",
        "stderr": "",
        "coverage_data": {},
    }

    try:
        # Evaluate arguments (Layer 2 validation happens inside eval_expression)
        args = tuple(eval_expression(expr) for expr in args_exprs)
        kwargs = {k: eval_expression(v) for k, v in kwargs_exprs.items()}
    except ValueError as e:
        result["exception"] = f"InputValidationError: {e}"
        result["traceback"] = traceback.format_exc()
        with open(output_path, "w") as f:
            json.dump(result, f)
        return

    # Set up coverage if requested
    cov = None
    if collect_coverage:
        try:
            import coverage as coverage_module

            cov = coverage_module.Coverage(
                data_file=coverage_data_path if coverage_data_path else None,
                branch=True,
            )
            cov.start()
        except ImportError:
            collect_coverage = False

    try:
        # Defense-in-depth: validate qualified_name before getattr traversal.
        _VALID_QNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
        if not _VALID_QNAME_RE.match(qualified_name):
            raise ValueError(
                f"Invalid qualified_name format: {qualified_name!r}. "
                "Must be a dot-separated sequence of plain identifiers."
            )
        name_parts = qualified_name.split(".")
        for part in name_parts:
            if part.startswith("__") and part.endswith("__"):
                raise ValueError(
                    f"qualified_name component {part!r} is a dunder -- "
                    "access to dunder attributes is not permitted."
                )

        # Load module
        module = load_module_from_file(module_path)

        # Resolve the target function
        obj = module
        for part in name_parts:
            obj = getattr(obj, part)

        # Execute the target function
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            obj(*args, **kwargs)

        result["success"] = True

    except SystemExit as e:
        result["success"] = False
        result["exception"] = f"SystemExit: {e}"
        result["traceback"] = traceback.format_exc()
    except Exception as e:
        result["success"] = False
        result["exception"] = f"{type(e).__name__}: {e}"
        result["traceback"] = traceback.format_exc()
    finally:
        if cov is not None:
            try:
                cov.stop()
                cov.save()
                import os

                tmp_json = (
                    os.path.join(os.path.dirname(coverage_data_path), "coverage_report.json")
                    if coverage_data_path
                    else os.path.join(os.path.dirname(output_path), "coverage_report.json")
                )
                try:
                    cov.json_report(outfile=tmp_json, show_contexts=False)
                    with open(tmp_json) as f:
                        result["coverage_data"] = json.load(f)
                finally:
                    try:
                        os.unlink(tmp_json)
                    except OSError:
                        pass
            except Exception as cov_err:
                result["coverage_data"] = {"error": str(cov_err)}

        result["stdout"] = stdout_buf.getvalue()
        result["stderr"] = stderr_buf.getvalue()

    with open(output_path, "w") as f:
        json.dump(result, f)


if __name__ == "__main__":
    main()
