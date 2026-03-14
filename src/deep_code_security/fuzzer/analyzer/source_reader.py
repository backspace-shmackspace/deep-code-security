"""Python source file reader with side-effect detection."""

from __future__ import annotations

import ast
import logging
from pathlib import Path

__all__ = [
    "SideEffectVisitor",
    "detect_side_effects",
    "find_python_files",
    "parse_source",
    "read_source_file",
]

logger = logging.getLogger(__name__)

SIDE_EFFECT_CALLS = {
    "open",
    "write",
    "read",
    "close",
    "flush",
    "os.remove",
    "os.unlink",
    "os.rename",
    "os.mkdir",
    "os.makedirs",
    "os.rmdir",
    "os.listdir",
    "os.walk",
    "os.scandir",
    "shutil.copy",
    "shutil.move",
    "shutil.rmtree",
    "pathlib.Path.write_text",
    "pathlib.Path.write_bytes",
    "pathlib.Path.unlink",
    "pathlib.Path.mkdir",
    "pathlib.Path.rmdir",
    "socket.connect",
    "socket.send",
    "socket.recv",
    "urllib.request.urlopen",
    "requests.get",
    "requests.post",
    "httpx.get",
    "httpx.post",
    "sqlite3.connect",
    "cursor.execute",
    "os.system",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "os.execv",
    "os.execve",
    "print",
}

SIDE_EFFECT_FUNC_NAMES = {"open", "print", "input"}

SIDE_EFFECT_ATTRS = {
    "remove",
    "unlink",
    "rename",
    "mkdir",
    "makedirs",
    "rmdir",
    "listdir",
    "walk",
    "scandir",
    "system",
    "write",
    "read",
}


class SideEffectVisitor(ast.NodeVisitor):
    """AST visitor that detects potential side effects in function bodies."""

    def __init__(self) -> None:
        self.has_side_effects = False
        self.side_effect_details: list[str] = []

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._get_call_name(node)
        if call_name:
            if call_name in SIDE_EFFECT_CALLS:
                self.has_side_effects = True
                self.side_effect_details.append(call_name)
            func_name = call_name.split(".")[-1]
            if func_name in SIDE_EFFECT_FUNC_NAMES and call_name not in {"print"}:
                self.has_side_effects = True
                self.side_effect_details.append(call_name)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in SIDE_EFFECT_ATTRS:
            pass
        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current: ast.expr = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                return ".".join(reversed(parts))
        return None


def read_source_file(path: str | Path) -> str:
    """Read a Python source file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Source file not found: {path}")
    if path.suffix != ".py":
        raise ValueError(f"Not a Python file: {path}")
    return path.read_text(encoding="utf-8")


def parse_source(source: str, filename: str = "<unknown>") -> ast.Module:
    """Parse Python source code into an AST."""
    return ast.parse(source, filename=filename)


def detect_side_effects(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[bool, list[str]]:
    """Detect potential side effects in a function body."""
    visitor = SideEffectVisitor()
    for node in func_node.body:
        visitor.visit(node)
    return visitor.has_side_effects, visitor.side_effect_details


def find_python_files(path: str | Path) -> list[Path]:
    """Recursively find all Python files in a path."""
    path = Path(path)
    if path.is_file():
        if path.suffix == ".py":
            return [path]
        return []
    elif path.is_dir():
        return sorted(path.rglob("*.py"))
    return []
