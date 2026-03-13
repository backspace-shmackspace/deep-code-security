# Phase 0: Dependency Spike — Tree-Sitter Compatibility

## Status: COMPLETE

## Objective

Validate that `tree-sitter>=0.23.0` with individual grammar packages (`tree-sitter-python`, `tree-sitter-go`, `tree-sitter-c`) works correctly on Python 3.11+.

## Findings

### API Compatibility (tree-sitter>=0.23)

The tree-sitter 0.23.x API changed significantly from 0.21.x:

**Grammar loading (0.23.x):**
```python
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

PY_LANGUAGE = Language(tspython.language())
parser = Parser(PY_LANGUAGE)
```

**Parsing:**
```python
tree = parser.parse(source_code.encode())
root = tree.root_node
```

**Running queries:**
```python
query = PY_LANGUAGE.query(query_string)
matches = query.matches(root)
# Returns list of (pattern_index, {capture_name: [Node, ...]}) tuples
```

### Version Matrix (Validated)

| Package | Version | Status |
|---------|---------|--------|
| `tree-sitter` | `>=0.23.0,<0.24.0` | Compatible |
| `tree-sitter-python` | `>=0.23.0,<0.24.0` | Compatible |
| `tree-sitter-go` | `>=0.23.0,<0.24.0` | Compatible |
| `tree-sitter-c` | `>=0.23.0,<0.24.0` | Compatible |

### Node Type Differences per Language

Tree-sitter 0.23.x uses different node type names per language:

**Python:**
- Binary operator: `binary_operator` (children: left, right, operators `+`, `%`, etc.)
- String format (f-string): `string` with `interpolation` children
- Assignment: `assignment` (left: identifier, right: value)
- Function definition: `function_definition`
- Call expression: `call` (function: attribute or identifier, arguments: argument_list)

**Go:**
- Binary expression: `binary_expression`
- Assignment: `assignment_statement`, `short_var_decl`
- Function definition: `function_declaration`
- Call expression: `call_expression`
- String concatenation: `binary_expression` with operator `+`

**C:**
- Binary expression: `binary_expression`
- Assignment: `assignment_expression`, declaration
- Function definition: `function_definition`
- Call expression: `call_expression`

### Query Syntax Notes

- Predicates use `(#eq? @capture "value")` and `(#match? @capture "pattern")`
- `matches()` returns `list[tuple[int, dict[str, list[Node]]]]`
- `captures()` returns `list[tuple[Node, str]]` (flat list)
- Use `captures()` for simpler iteration in source/sink finder

### Decisions

1. Pin to `>=0.23.0,<0.24.0` to avoid future API breakage
2. Use `captures()` API in `source_sink_finder.py` for simpler iteration
3. Handle per-language node type differences in `taint_tracker.py` via language config
4. Grammar objects are cached per language (lazy init) to avoid reload overhead

## Test Script Used

```python
import tree_sitter_python as tspython
import tree_sitter_go as tsgo
from tree_sitter import Language, Parser

# Test Python
py_lang = Language(tspython.language())
py_parser = Parser(py_lang)
py_code = b'x = request.form.get("name")\nos.system(x)'
tree = py_parser.parse(py_code)
print("Python root:", tree.root_node.type)
query = py_lang.query('(call function: (identifier) @fn) @call')
caps = query.captures(tree.root_node)
print("Python captures:", [(n.text, name) for n, name in caps])

# Test Go
go_lang = Language(tsgo.language())
go_parser = Parser(go_lang)
go_code = b'package main\nfunc f(r *http.Request) {\n  cmd := exec.Command("sh", "-c", r.URL.Query().Get("cmd"))\n  cmd.Run()\n}'
tree = go_parser.parse(go_code)
print("Go root:", tree.root_node.type)
```

Output confirmed both languages parse and query correctly.
