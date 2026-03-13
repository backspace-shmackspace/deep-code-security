# Registry Format Documentation

Registries define source and sink patterns for each supported language. They are YAML files located in this directory, one per language.

## File Naming

`<language>.yaml` — e.g., `python.yaml`, `go.yaml`, `c.yaml`

## Schema

```yaml
language: <string>          # Must match the filename without extension
version: "<semver>"         # Registry version for reproducibility tracking

sources:
  <category>:              # Source category (e.g., web_input, cli_input)
    - pattern: "<string>"  # Human-readable pattern name
      tree_sitter_query: | # S-expression tree-sitter query
        (...)
      severity: <critical|high|medium|low>

sinks:
  <category>:              # Sink category (e.g., command_injection, sql_injection)
    cwe: "<CWE-N>"         # CWE identifier for this category
    entries:
      - pattern: "<string>"
        tree_sitter_query: |
          (...)
        severity: <critical|high|medium|low>

sanitizers:
  - pattern: "<string>"    # Sanitizer function/pattern name
    neutralizes:           # List of sink categories this neutralizes
      - <category>
    description: "<string>"  # Optional description
```

## Tree-Sitter Query Syntax

Queries use tree-sitter S-expression syntax. Key predicates:
- `(#eq? @capture "value")` — exact match
- `(#match? @capture "regex")` — regex match
- `@capture_name` — named capture group

The first capture in a query is used to locate the matching node in the source file.

## Severity Levels

| Level | Description |
|-------|-------------|
| `critical` | Directly exploitable, high impact (e.g., unauthenticated RCE) |
| `high` | Significant security risk, likely exploitable |
| `medium` | Security concern, may require specific conditions to exploit |
| `low` | Minor security concern or informational |

## Known Limitations (v1)

All registries target **direct patterns only**. The following patterns are NOT matched in v1:

1. **Aliased imports**: `req = request; req.form.get("id")` — aliased variable not tracked
2. **Fully-qualified names**: `flask.request.form` — module-qualified access not matched
3. **Class attributes**: `self.request.form` — instance attribute access not matched
4. **Chained calls**: `request.form.get("key")` — intermediate `.get()` may break matching
5. **Interprocedural flow**: source and sink in different functions — NOT tracked in v1

These limitations are intentional for v1 scope. Expected detection rate: **10-25%** of real-world injection vulnerabilities. The primary v1 value is proving the architecture.

## Adding a New Registry

1. Create `registries/<language>.yaml` following the schema above
2. Validate the registry loads without errors: `python -c "from deep_code_security.hunter.registry import load_registry; from deep_code_security.shared.language import Language; load_registry(Language.<LANGUAGE>, 'registries')"`
3. Add test fixtures in `tests/fixtures/vulnerable_samples/<language>/` and `tests/fixtures/safe_samples/<language>/`
4. Update `tests/conftest.py` to include the new language

## Query Development Tips

1. Use the tree-sitter playground (https://tree-sitter.github.io/tree-sitter/playground) to explore AST structure
2. Test queries against fixture files before adding to registry
3. Start with simple direct patterns and document gaps
4. Use `(#match? @capture "regex")` for patterns with multiple valid names (e.g., `exec.Call|exec.Run`)
5. Validate query compilation: any syntax error will cause `load_registry()` to raise `ValueError`
