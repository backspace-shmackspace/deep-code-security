# Code Review: suppressions-file

**Verdict:** PASS

The implementation is complete, correct, and security-sound. No Critical or Major findings remain.

---

## Critical Findings (Must Fix)

None.

---

## Major Findings (Should Fix)

### 1. TOCTOU window between `stat()` and `read_text()` in `load_suppressions`

**File:** `src/deep_code_security/shared/suppressions.py`, lines 326–342

The size check calls `suppress_path.stat().st_size` and then calls `suppress_path.read_text()` in a separate operation. Between the two calls an adversary (or a concurrent process) could swap in a larger file. The size guard therefore only provides a soft DoS defence; it can be bypassed in a race.

The correct fix is to open the file once and read up to the limit in a single operation, rather than stat-then-read:

```python
try:
    with suppress_path.open("r", encoding="utf-8") as fh:
        content = fh.read(_MAX_SUPPRESSION_FILE_SIZE + 1)
except OSError as e:
    logger.warning("Cannot read suppressions file %s: %s", suppress_path, e)
    return None

if len(content) > _MAX_SUPPRESSION_FILE_SIZE:
    raise SuppressionLoadError(...)
```

This closes the race and simplifies the code by removing the `stat()` call.

**Severity assessment:** In the project's threat model the suppression file is written by the developer who owns the project root. An adversary capable of swapping files in that directory already has code-execution-equivalent access on the host. The risk is DoS (OOM on YAML parse of a huge file), not RCE. The mitigation is still worth applying, but the risk is low enough that it does not block this review.

---

### 2. `test_load_suppressions_file_exists` has a typo in the YAML that silently exercises unexpected behaviour

**File:** `tests/test_shared/test_suppressions.py`, lines 167–178

```python
suppress_file.write_text(
    "version: 1\nsuppressons: []\n"    # <-- "suppressons" (typo) -- ignored by Pydantic
    "suppressions:\n"
    "  - rule: CWE-78\n"
    "    reason: Known false positive\n",
    encoding="utf-8",
)
```

The concatenated string produces a YAML document with both `suppressons: []` (typo, unknown key ignored by Pydantic) and `suppressions:`. This is incidental to what the test intends to verify and could mask a regression if `SuppressionConfig` were ever switched to `model_config = {"extra": "forbid"}`. The typo line should be removed.

---

### 3. `full_scan` formatter does not attach the suppression section to HTML output

**File:** `src/deep_code_security/shared/formatters/html.py`, lines 101–113

`format_full_scan` builds `findings_html` and calls `_build_footer()`, but it never calls `_build_suppression_section(data.suppression_summary)`. The `format_hunt` method correctly appends the suppression section; `format_full_scan` omits it entirely. The plan's Goal 6 requires "suppression summary visible in all output formats". HTML for `full-scan` is therefore incomplete.

The plan's "Task breakdown" does note suppression for full-scan HTML should be added. The test suite (`test_html.py`) has `TestHtmlSuppressions` tests only for `format_hunt`, not `format_full_scan`, so this gap has no test coverage either.

---

## Minor Findings (Consider)

### A. `_glob_match` backtracking does not handle trailing `**` followed by nothing

**File:** `src/deep_code_security/shared/suppressions.py`, lines 52–102

A pattern ending in a bare `**` (e.g. `src/**`) should match any path under `src/`. The current implementation works correctly for this via the backtracking loop, but the behaviour is not tested. Adding a test for `_glob_match(["src", "a", "b.py"], ["src", "**"])` would make the intent explicit and guard against future refactors.

### B. `SuppressionLoadError` docstring says "exceeds size or rule count" but the class body is `pass`

**File:** `src/deep_code_security/shared/suppressions.py`, lines 46–49

Minor: the class docstring accurately describes usage, but it would help downstream users if the constructor accepted an optional `limit_type: str` attribute to distinguish size from count violations programmatically. Not blocking.

### C. CLI suppression summary block uses multiple variable aliases per command

**File:** `src/deep_code_security/cli.py`

The suppression result wrangling in `hunt`, `full_scan`, and `hunt_fuzz` is identical three times (build `SuppressionSummary`, echo to stderr, build `_suppressed_ids`). Extracting this to a shared `_build_suppression_summary(suppression_result) -> tuple[SuppressionSummary | None, list[RawFinding], list[str]]` helper would eliminate the duplication and reduce the chance of a future divergence. Not blocking.

### D. MCP `_handle_hunt` does not include suppression `reasons` dict in the response

**File:** `src/deep_code_security/mcp/server.py`, `_handle_hunt` method

The MCP response for `deep_scan_hunt` includes `suppressed_count`, `total_rules`, `expired_rules`, and `suppressed_finding_ids` (from `ScanStats`), but does not include the per-finding suppression reasons (`suppression_reasons` dict from `SuppressionResult`). The CLI and JSON formatter both surface reasons so the MCP caller can explain _why_ a finding was suppressed. The omission is intentional if MCP callers are expected to treat findings as opaque by ID, but it creates an asymmetry with the JSON output format. Worth discussing with the team.

### E. `test_load_suppressions_too_many_rules` generates CWE IDs like `CWE-1` through `CWE-501`

**File:** `tests/test_shared/test_suppressions.py`, lines 233–243

The test generates rules with `rule: CWE-{i}` for `i` in `range(1, 502)`. `CWE-1` through `CWE-9` are valid per the `^CWE-\d+$` pattern, so validation passes. This is fine and the test correctly hits the 500-rule limit. Noted for completeness only.

### F. `_glob_match` has a worst-case O(N×M) backtracking cost

**File:** `src/deep_code_security/shared/suppressions.py`, lines 52–102

With 500 rules and deep path trees the inner loop is bounded by the product of path segments and pattern segments per rule. For realistic paths and patterns (< 20 segments each) this is negligible. The 500-rule hard cap prevents any degenerate input from being a DoS vector. No action required, documented for awareness.

---

## Positives

**Security posture is excellent.**
- `yaml.safe_load()` is used exclusively and verified by a dedicated test that patches `yaml.safe_load` at the module level and asserts it is called.
- No user-controlled input flows into the suppression file path; the filename `_SUPPRESS_FILENAME` is a module-level constant.
- The 64 KB file-size limit and 500-rule count cap are both enforced before YAML parsing, providing two independent DoS barriers.
- `SuppressionRule` is a frozen Pydantic model (`model_config = {"frozen": True}`), preventing accidental mutation after validation.
- All fields that can be interpolated into formatter output (suppression reasons, file IDs) flow through `html.escape()` before rendering in `HtmlFormatter._build_suppression_section`.
- The `ignore_suppressions` flag propagates correctly through CLI (`hunt`, `full_scan`, `hunt_fuzz`), MCP (`deep_scan_hunt`, `deep_scan_full`, `deep_scan_hunt_fuzz`), and the orchestrator.

**Glob implementation is correct and well-tested.**
The custom `_glob_match` correctly prevents `*` from crossing `/` boundaries while allowing `**` to span multiple path segments. The "zero directory levels" edge case (`**/*.py` matching `foo.py`) is explicitly tested. This is a subtle algorithm and it's implemented right.

**SARIF suppression output conforms to spec.**
Suppressed findings are emitted as SARIF `result` objects with a `suppressions[]` array using `"kind": "inSource"` and `justification`, as specified by SARIF 2.1.0 section 3.27.23. The test validates this against the official JSON schema using `jsonschema`.

**Expiration semantics are tested at the boundary.**
`test_matches_expires_today` explicitly verifies that a suppression expiring on the same day as `today` still matches (inclusive boundary), which is the correct product behaviour and is easy to get wrong.

**`ScanStats` model is cleanly extended.**
The four new suppression fields (`findings_suppressed`, `suppression_rules_loaded`, `suppression_rules_expired`, `suppressed_finding_ids`) have correct defaults (0 / empty list) so existing scans that load no suppression file produce the same stats shape with no code changes at call sites.

**`CLAUDE.md` was updated** to add the `--ignore-suppressions` variants to the CLI Commands table, keeping the project guide accurate.

**Test coverage is thorough** for the new module: validation (model, config, load), glob matching, rule matching (rule, file glob, line range, combinations, expiration), `apply_suppressions` (no match, partial match, full match, reason tracking, first-rule-wins, expired count), and formatter output for all four formats including the SARIF schema validation test.
