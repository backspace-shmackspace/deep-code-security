# Review: merge-fuzzy-wuzzy (Round 2)

**Plan:** `./plans/merge-fuzzy-wuzzy.md`
**Reviewed:** 2026-03-14
**Round 1 review:** 2026-03-14
**Verdict:** PASS

---

## Round 1 Finding Resolution

### Required Edits

**1. Fix the `-f` short option collision.**
**Status: Resolved.**
The revised plan changes `--function` to use `-F` (capital) as its short flag. This is stated explicitly in the CLI code block (line 168: `@click.option("--function", "-F", ...)`), in the CLI flag resolution paragraph (line 187), in the Interfaces/Schema Changes table (line 549: `--function` (`-F`)), and in Task 4.1 (line 1204). `-f` is reserved for `--format` throughout.

**2. Add a security deviation section for the fuzzer subprocess sandbox.**
**Status: Resolved.**
The plan adds a thorough Security Deviation SD-01 (lines 805-828) that explicitly compares the fuzzer's rlimit-only isolation with the DCS auditor's container isolation in a side-by-side table. The justification is clear: the fuzzer executes the user's own code (analogous to pytest), while the auditor executes generated PoC scripts. Compensating controls are enumerated, and the resolution path (implement `ContainerBackend`) is specified. Additionally, the `deep_scan_fuzz` MCP tool is deferred entirely until the container backend is available (lines 196-198), which is a stronger mitigation than originally required.

**3. Address `input_validator.py` for fuzz MCP tool responses.**
**Status: Resolved.**
Line 123 in the architecture diagram shows `input_validator.py` with the comment "Extended: validates fuzz crash data in MCP responses." Line 223 states: "All crash data (exception messages, tracebacks, function names) in the MCP response is validated through `input_validator.py` to sanitize untrusted content from target code execution." Task 5.3 (lines 1239-1242) creates the implementation task. The plan also notes this applies to `_handle_fuzz_status()` when it returns crash data from polled runs.

**4. Clarify the AST allowlist execution mechanism.**
**Status: Resolved.**
Security Deviation SD-02 (lines 830-841) explicitly acknowledges that `_worker.py:eval_expression()` uses `eval()` with restricted globals and justifies this as a deliberate, documented exception to the CLAUDE.md `eval()` ban. The mitigations are specified in detail: dual-layer AST validation (Layer 1 in `response_parser.py`, Layer 2 in `_worker.py`), restricted globals with `__builtins__` cleared, and extraction of the validator into a shared `expression_validator.py` module (Task 2.5, lines 1092-1096). The plan also specifies removing `memoryview` from `RESTRICTED_BUILTINS`.

**5. Resolve the `Formatter` protocol backward compatibility mechanism.**
**Status: Resolved.**
The revised plan introduces a completely separate `FuzzFormatter` protocol (lines 281-290) rather than adding methods to the existing `Formatter` protocol. The `Formatter` protocol retains exactly two methods (`format_hunt`, `format_full_scan`) and is unchanged. The rationale for separate protocols is stated explicitly on lines 295: "Adding methods to an existing Protocol breaks all classes that previously satisfied it but lack the new methods." The `register_formatter()` function continues to validate only the original two methods (line 293). A `supports_fuzz()` helper checks `isinstance(formatter, FuzzFormatter)` at runtime. This is a clean structural solution that avoids the ABC/default-methods problem entirely.

**6. Acknowledge the `format_hunt()` signature change as a revision of the output-formats plan.**
**Status: Resolved.**
Lines 297 states: "The `target_path: str = ""` parameter already exists in the current codebase (`shared/formatters/protocol.py` line 55). This is not a new addition by this plan." Historical Alignment Note #1 (lines 1401) elaborates: "the implemented code in `shared/formatters/protocol.py` already includes `target_path: str = ""` ... This plan's `FuzzFormatter` methods follow the same signature pattern. This is consistent with the codebase as-implemented, not a revision of the output-formats plan." I verified this claim -- the current `protocol.py` line 55 does indeed contain `target_path: str = ""`. This finding from round 1 was based on a discrepancy between the output-formats plan text and the implemented code; the revised plan correctly identifies that the implementation already includes the parameter.

### Optional Suggestions

**1. Note the CLAUDE.md tool count update explicitly.**
**Status: Resolved.**
Line 193 states: "bringing the total tool count from 5 to 7. CLAUDE.md must be updated (Task 7.1) to reflect this." Task 7.1 (line 1280) specifies the exact change: '"5 tools" -> "6 tools (deep_scan_fuzz deferred pending container backend)"'. The count is 6 active (not 7) because `deep_scan_fuzz` is deferred and not registered.

**2. `rich` fallback behavior should be specified.**
**Status: Resolved.**
Assumption #6 (line 38) states: "When not installed, the fuzzer falls back to `logging.StreamHandler` with basic formatting." Deviation #4 (line 1413) reiterates the same.

**3. Consider `--fn` or `--func` instead of `-F` for `--function`.**
**Status: Acknowledged (no change needed).**
The plan uses `-F`. This was an optional suggestion; `-F` is a valid choice.

**4. Consent migration race condition.**
**Status: Resolved.**
Line 505 states: "The copy uses a temporary file + rename pattern to avoid race conditions if two processes attempt migration simultaneously." Task 2.4 (line 1090) reiterates: "copy, not move; temp file + rename." Test case `test_consent_migration_atomicity` (line 998) covers this.

**5. `FuzzReport.config_summary` typed as `dict`.**
**Status: Resolved.**
Line 412 states: "A `FuzzConfigSummary` Pydantic model is defined in `shared/formatters/protocol.py` for the formatter DTO layer, providing typed access for formatters." Task 1.2 (line 1040) includes `FuzzConfigSummary` in the list of models to add. The internal `FuzzReport.config_summary` remains `dict` (avoiding API key leakage), while the formatter-facing DTO uses the typed model.

### Archived Plans Metadata

**Round 1 finding:** `archived_plans_consulted` referenced a deleted file.
**Status: Resolved.**
Line 1425 now reads: `archived_plans_consulted: none (previously referenced plans/archive/output-formats/output-formats.feasibility.md which was not accessible at planning time)`.

---

## Context Alignment Verification

The Context Alignment section (lines 1377-1419) has been substantially expanded and addresses all round-1 historical alignment issues:

- **Formatter protocol:** Explicitly states the `Formatter` protocol is unchanged and introduces `FuzzFormatter` as a separate protocol (lines 1397, 1403).
- **`target_path` parameter:** Historical Alignment Note #1 (line 1401) correctly identifies this as already present in the codebase, not a new addition.
- **CLAUDE.md tool count:** Line 1392 specifies the update from 5 to 6 active tools with `deep_scan_fuzz` deferred.
- **Security deviations:** Both SD-01 (rlimits-only sandbox) and SD-02 (`eval()` usage) are cross-referenced in the Context Alignment section (lines 1388, 1417-1419).
- **`input_validator.py`:** Explicitly addressed at line 1390.
- **All CLAUDE.md patterns listed with compliance status** (lines 1379-1392).

## Context Metadata Block

The metadata block (lines 1421-1430) is present and accurate:
- `claude_md_exists: true` -- correct.
- `recent_plans_consulted` lists both relevant plans.
- `archived_plans_consulted` corrected to `none` with explanation.
- `review_artifacts_addressed` lists all three review artifacts (redteam, review, feasibility) with specific finding IDs.

## New CLAUDE.md Conflicts

None identified. The revised plan:
- Does not introduce any new `eval()` usage beyond what is already justified in SD-02.
- Does not add `shell=True` subprocess calls.
- Does not bypass path validation.
- Does not modify the existing `Formatter` protocol.
- Correctly defers MCP tool registration until container-based sandboxing is available.
- Specifies updating CLAUDE.md's tool count in Task 7.1.

## Required Edits

None.

## Optional Suggestions

1. **Task 7.1 tool count arithmetic.** The plan states the tool count goes from 5 to 7 (line 193) but Task 7.1 updates CLAUDE.md to say "6 tools (deep_scan_fuzz deferred)" (line 1280). This is internally consistent (6 registered + 1 deferred = 7 total designed), but a brief parenthetical at line 193 clarifying "from 5 to 7 (6 active, 1 deferred)" would prevent confusion during implementation.

2. **`preexec_fn` deprecation.** The risk table (line 782) notes `preexec_fn` is deprecated in Python 3.12+ and suggests migration as post-merge tech debt. Consider adding this to the Known Limitations section in the CLAUDE.md update (Task 7.1) so it is tracked alongside the `eval()` exception.

---

**Reviewer:** Librarian (automated)
**Plan status:** APPROVED -- ready for implementation.
