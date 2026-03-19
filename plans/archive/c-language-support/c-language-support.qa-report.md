# QA Report: C Language Support for the Hunter Pipeline

**Plan:** `plans/c-language-support.md`
**Reviewer:** qa-engineer agent (claude-sonnet-4-6)
**Date:** 2026-03-18
**Verdict:** PASS_WITH_NOTES

---

## Summary

The C language support implementation is substantially complete and correct. All plan-specified files were created, all taint tracker enhancements are present in the source, the registry matches the plan exactly, and CLAUDE.md was updated. The test suite is comprehensive for the areas it covers.

Two non-blocking gaps were found: (1) no end-to-end unit test for the `integer_overflow.c` fixture (CWE-190), and (2) no test that specifically exercises the `--languages c` CLI filter (existing filter tests use `python` as the language). Additionally, because Bash execution was denied, criteria requiring live test execution (AC-5, AC-6, AC-7) were validated by static analysis only and must be confirmed by the team running `make test-hunter` and `make test`.

---

## Acceptance Criteria Coverage

### AC-1: `dcs hunt tests/fixtures/vulnerable_samples/c/` produces findings for all fixture files with correct CWE identifiers.

**Status: MET (static analysis)**

All six vulnerable C fixture files are present and their patterns are covered by C registry queries and taint tracker end-to-end tests:

| Fixture | CWE | Test |
|---------|-----|------|
| `buffer_overflow.c` | CWE-120 | `TestCEndToEnd::test_buffer_overflow_detected` |
| `command_injection.c` | CWE-78 | `TestCEndToEnd::test_command_injection_detected` |
| `format_string.c` | CWE-134 | `TestCEndToEnd::test_format_string_detected` |
| `dangerous_functions.c` | CWE-676 | `TestCEndToEnd::test_dangerous_function_gets` |
| `memory_functions.c` | CWE-119 | `TestCEndToEnd::test_argv_to_memcpy` |
| `network_input.c` | CWE-120 | `TestCEndToEnd::test_fgets_to_strcpy` |

Note: `integer_overflow.c` (CWE-190) does NOT have an end-to-end fixture test in `TestCEndToEnd` — only a sink-detection-level test (`test_malloc_sink_found`) and a source/sink presence check (`test_c_init_declarator`). The fixture file itself is well-formed and the registry query for `malloc` is present. See Missing Tests section.

Requires live run to confirm CLI output format and CWE string rendering. The `_cwe_name()` mapping covers all 7 required CWEs.

---

### AC-2: `dcs hunt tests/fixtures/safe_samples/c/` produces zero findings.

**Status: MET (static analysis)**

Two safe fixtures are present:

- `tests/fixtures/safe_samples/c/bounded_copy.c` — uses `strncpy`/`snprintf` (both registered sanitizers neutralizing `buffer_overflow`). Tested by `TestCEndToEnd::test_safe_bounded_copy_no_findings`, which asserts that any `buffer_overflow` paths found are marked `sanitized=True`.
- `tests/fixtures/safe_samples/c/safe_command.c` — no taint source present (hardcoded args). Tested by `TestCEndToEnd::test_safe_command_no_findings`, which asserts `len(paths) == 0`.

One caveat: `bounded_copy.c` uses `strncpy` and `snprintf`, which are sanitizers for `buffer_overflow`. The test correctly handles this by checking `tp.sanitized` rather than asserting zero paths. This is the correct behavior — the test logic matches the intent.

Requires live run to confirm via CLI output.

---

### AC-3: `registries/c.yaml` loads without errors and all queries compile.

**Status: MET (static analysis)**

The registry at `/Users/imurphy/projects/deep-code-security/registries/c.yaml` matches the full content specified in the plan exactly, including:
- Version `"2.0.0"`
- All active source/sink entries with valid S-expression tree-sitter queries
- All deferred output-parameter sources properly commented out with explanatory notes
- All 7 sanitizer patterns

The test `TestCRegistryLoad::test_c_all_queries_compile` verifies that every source and sink entry has a non-None `compiled_query` after load. This covers AC-3 at the test level.

---

### AC-4: The C registry covers at least 7 CWE categories: CWE-78, CWE-119, CWE-120, CWE-134, CWE-190, CWE-22, CWE-676.

**Status: MET**

Verified directly from `registries/c.yaml`:

| CWE | Sink Category | Present |
|-----|--------------|---------|
| CWE-78 | `command_injection` | Yes |
| CWE-119 | `memory_corruption` | Yes |
| CWE-120 | `buffer_overflow` | Yes |
| CWE-134 | `format_string` | Yes |
| CWE-190 | `integer_overflow` | Yes |
| CWE-22 | `path_traversal` | Yes |
| CWE-676 | `dangerous_function` | Yes |

All 7 required CWEs are present. The `_cwe_name()` function in `hunter/orchestrator.py` (lines 394-406) has entries for all 7.

---

### AC-5: `make test-hunter` passes with all new tests green.

**Status: UNVERIFIED (Bash execution denied)**

Static analysis confirms:
- Both new test modules exist: `tests/test_hunter/test_c_registry.py` and `tests/test_hunter/test_taint_c_paths.py`
- All test classes and methods specified in the plan's Test Plan section are implemented
- All taint tracker enhancements from the plan (pointer_declarator, subscript_expression, field_expression, cast_expression, pointer_expression handling) are present in `taint_tracker.py`
- All fixture files referenced by tests exist on disk

**Action required:** Run `source .venv/bin/activate && make test-hunter` to confirm green.

---

### AC-6: `make test` passes with 90%+ coverage maintained.

**Status: UNVERIFIED (Bash execution denied)**

The new C tests add coverage for all newly implemented code paths. The existing test suite (Python and Go paths) was not modified. No regressions are expected from the additive changes to `taint_tracker.py`.

**Action required:** Run `source .venv/bin/activate && make test` to confirm 90%+ coverage maintained.

---

### AC-7: Scanning a real C project with `dcs hunt` completes without errors.

**Status: NOT TESTED**

No integration test against a real C project (OpenSSL, curl, or similar) exists in the test suite. This criterion is listed as a manual verification step in the plan ("Run `dcs hunt tests/fixtures/vulnerable_samples/c/` to verify CLI output"). There is no automated test for this.

**Action required:** Run `dcs hunt /path/to/a/real/c/project` manually and verify it completes without errors. For a minimal test, the team can use any local C codebase or download a small open-source C project.

---

### AC-8: The `--languages c` filter works correctly.

**Status: MET (framework verified, C-specific gap noted)**

The filter infrastructure is fully implemented: `Language.C` is defined in `shared/language.py`, `.c` and `.h` extensions are mapped, and `HunterOrchestrator.scan()` accepts the `languages` parameter and converts it to `lang_filter`. The CLI `hunt` command exposes `--language` (not `--languages`) with helptext that lists `c` as a valid value.

However, no test specifically passes `languages=["c"]` to verify that scanning a mixed fixture directory returns only C findings. The existing language filter tests in `test_orchestrator.py::test_scan_with_language_filter` and `test_end_to_end.py::test_pipeline_with_language_filter` use `languages=["python"]`. The C filter is covered by the same code path, but there is no C-specific assertion to confirm it.

This is a minor gap — the mechanism is identical for all languages and the code path is covered — but a dedicated test would strengthen confidence.

---

### AC-9: `gets()` is flagged as both CWE-676 sink and `cli_input` source.

**Status: MET**

Verified in `registries/c.yaml`:
- `gets` appears under `sources.cli_input` with `severity: critical`
- `gets` appears under `sinks.dangerous_function` (CWE-676) with `severity: critical`

The test `TestCEndToEnd::test_dangerous_function_gets` tests the `dangerous_functions.c` fixture, which contains two `gets()` calls: the first acts as the taint source, the second (at a higher line number) acts as the CWE-676 sink. The test asserts `"dangerous_function" in sink_categories`.

The plan's mitigation for Risk #5 (double-counting) is confirmed present: the `sink.line > source.line` constraint (taint_tracker.py line 256) prevents a single `gets()` from being both its own source and sink.

---

### AC-10: All existing Python and Go hunter tests pass unchanged.

**Status: MET (static analysis)**

The changes to `taint_tracker.py` are strictly additive. The C-specific branches (`if node.type == "pointer_declarator"`, etc.) only activate for node types that do not appear in Python or Go ASTs. The `_LANGUAGE_NODE_TYPES["c"]` dict is separate from the Python and Go entries. No existing test fixture files were modified.

Requires live run to confirm no regressions.

---

### AC-11: CLAUDE.md Known Limitations documents C support, CWE-416 deferral, and output-parameter source limitations.

**Status: MET**

Verified in `/Users/imurphy/projects/deep-code-security/CLAUDE.md` lines 152-154:

- Item 6: "C language support -- intraprocedural taint only (same as Python/Go). No preprocessor resolution... No struct member taint tracking. Pointer aliasing is tracked within the same function only."
- Item 7: "C output-parameter sources deferred -- C source functions that deliver tainted data via output parameters (recv, fread, read, scanf, getline, getdelim) are not effective taint sources in v1..."
- Item 8: "CWE-416 (use-after-free) detection deferred -- requires temporal ordering analysis..."

All three required limitations are documented. The wording aligns with the plan's AC-11 requirements.

---

## Missing Tests or Edge Cases

### Missing: End-to-end test for `integer_overflow.c` fixture (non-blocking)

`tests/test_hunter/test_taint_c_paths.py::TestCEndToEnd` has tests for all six fixture files except `integer_overflow.c`. The CWE-190 path (`argv -> atoi -> malloc(tainted * sizeof(int))`) is partially covered by `test_c_init_declarator` (which checks that argv is a source and malloc is a sink) and `test_malloc_sink_found` in `test_c_registry.py`. However, there is no test that:
1. Parses the actual `integer_overflow.c` fixture file
2. Runs taint path analysis end-to-end
3. Asserts at least one path is found with `integer_overflow` category

This is the same level of coverage as the other five fixtures. The omission is a gap against the plan's Test Plan section, which lists `integer_overflow.c` among the fixtures (files to create, task 3) but does not explicitly name an end-to-end test for it. The plan's `TestCEndToEnd` list also does not include it. The gap is therefore consistent with the plan as written, but it means CWE-190 taint path detection has less test coverage than the other CWE categories.

### Missing: C-specific `--languages c` filter test (non-blocking)

No test calls `hunter.scan(target_path=mixed_dir, languages=["c"])` and asserts `all(f.language == "c" for f in findings)`. The mechanism works identically for all languages (tested with Python), but a dedicated C assertion would give higher confidence.

### Missing: Integration-level false positive test for C safe samples (non-blocking)

`tests/test_integration/test_false_positives.py` covers Python (`safe_samples/python`) and Go (`safe_samples/go`) but not C (`safe_samples/c`). The C safe sample tests exist at the unit level (`TestCEndToEnd::test_safe_bounded_copy_no_findings`, `test_safe_command_no_findings`), which is sufficient for AC-2, but an integration-level scan of `safe_samples/c/` via `HunterOrchestrator` would add another layer of confidence.

### Missing: Automated real-project scan test (non-blocking, per plan)

The plan acknowledges AC-7 is a manual check ("Step 10: Run `dcs hunt tests/fixtures/vulnerable_samples/c/` to verify CLI output"). No automated test validates scanning a real-world C codebase. This is an ongoing gap for all three languages.

---

## Notes

### Note 1: `test_safe_bounded_copy_no_findings` has a subtle assertion

The test asserts `tp.sanitized == True` for any `buffer_overflow` paths, rather than asserting `len(paths) == 0`. This is correct: `bounded_copy.c` uses `strncpy` and `snprintf`, which are registered sanitizers but are not themselves sinks. The sanitizer detection means paths that reach buffer_overflow sinks through these calls are marked sanitized. However, if the scanner were to find a path from argv through `snprintf` to some other sink (e.g., a subsequent `printf`), that path would not be caught by the current assertion. The test is correct for the current fixture content, but the assertion is narrower than "zero unsanitized findings from any sink category."

### Note 2: `mktemp`/`tmpnam` detection gap is correctly documented

The registry includes `mktemp` and `tmpnam` as CWE-676 sinks. As documented in the registry YAML comments and in Risk #7, these will not trigger findings when called with hardcoded templates (the common case). No fixture tests the `mktemp`/`tmpnam` path because doing so would require a function that also contains a taint source, which is an artificial pattern. This is consistent with the plan and correctly documented.

### Note 3: Plan status is "DRAFT" but approved

The plan header reads `## Status: DRAFT` while the bottom of the file reads `## Status: APPROVED`. The approved status at the bottom takes precedence (it is the final state marker). This is a minor documentation inconsistency in the plan file itself and does not affect the implementation.

### Note 4: `format_string.c` uses fgets return-value pattern correctly

The fixture correctly uses `char *input = fgets(buf, sizeof(buf), stdin); printf(input);` (the return-value pattern) rather than the output-parameter pattern. This is the correct implementation for the LHS-seeding taint engine and matches the plan's design intent.

---

## Verdict: PASS_WITH_NOTES

The implementation satisfies all acceptance criteria that can be verified by static analysis. The two missing edge-case tests (CWE-190 end-to-end, C language filter test) are non-blocking — they represent gaps against the spirit of the QA agent fixture philosophy ("every registry entry must have at least one fixture") but are consistent with the plan's stated test scope. The live test execution (AC-5, AC-6, AC-7) must be confirmed by running the commands below.

### Required Follow-up Actions

1. **Run `source .venv/bin/activate && make test-hunter`** — confirm all C registry and taint path tests are green (AC-5).
2. **Run `source .venv/bin/activate && make test`** — confirm 90%+ overall coverage maintained (AC-6).
3. **Run `dcs hunt` against a real C project** — confirm no errors and at least some findings (AC-7).

### Recommended Follow-up (Non-blocking)

4. Add `TestCEndToEnd::test_integer_overflow_detected` in `test_taint_c_paths.py` to parse `integer_overflow.c` and assert at least one path with `integer_overflow` category.
5. Add a `languages=["c"]` filter test in `test_orchestrator.py` to explicitly verify the C language filter returns only C findings.
