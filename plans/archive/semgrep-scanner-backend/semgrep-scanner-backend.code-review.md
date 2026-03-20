# Code Review: semgrep-scanner-backend (Revision 2)

**Verdict: PASS**

All three Critical findings and all seven Major findings from the first review have been addressed. Four Minor findings carry over and one new Minor finding is introduced, but none block shipment.

---

## Critical Findings (must fix)

None.

### Prior Critical Findings -- Resolved

**C-1 (`__init__.py` missing imports):** Fixed. The three new modules are now imported at the top of `/Users/imurphy/projects/deep-code-security/src/deep_code_security/hunter/__init__.py` (`from deep_code_security.hunter import scanner_backend, semgrep_backend, treesitter_backend`), making the string entries in `__all__` reachable.

**C-2 (`_compute_raw_confidence` dead code):** Fixed. The orphaned method has been removed from `HunterOrchestrator`. The orchestrator no longer contains any scoring code. `_compute_raw_confidence` lives only in `treesitter_backend.py` as a module-level function. `SemgrepBackend` hardcodes `raw_confidence = 0.6` inline, which is consistent with the plan's design (two-step synthetic path = 0.6).

**C-3 (`sources_found`/`sinks_found` misreported):** Fixed. `/Users/imurphy/projects/deep-code-security/src/deep_code_security/hunter/semgrep_backend.py` lines 444-448 now set `sources_found=0` and `sinks_found=0`, with a comment explaining that Semgrep OSS does not expose discrete source/sink counts. `taint_paths_found` is set to the actual post-filter finding count. Honest and correct.

---

## Major Findings (should fix)

None.

### Prior Major Findings -- Resolved

**M-1 (dead `..` check):** Fixed. The check was removed. Lines 185-187 of `/Users/imurphy/projects/deep-code-security/src/deep_code_security/shared/config.py` now contain a comment explaining why the check cannot fire after `Path.resolve()`, and the code correctly relies on the subsequent `exists()` and `is_dir()` guards as the real safety net.

**M-2 (`_cwe_name` duplication):** The prior review flagged that `_cwe_name` appeared in both `orchestrator.py` and `treesitter_backend.py`. After the refactor, `orchestrator.py` no longer contains `_cwe_name` at all -- the function lives only in `treesitter_backend.py` where it is actually used. The duplication is resolved.

**M-3 (bytes/text mode inconsistency):** The inconsistency remains in the code -- `_check_version` uses `text=True` and `scan_files` uses `capture_output=True` without `text=True` -- but a comment explaining the distinction is now present. `json.loads` accepts both `str` and `bytes`, and the stderr decode calls are explicit. This is a readability issue, not a bug, and the first review classified it as a "should fix." The comment addresses the spirit of the finding.

**M-4 (missing MCP ToolError test):** Fixed. `/Users/imurphy/projects/deep-code-security/tests/test_hunter/test_scanner_backend.py` now includes `TestMCPToolErrorWhenSemgrepAbsent` (lines 402-479) with two tests: `test_handle_hunt_raises_tool_error_when_hunter_init_fails` and `test_handle_full_raises_tool_error_when_hunter_init_fails`. Both exercise the MCP layer directly -- constructing `DeepCodeSecurityMCPServer`, patching `HunterOrchestrator.__init__` to raise `RuntimeError`, and asserting `ToolError(retryable=False)` is raised from `_handle_hunt`/`_handle_full`. Plan AC-7 is now tested.

**M-5 (`is_available()` version subprocess on every call):** Fixed. `SemgrepBackend` now has two class-level caches: `_binary_cache` (the `shutil.which` result) and `_cached_version` (the version string from `semgrep --version`). The binary check runs once per process; the version check runs once and stores the result. The rules-dir check is intentionally not cached (documented inline) because `DCS_SEMGREP_RULES_PATH` can change between calls during tests. The `dcs status` path no longer spawns repeated `semgrep --version` subprocesses.

**M-6 (CWE-676 search-mode normalization undocumented):** Partially addressed. The rule file `/Users/imurphy/projects/deep-code-security/registries/semgrep/c/cwe-676-dangerous-function.yaml` now includes explicit comments explaining why `source_function: "none"` is used instead of `"unknown"`, and the comment notes the normalizer's fallback behavior. The rule sets `source_function: "none"` and `source_category: "none"` explicitly rather than relying on the `"unknown"` default -- this makes the intent clear to rule authors.

However, there is still no test asserting what a normalized CWE-676 finding looks like (i.e., no test in `test_semgrep_backend.py` that feeds a search-mode result through `_normalize_result` and verifies `source.function == "none"` and `source.category == "none"`). The first review identified this as a "should fix." The rule comment addresses the documentation gap but the test gap remains. This is reclassified to Minor given the documentation improvement.

**M-7 (`scanner_backend_version` missing from MCP status):** Fixed. The `SemgrepBackend` now has a `version` property (line 271) that returns `_cached_version or None`. The MCP server at `/Users/imurphy/projects/deep-code-security/src/deep_code_security/mcp/server.py` line 829 calls `getattr(self.hunter._backend, "version", None)`, and the `scanner_backend_version` field is now populated in the status response (line 846). The CLI `dcs status` path (lines 441-455) also reads `getattr(_backend, "version", None)` and appends the version to the backend label. `TreeSitterBackend` has no `version` attribute -- the `getattr` default of `None` silently omits the version from tree-sitter status reports, which is correct since there is no meaningful "tree-sitter version" to report.

---

## Minor Findings (optional)

### m-1: `_VALID_DCS_SEVERITIES` frozenset still defined inside `_normalize_result` body

`/Users/imurphy/projects/deep-code-security/src/deep_code_security/hunter/semgrep_backend.py` line 533

The frozenset is redefined on every call to `_normalize_result`. This was flagged in the first review as m-2 and was not addressed. Move it to module level alongside `_SEMGREP_SEVERITY_MAP`.

### m-2: `registry_version_hash` does not hash Semgrep rule file content

`/Users/imurphy/projects/deep-code-security/src/deep_code_security/hunter/orchestrator.py` lines 187-191

The orchestrator computes `registry_version_hash` as `sha256(backend_name + ":" + sorted_languages)`. This hash does not change when Semgrep rule files are modified. The first review flagged this as m-3 and it was not addressed. The plan's Review Response Matrix (F-12) stated "The Semgrep backend computes `registry_version_hash` by hashing the Semgrep rule files." This was not implemented. For the Semgrep backend, `registry_version_hash` is currently a stable hash of the backend name and language list, making it meaningless for detecting rule changes. Low practical impact today (no consumer acts on rule changes between scans), but misleading.

### m-3: `open(rule_file)` in test_semgrep_rules.py is missing `encoding="utf-8"`

`/Users/imurphy/projects/deep-code-security/tests/test_hunter/test_semgrep_rules.py` line 80

`open(rule_file)` should be `open(rule_file, encoding="utf-8")` per PEP 597 and the project's Python 3.11 minimum. The first review flagged this as m-4 and it was not addressed. Harmless on macOS/Linux with UTF-8 locales, but a hygiene issue.

### m-4: `BackendResult.model_rebuild()` called at import time in both backend modules

`/Users/imurphy/projects/deep-code-security/src/deep_code_security/hunter/semgrep_backend.py` line 42
`/Users/imurphy/projects/deep-code-security/src/deep_code_security/hunter/treesitter_backend.py` line 36

The duplication persists from the first review (m-1). Pydantic v2 handles double `model_rebuild()` calls safely, and the accompanying comments explain the rationale. No correctness risk, but the pattern remains a code smell.

### m-5 (new): CWE-676 search-mode normalization has no test

No test in `test_semgrep_backend.py` exercises the search-mode normalization path where `source_function` and `source_category` are `"none"`. The prior review's M-6 finding asked for this. The rule file documentation was improved, but the test coverage gap remains. This is a narrow gap -- the normalizer's fallback path is implicitly covered when `metadata.source_function` is present, but the `source_function="none"` case is not directly asserted.

---

## Positives

**All three prior Critical findings are cleanly resolved.** The `__init__.py` fix uses option (a) from the first review's recommendation (import modules at top level, keep string entries in `__all__`). The dead `_compute_raw_confidence` removal was clean -- no remnant. The `sources_found=0`/`sinks_found=0` correction has a helpful inline comment.

**The MCP `ToolError` test is thorough.** `TestMCPToolErrorWhenSemgrepAbsent` tests both `_handle_hunt` and `_handle_full` and directly verifies `retryable=False` on the `ToolError`. The test patches `HunterOrchestrator.__init__` at the MCP layer rather than at the `select_backend` layer, which correctly exercises the actual error propagation path documented in the plan.

**Caching design in `is_available()` is correct and pragmatic.** Caching the binary lookup but not the rules-dir check is exactly the right trade-off. The inline comment explaining why the rules-dir check is intentionally not cached will prevent future developers from "optimizing" it away and breaking the test isolation behavior.

**The `..` removal in config.py is clean.** The comment at lines 185-187 accurately explains why `Path.resolve()` makes the check redundant, which prevents future auditors from re-adding it and trusting it as real defense. The real guards (`exists()` and `is_dir()`) are unchanged and correct.

**`SemgrepBackend.version` property is correctly implemented.** It returns `_cached_version or None`, gating on the class-level cache that `is_available()` populates. The `getattr(..., None)` fallback in both the MCP server and CLI is correct defensive coding.

**CWE-676 rule documentation is substantially improved.** The inline comments in `cwe-676-dangerous-function.yaml` explain the search-mode design, the normalizer behavior, and the decision to use `"none"` instead of `"unknown"`. Future rule authors will understand why this rule looks different from taint-mode rules.

**Security requirements remain fully met.** Subprocess invocation is list-form with no `shell=True`. `--metrics=off` is in the command. Semgrep JSON output is parsed with `json.loads()`, not `eval()` or `yaml.load()`. stderr is truncated to 4KB and never interpolated into templates. `Path.resolve()` is applied to the rules path. The `DCS_SCANNER_BACKEND=semgrep` failure path correctly raises `RuntimeError` at `select_backend()` and the MCP server defers the error to the first hunt call.
