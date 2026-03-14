# Red Team Review (Round 2): Merge fuzzy-wuzzy into deep-code-security

<!-- Review Metadata
reviewer_role: security-analyst
review_round: 2
review_date: 2026-03-14
plan_reviewed: plans/merge-fuzzy-wuzzy.md (revised)
plan_status: DRAFT
prior_review: plans/merge-fuzzy-wuzzy.redteam.md (round 1, 2026-03-14)
source_code_verified:
  - fuzzy-wuzzy/src/fuzzy_wuzzy/execution/_worker.py (eval_expression, RESTRICTED_BUILTINS)
  - fuzzy-wuzzy/src/fuzzy_wuzzy/ai/response_parser.py (_validate_expression, ALLOWED_NODE_TYPES)
  - fuzzy-wuzzy/src/fuzzy_wuzzy/orchestrator.py (signal handler installation at line 56-65)
  - fuzzy-wuzzy/src/fuzzy_wuzzy/plugins/registry.py (_load_plugins eager instantiation)
  - fuzzy-wuzzy/src/fuzzy_wuzzy/execution/runner.py (_build_env, no PYTHONSAFEPATH)
  - fuzzy-wuzzy/src/fuzzy_wuzzy/corpus/serialization.py (deserialize_fuzz_result, no re-validation)
  - deep-code-security/src/deep_code_security/mcp/path_validator.py (validate_path, no write distinction)
-->

## Verdict: PASS

All Critical findings from round 1 have been resolved. All Major findings have been resolved or adequately addressed. No new Critical findings were introduced by the revision. The plan may proceed to approval.

---

## Round 1 Finding Resolution

### CRITICAL-01: Sandbox Isolation Regression -- rlimits vs Container-Based Sandboxing

**Round 1 Severity:** Critical
**Resolution:** Resolved
**Approach taken:** Option (B) from the round 1 recommendation.

The revised plan adopts the strongest of the three recommended mitigations: `deep_scan_fuzz` is NOT registered as an MCP tool. The plan explicitly states (line 197): "The `deep_scan_fuzz` tool is a CLI-only feature in this plan. It is NOT exposed as an MCP tool until the container-based sandbox backend is implemented."

Specific evidence of thorough resolution:

1. **MCP tool deferred, not just gated.** The tool is not registered in the MCP server at all (Task 5.2 says "Do NOT register the tool in the tool list"). This is stronger than a runtime check, which could be bypassed. The `_handle_fuzz()` stub raises `ToolError` if somehow called.

2. **Only `deep_scan_fuzz_status` is active.** This tool performs no code execution -- it reports availability, consent status, and whether the container backend is ready. This is safe.

3. **Security Deviation SD-01 is well-documented.** The plan includes a full comparison table of DCS Auditor vs Fuzzer isolation (lines 808-817), an honest justification (the fuzzer executes user's own code, not fully untrusted code), compensating controls (PYTHONSAFEPATH, AST validation, DCS_ALLOWED_PATHS), and a concrete resolution path (implement ContainerBackend post-merge, listed as feature #5).

4. **MCP-triggered fuzz runs require the container backend exclusively** (line 224): "MCP-triggered fuzz runs use the container backend exclusively (rlimit-only backend is rejected)." This ensures that when the tool is eventually enabled, it cannot fall back to the weaker isolation model.

5. **Acceptance criterion #17** (line 1022): "deep_scan_fuzz MCP tool is NOT registered (deferred until container backend)."

6. **Non-Goals updated** (line 29): "Implementing the `ContainerBackend` for the fuzzer sandbox in this plan (deferred; see Security Deviation SD-01)."

7. **Risk table entry** (line 776) explicitly marks the MCP exposure risk as "N/A" with "Mitigated by design."

**Residual concern (Minor):** The CLI `dcs fuzz` command still uses rlimit-only isolation. This is acceptable because: (a) the user explicitly invokes the CLI and selects the target, (b) the fuzzer executes the user's own code, analogous to running `pytest`, and (c) the plan documents this clearly. However, the CLI should print a warning that fuzz targets execute with full host privileges. The plan does not explicitly include this warning message in the CLI design. This is tracked under residual concern RC-01 in the New Findings section.

---

### CRITICAL-02: Expression Evaluation Uses `eval()` with Insufficient Restriction in _worker.py

**Round 1 Severity:** Critical
**Resolution:** Resolved

The revised plan implements the primary recommendation -- moving AST validation into `_worker.py` so it runs independently of the response parser. The fix is comprehensive:

1. **Shared expression validator module** (Task 2.5, line 1093): `_validate_expression()` is extracted into `fuzzer/ai/expression_validator.py`. Both `response_parser.py` and `_worker.py` import from this module. This eliminates the TOCTOU gap.

2. **Dual-layer defense documented in SD-02** (lines 836-841): Layer 1 (response_parser.py) validates before serialization. Layer 2 (_worker.py) validates before `eval()`. The plan explicitly states both layers are independent.

3. **`memoryview` removed from RESTRICTED_BUILTINS** (Task 2.7, line 1115): "Remove `memoryview` from `RESTRICTED_BUILTINS` in `_worker.py`." This addresses the secondary concern about memory probing vectors.

4. **Trust Boundary Analysis corrected** (line 790): The revised plan accurately states "Additionally, `_worker.py` independently validates expressions via the same AST allowlist before calling `eval()` with restricted globals." The misleading "no eval()" claim from round 1 is replaced with an honest description of the dual-layer defense.

5. **Corpus replay re-validates expressions** (lines 622, 663): `deserialize_fuzz_result()` re-validates all expression strings through the AST allowlist when loading for replay. This closes the corpus tampering vector.

6. **Security-critical test cases added** (lines 955-959): Tests cover `_worker.py` rejecting subclass attacks, import expressions, tampered corpus files, and direct worker invocation.

7. **Acceptance criterion #15** (line 1020): "The `_worker.py` `eval()` call is preceded by AST validation."
   **Acceptance criterion #18** (line 1023): "Expression strings are re-validated on corpus replay load."

8. **Context Alignment section corrected** (line 1388): Now explicitly states the `eval()` is a "justified deviation" from CLAUDE.md, documented in SD-02.

The IPC file integrity checksums (HMAC) recommended in round 1 were not adopted. This is acceptable because the AST validation at the `eval()` call site makes corpus tampering ineffective -- even if the JSON is modified, the malicious expressions are rejected before evaluation. The dual-layer defense is stronger than integrity-only protection (which would fail open if the key is compromised).

---

### MAJOR-01: MCP Consent Model is Bypassable by Replay and Corpus Paths

**Round 1 Severity:** Major
**Resolution:** Resolved

The revised plan addresses all three sub-issues:

1. **Consent scope clarified** (line 503): "The `consent` flag gates API data transmission (sending source code to the Anthropic API). It does NOT gate code execution -- the fuzzer executes the user's own code on the host regardless of the consent flag." The plan no longer conflates the two threat models. The distinction between API transmission consent and code execution is explicit.

2. **MCP fuzz tool deferred** (resolving the primary attack vector): Since `deep_scan_fuzz` is not registered as an MCP tool, the MCP consent bypass via replay is not exploitable. An MCP client cannot trigger code execution through the fuzzer at all.

3. **Expression re-validation on corpus replay** (lines 622, 663, 669): `deserialize_fuzz_result()` validates all expression strings via the AST allowlist before returning `FuzzInput` objects. The replay runner (Task 2.13, line 1155) also re-validates. This means tampered corpus files with malicious expressions are rejected regardless of whether they were created by a legitimate fuzz run or crafted by an attacker.

4. **Acceptance criterion #18** (line 1023) codifies the re-validation requirement.

5. **No MCP replay tool is defined.** Replay remains CLI-only (the `dcs replay` command). This is the safest approach.

---

### MAJOR-02: Signal Handler in Orchestrator Conflicts with MCP Server Event Loop

**Round 1 Severity:** Major
**Resolution:** Resolved

The revised plan adopts the exact recommendation from round 1:

1. **`install_signal_handlers` parameter added** (lines 78, 655, 1164): `FuzzOrchestrator` accepts `install_signal_handlers: bool = True` in `__init__()`. When `False`, `_setup_signal_handlers()` is skipped.

2. **MCP handler uses `False`** (line 222): "The `FuzzOrchestrator` is instantiated with `install_signal_handlers=False`." Even though `deep_scan_fuzz` is currently deferred, the design is documented for when it is enabled.

3. **CLI uses `True`** (line 693, Task 4.1): "Instantiate `FuzzOrchestrator` with `install_signal_handlers=True`."

4. **Test case added** (lines 991-992): `test_orchestrator_no_signal_handlers` and `test_orchestrator_default_installs_handlers` verify both paths.

5. **Risk table entry** (line 781): "Mitigated by design."

6. **Acceptance criterion #20** (line 1025): "`FuzzOrchestrator` does not install signal handlers when `install_signal_handlers=False`."

---

### MAJOR-03: Fuzzer Plugin System Loads Arbitrary Code via Entry Points

**Round 1 Severity:** Major
**Resolution:** Resolved

The revised plan adopts all four recommendations from round 1:

1. **Lazy loading** (lines 441, 665, 1140): "`list_plugins()` returns registered names without instantiating plugin classes. Only `get_plugin(name)` instantiates." This prevents code execution just from listing plugins.

2. **`DCS_FUZZ_ALLOWED_PLUGINS` allowlist** (lines 442, 574, 665, 1141): Default is `"python"`. Plugins not in the allowlist are logged and skipped. The environment variable is added to `shared/config.py` (Task 1.1, line 1035).

3. **Source package logging** (lines 443, 665, 1142): "The source package of each loaded plugin is logged for audit purposes."

4. **Test cases added** (lines 986-988): `test_plugin_allowlist_default`, `test_plugin_allowlist_rejects_unknown`, and `test_plugin_lazy_loading`.

5. **Acceptance criterion #19** (line 1024): "Plugin registry respects `DCS_FUZZ_ALLOWED_PLUGINS` allowlist."

6. **Supply chain risk section** (lines 865-868) documents the mitigations.

The plan also adds backward compatibility with the old `fuzzy_wuzzy.plugins` entry point group (with deprecation warning, removal in v2.0.0 or 6 months). This is a reasonable transition strategy.

---

### MAJOR-04: `_worker.py` Executes User Module with Full PYTHONPATH Manipulation

**Round 1 Severity:** Major
**Resolution:** Resolved

The revised plan addresses all three recommendations:

1. **Documentation** (line 788): "This is rlimit-only isolation, not container isolation. The subprocess runs with the full host filesystem visible, no network isolation, and inherits the parent process's capabilities." The Trust Boundary Analysis is honest about the limitations.

2. **MCP blocked** (resolving the primary risk): Since `deep_scan_fuzz` is not an MCP tool, MCP clients cannot trigger module loading on arbitrary paths.

3. **`PYTHONDONTWRITEBYTECODE=1` and `PYTHONSAFEPATH=1` added** (lines 660, 788, 824, 1116): Task 2.7 explicitly calls out adding these environment variables to `_build_env()` in `runner.py`. `PYTHONSAFEPATH=1` prevents `.pth` processing and removes the current directory from `sys.path`, which mitigates the `.pth` injection vector identified in round 1.

I verified that the current fuzzy-wuzzy `runner.py:_build_env()` does NOT set these variables, confirming this is a genuine improvement introduced by the revised plan.

---

### MAJOR-05: Long-Running Fuzz Operations Block the MCP Server

**Round 1 Severity:** Major
**Resolution:** Resolved

The revised plan addresses all four recommendations, even though the MCP tool is deferred:

1. **Hard wall-clock timeout** (lines 221, 575): `DCS_FUZZ_MCP_TIMEOUT` (default 120 seconds) is defined as an environment variable. The design states "A hard wall-clock timeout caps execution time. The fuzzer saves partial results when the timeout expires."

2. **Background thread pattern** (lines 219-220): "Start the fuzz run in a background thread, returning immediately with `{status: running, fuzz_run_id: ...}`. The client polls `deep_scan_fuzz_status` with the `fuzz_run_id`." This async-start/poll-status pattern prevents blocking the MCP server.

3. **Reduced defaults for MCP** (line 207): MCP defaults are 3 iterations and 5 inputs per iteration (vs CLI defaults of 10/10), matching the round 1 recommendation.

4. **`deep_scan_fuzz_status` supports polling** (lines 226-237): When `fuzz_run_id` is provided, returns progress or final results.

Since the MCP tool is currently deferred, these are design specifications rather than implemented code. However, the specifications are detailed enough to be implementable correctly when the container backend is ready, and the acceptance criteria will enforce them.

---

### MAJOR-06: Corpus Directory Traversal -- Output Path is Not Adequately Constrained

**Round 1 Severity:** Major
**Resolution:** Resolved

The revised plan adds write-path constraints:

1. **Write-path validation** (lines 189, 693, 1206): "`--output-dir` directory for corpus/reports is also validated via `PathValidator`, with an additional write-path check that rejects paths inside `src/`, `registries/`, and `.git/`."

2. **Task 4.1** (line 1206): "Add write-path validation for `--output-dir` (reject `src/`, `registries/`, `.git/`)."

3. **Test case** (line 973): `test_dcs_fuzz_output_dir_write_validation` -- "`--output-dir ./src/` rejected."

The plan does not adopt the secondary recommendation of defaulting to `~/.cache/deep-code-security/fuzz-output/`. The default remains `./fuzzy-output` for backward compatibility with existing fuzzy-wuzzy users. This is acceptable because the write-path blocklist prevents the most dangerous locations, and `./fuzzy-output` is a reasonable default that is clearly distinct from source directories.

One gap: the blocklist (`src/`, `registries/`, `.git/`) does not include `plans/`, `tests/`, `sandbox/`, or `docs/`. Writing corpus JSON files into `tests/` or `plans/` is not a security vulnerability per se, but could cause confusion. This is a minor concern and does not warrant re-rating.

---

### Minor-01: `DCS_FUZZ_CONSENT` Environment Variable Undermines Consent Model Intentionality

**Round 1 Severity:** Minor
**Resolution:** Resolved

The revised plan adopts two of three recommendations:

1. **Warning logged** (line 484): "When consent is granted via this environment variable, a warning is logged: 'Consent granted via DCS_FUZZ_CONSENT environment variable. Source code will be transmitted to the Anthropic API.'"

2. **`.env` not read** (line 484): "The DCS config loader does not read `.env` files; this is a security invariant that must be preserved."

The variable was NOT renamed to `DCS_FUZZ_CONSENT_CI` as suggested. The plan keeps `DCS_FUZZ_CONSENT`. This is acceptable -- the warning log message adequately communicates the implications, and renaming could break existing CI configurations.

---

### Minor-02: Config TOML File API Key Loading Not Migrated to DCS Path

**Round 1 Severity:** Minor
**Resolution:** Resolved

The revised plan explicitly addresses the config file path migration (lines 482, 670-671):

1. **Primary path migrated** (line 482): "The primary path is `~/.config/deep-code-security/config.toml`."
2. **Old path as fallback** (line 482): "The old path is checked as a fallback with a deprecation warning."
3. **File permission checks preserved** (line 671): "File permission checks are preserved on the new path."
4. **Task 2.15** (line 1170-1172) codifies this with `from_dcs_config()` factory.

---

### Minor-03: `preexec_fn` is Deprecated in Python 3.12+ and Unsafe with Threads

**Round 1 Severity:** Minor
**Resolution:** Partially Resolved (remains Minor)

The revised plan acknowledges the issue in the risk table (line 782): "`SubprocessBackend` uses `preexec_fn=_apply_rlimits`. This is deprecated but functional through Python 3.13. Migration to `subprocess.Popen()` with `start_new_session=True` and a wrapper script is tracked as post-merge tech debt."

The plan does NOT fix `preexec_fn` in this merge. It explicitly defers the migration. This is acceptable for two reasons:

1. The fuzzer is CLI-only (no MCP), so the multi-threaded deadlock risk from the asyncio event loop is not triggered.
2. The MCP tool is deferred until the container backend is implemented, at which point the rlimit-based `SubprocessBackend` will not be used for MCP invocations.

However, the deprecation remains. When the container backend is implemented, if the rlimit backend is retained for CLI use, the `preexec_fn` issue will need to be addressed before Python 3.14+ where it may be removed. This is adequately tracked as tech debt.

---

### Minor-04: Prompt Injection via Source Code is Mitigated but Not Tested

**Round 1 Severity:** Minor
**Resolution:** Resolved

The revised plan adds the recommended test cases (lines 1000-1002):

1. `test_adversarial_docstring` -- "Target with 'Ignore all previous instructions' docstring does not alter prompt structure."
2. `test_json_in_comment` -- "Target with JSON-like comments does not produce spurious fuzz inputs."

The plan did not adopt the XML-escaping recommendation. This is acceptable since the XML delimiter approach is already implemented in the existing fuzzy-wuzzy codebase and the tests verify it works.

---

### Minor-05: Crash Signature SHA-256 Has No Salt -- Collision Risk for Dedup Evasion

**Round 1 Severity:** Minor
**Resolution:** Not Addressed (remains Minor)

The revised plan does not mention changes to the crash signature computation or dedup algorithm documentation. The `UniqueCrash` model (lines 374-382) retains the same fields as before. The SARIF mapping (lines 299-306) still uses `fuzzyWuzzyCrashSignature/v1` without specifying what inputs are hashed.

This remains a Minor finding. The attack scenario (an attacker who controls the target code crafting colliding crash signatures) is low-probability and requires the attacker to already have code execution -- at which point they have many easier attack paths.

**Re-rated severity: Minor (unchanged).**

---

### Minor-06: `--function` and `--format` CLI Options Both Use `-f` Short Flag

**Round 1 Severity:** Minor
**Resolution:** Resolved

The revised plan explicitly fixes this (line 168, 187, 1204):

- `--function` uses `-F` (capital)
- `--format` uses `-f`

Line 187: "CLI flag resolution: `--function` uses `-F` (capital) as its short flag. `-f` is reserved for `--format`, consistent with the existing `hunt` and `full-scan` commands per the output-formats plan."

Line 1204 (Task 4.1): "`--function` uses `-F` (capital), `--format` uses `-f`, `--output-file` uses `-o`."

---

### Info-01: Supply Chain -- `anthropic` SDK Brings Significant Transitive Dependency Tree

**Round 1 Severity:** Info
**Resolution:** Resolved

The revised plan adopts all three recommendations (lines 858-861):

1. "Run `pip-audit` on the full `[fuzz]` and `[vertex]` dependency trees as part of Phase 1."
2. "Pin `anthropic` to a specific minor version range (e.g., `>=0.25.0,<1.0.0`)." This is reflected in Task 1.4 (line 1051).
3. "Add `make audit-deps` target" -- Task 1.5 (line 1060).

The supply chain assessment table (lines 847-855) now rates `anthropic` as "Low-Medium" and includes the transitive dependency list.

---

### Info-02: The Plan Claims "No `eval()`" but the Codebase Uses `eval()`

**Round 1 Severity:** Info
**Resolution:** Resolved

The revised plan corrects the inaccurate statements:

1. **Trust Boundary Analysis** (line 790): Now accurately states `_worker.py` uses `eval()` with dual-layer AST validation.
2. **SD-02 section** (lines 830-841): Explicitly documents the `eval()` usage as a justified deviation from CLAUDE.md with full rationale.
3. **Context Alignment** (line 1388): "The fuzzer's `_worker.py` uses `eval()` with restricted globals -- this is a justified deviation from the CLAUDE.md `eval()` ban, documented in Security Deviation SD-02."
4. **CLAUDE.md update planned** (Task 7.1, line 1284): "Add `_worker.py` `eval()` to Known Limitations section with justification reference to SD-02."

---

### Info-03: No Rate Limiting on MCP `deep_scan_fuzz` Tool

**Round 1 Severity:** Info
**Resolution:** Partially Resolved (remains Info)

Since the MCP tool is deferred, this is not immediately exploitable. The plan does not add per-session cost tracking or `DCS_FUZZ_SESSION_COST_LIMIT`. However:

1. The per-invocation cost budget is preserved ($2 for MCP, $5 for CLI).
2. The tool is not registered, so the attack vector does not exist.
3. When the tool is eventually enabled, cost tracking should be added.

This remains informational. The deferred MCP tool design should include aggregate cost tracking when implemented.

---

## New Findings

### RC-01: CLI `dcs fuzz` Lacks Explicit Warning About Host-Privilege Execution

**Severity: Minor**
**STRIDE: Information Disclosure**

The plan documents in SD-01 that the fuzzer executes with full host privileges (rlimit-only isolation). However, the CLI `dcs fuzz` command design (Task 4.1) does not include a warning message to the user that their target code will be executed with full process privileges. The `--consent` flag only warns about API transmission, not about code execution.

When a user runs `dcs fuzz ./untrusted-project/module.py --consent`, the consent message covers API data transmission but not the fact that `module.py` and all its imports will be executed with the same privileges as the DCS process.

**Recommendation:**
- Add a one-time informational message on first CLI fuzz invocation: "Note: The fuzz target and its imports will be executed as a subprocess with the same privileges as the current user. Only fuzz code you trust."
- This is distinct from the API consent message and should appear regardless of consent status.

---

### RC-02: Backward-Compatible `fuzzy_wuzzy.plugins` Entry Point Group Widens Attack Surface During Transition

**Severity: Minor**
**STRIDE: Tampering**

The revised plan supports both the old `fuzzy_wuzzy.plugins` and new `deep_code_security.fuzzer_plugins` entry point groups during a transition period (line 443, 665, 1143). This means during the transition window, a malicious package could register under either group name.

The `DCS_FUZZ_ALLOWED_PLUGINS` allowlist mitigates this since it restricts by plugin *name*, not by entry point group. A plugin named "python" registered under the old group would need to collide with the built-in Python plugin name, which would be rejected as a duplicate.

However, a malicious package could register a plugin with a name that happens to be in the allowlist (if the user has expanded the allowlist beyond the default "python"). The dual-group support doubles the surface area for this attack.

**Recommendation:**
- Log a deprecation warning when a plugin is loaded from the old `fuzzy_wuzzy.plugins` group, including the source package name. This is already planned.
- Consider whether 6 months is too long for the transition period. If no external fuzzer plugins exist yet (which is likely since fuzzy-wuzzy is being merged), the old group can be removed immediately.

---

### RC-03: `DCS_FUZZ_MCP_TIMEOUT` Default of 120 Seconds May Be Excessive for Deferred Design

**Severity: Info**

The plan adds `DCS_FUZZ_MCP_TIMEOUT` with a default of 120 seconds (line 575). While the MCP tool is deferred, this timeout value is only a design specification. When the tool is eventually enabled:

- 120 seconds is reasonable for a fuzz run with 3 iterations and 5 inputs per iteration at 5 seconds per input (75 seconds compute + API latency).
- However, the async-start/poll-status pattern (line 219) means the client is not actually blocked for 120 seconds. The timeout is a server-side wall-clock cap.

No action required. This is informational for when the MCP tool is implemented.

---

## Container Security Assessment (Round 2)

The security asymmetry identified in round 1 (container-isolated auditor vs. rlimit-only fuzzer) remains architecturally unchanged. However, the revised plan's mitigation strategy is sound:

| Aspect | Round 1 Status | Round 2 Status |
|---|---|---|
| MCP exposure of fuzzer | Proposed as active tool | **Deferred** until container backend |
| Rlimit-only isolation | Only isolation available | Explicitly documented as CLI-only |
| Container backend | Stub (NotImplementedError) | Roadmapped as post-merge feature #5 |
| MCP tool design | Direct execution | Async-start/poll with wall-clock timeout |
| Container requirement for MCP | Not mentioned | **Mandatory** (line 224) |

The key improvement is the hard architectural gate: the MCP tool is NOT registered, not merely gated behind a runtime check. This means a code change is required to enable it, which provides an opportunity for security review when the container backend is implemented.

**Verdict on container security (Round 2):** The revised plan adequately contains the rlimit-only isolation risk by restricting it to CLI usage and deferring MCP exposure. The CLI threat model (user fuzzing their own code) does not require container isolation for the same reasons that `pytest` does not require container isolation.

## Supply Chain Risk (Round 2)

| Component | Round 1 Risk | Round 2 Risk | Change |
|---|---|---|---|
| `anthropic` SDK | Low-Medium | Low-Medium | Unchanged, but `pip-audit` planned |
| `google-auth` | Low | Low | Unchanged |
| `coverage` | Low | Low | Unchanged |
| `rich` | Low | Low | Unchanged |
| Entry points discovery | Medium | Low | Mitigated by allowlist + lazy loading |
| Corpus files (JSON) | Medium | Low | Mitigated by expression re-validation |

## Summary

| ID | Round 1 Severity | Resolution | Status |
|---|---|---|---|
| CRITICAL-01 | Critical | `deep_scan_fuzz` MCP tool deferred until container backend | **Resolved** |
| CRITICAL-02 | Critical | AST validation added to `_worker.py` via shared `expression_validator.py` | **Resolved** |
| MAJOR-01 | Major | Expression re-validation on corpus replay; consent scope clarified | **Resolved** |
| MAJOR-02 | Major | `install_signal_handlers` parameter added; `False` for MCP | **Resolved** |
| MAJOR-03 | Major | Lazy loading + `DCS_FUZZ_ALLOWED_PLUGINS` allowlist + source logging | **Resolved** |
| MAJOR-04 | Major | `PYTHONSAFEPATH=1` + `PYTHONDONTWRITEBYTECODE=1`; MCP blocked | **Resolved** |
| MAJOR-05 | Major | `DCS_FUZZ_MCP_TIMEOUT` + async-start/poll-status + reduced defaults | **Resolved** |
| MAJOR-06 | Major | Write-path validation rejects `src/`, `registries/`, `.git/` | **Resolved** |
| Minor-01 | Minor | Warning logged; `.env` not read documented as invariant | **Resolved** |
| Minor-02 | Minor | Config file path migrated with fallback and deprecation warning | **Resolved** |
| Minor-03 | Minor | Deferred as tech debt (acceptable: CLI-only, no MCP threading risk) | **Partially Resolved** |
| Minor-04 | Minor | Prompt injection test cases added | **Resolved** |
| Minor-05 | Minor | Not addressed | **Unresolved (Minor)** |
| Minor-06 | Minor | `-F` for `--function`, `-f` for `--format` | **Resolved** |
| Info-01 | Info | `pip-audit`, version pinning, `make audit-deps` | **Resolved** |
| Info-02 | Info | Trust boundary analysis corrected; SD-02 documented | **Resolved** |
| Info-03 | Info | MCP tool deferred; cost tracking not added | **Partially Resolved** |

| ID | Severity | New Finding |
|---|---|---|
| RC-01 | Minor | CLI lacks warning about host-privilege execution of fuzz targets |
| RC-02 | Minor | Dual entry point groups during transition slightly widen plugin attack surface |
| RC-03 | Info | `DCS_FUZZ_MCP_TIMEOUT` default is design-only (MCP tool deferred) |

No Critical or Major findings remain. The plan is approved from a security perspective.
