# Red Team Review (Round 2): Semgrep Scanner Backend

**Plan reviewed:** `./plans/semgrep-scanner-backend.md`
**Reviewer role:** Security Analyst (security-analyst specialist)
**Date:** 2026-03-19
**Plan status at review:** DRAFT (revised, round 2)
**Prior review:** `./plans/semgrep-scanner-backend.redteam.md` (round 1, FAIL -- 2 Critical findings)

---

## Verdict: PASS

Both original Critical findings (F-01 and F-02) have been properly resolved.
No new Critical findings were introduced by the revision. Four Major findings,
three Minor findings, and two Info-level items are documented below.

---

## Resolution Status of Round 1 Critical Findings

### F-01 (Round 1): `dataflow_trace` is a Semgrep Pro feature -- normalization pipeline must work without it

**Status: RESOLVED.**

The revised plan comprehensively addresses this finding. Specific evidence:

1. **Context section (line 17-18):** Explicitly states `extra.dataflow_trace` is
   a "Semgrep Pro / AppSec Platform feature" and is "NOT available in OSS output."
2. **Normalization Strategy (lines 166-207):** Completely redesigned around rule
   metadata (`metadata.source_category`, `metadata.source_function`) and
   metavariable bindings (`extra.metavars.$SOURCE`). No dependency on
   `dataflow_trace` remains.
3. **Source construction:** Uses `$SOURCE` metavariable binding for location data
   when available; falls back to match location when not.
4. **TaintPath construction:** Always produces a synthetic two-step path. The
   plan explicitly acknowledges this as an "inherent limitation of Semgrep OSS."
5. **Confidence Scoring Adaptation (lines 326-352):** Documents the scoring
   asymmetry between backends (Semgrep OSS capped at 50 for taint completeness)
   and explains why this is acceptable behavior rather than a defect.
6. **Non-Goal #1:** Explicitly scopes out `dataflow_trace` normalization and
   labels it a "future enhancement contingent on Semgrep Pro evaluation."

The normalization approach is sound: rule metadata provides the semantic content
(source category, sink category, CWE) while metavariable bindings provide
location data. This is a legitimate and well-documented design.

### F-02 (Round 1): Semgrep rule YAML syntax was invalid

**Status: RESOLVED.**

The revised plan fixes both syntax issues identified in round 1:

1. **Multiple sources (lines 258-264):** The example rule now uses separate list
   entries under `pattern-sources` for OR semantics, replacing the invalid nested
   `patterns:` AND combinator. Each `- pattern:` entry is a separate alternative.
2. **Sanitizer constraint (lines 267-268):** The invalid `where:`/`type:`
   constraint is replaced with structural pattern matching:
   `$CURSOR.execute($QUERY, ($PARAMS, ...))` matches parameterized queries by
   their tuple structure. This is valid Semgrep DSL syntax.
3. **Validation enforcement:** The plan adds `semgrep --validate --config <file>`
   to the test plan (test scenario #13), CI, and acceptance criteria (AC #18).
   The DSL syntax notes section (lines 271-274) explicitly documents the round 1
   error and the correction.

The example rule at lines 241-269 appears syntactically correct for Semgrep
taint mode. The `pattern-sanitizers` entry uses structural matching, which
Semgrep supports.

---

## New Findings

### F-15: Semgrep-generated Source `function` values may contain bracket notation that fails input validation [Major]

**Description:** The normalizer constructs `Source.function` from
`metadata.source_function` in the Semgrep rule (line 200: "Constructed from
rule metadata (`metadata.source_category`, `metadata.source_function`)"). The
example rule shows `source_function: request.form` (line 181), which passes
the existing `_FUNCTION_NAME_RE` regex `^[a-zA-Z_][a-zA-Z0-9_.]*$`.

However, the Semgrep `$SOURCE` metavariable's `abstract_content` field (line
191) may contain bracket notation like `request.form['id']` or `request.args.get("user")`.
If the normalizer uses `abstract_content` as the `Source.function` value (which
would be more informative than the static rule metadata), it will fail input
validation because `[`, `'`, `(`, `)`, and `"` are not permitted by
`_FUNCTION_NAME_RE`.

Additionally, the C rules may produce source functions like `argv[1]` or
`*(argv+1)` which contain characters outside the function name regex.

**Impact:** If the normalizer uses `abstract_content` for `Source.function`,
findings will fail `validate_raw_finding()` in `input_validator.py` and be
rejected by the Auditor. If it uses the static `metadata.source_function`, the
information loss is acceptable but should be explicitly documented.

The plan says (line 200) the Source is "Constructed from rule metadata
(`metadata.source_category`, `metadata.source_function`) and the metavariable
binding for `$SOURCE` (if present)." The "and" here is ambiguous -- does the
metavar binding override the function field, or only supply the location?

**Remediation:** Explicitly specify that `Source.function` is populated from
`metadata.source_function` (the static rule metadata, which is controlled and
guaranteed to pass validation), not from the `$SOURCE` metavariable's
`abstract_content`. The metavar binding should only provide `start.line` and
`start.col` for the source location. Add a test scenario that verifies
Semgrep-generated findings with bracket-notation source content still pass
`validate_raw_finding()`.

---

### F-16: Semgrep `check_id` format may produce `vulnerability_class` values that fail CWE validation [Major]

**Description:** The plan states `vulnerability_class` is constructed "From
the rule's `metadata.cwe` field (first entry)" (line 203). The example shows
`metadata.cwe: ["CWE-89: SQL Injection"]`. The normalizer presumably extracts
this string and uses it as `vulnerability_class`.

The existing `input_validator.py` validates `vulnerability_class` with
`_CWE_RE.match(finding.vulnerability_class)` where `_CWE_RE = re.compile(r"^CWE-\d+")`.
The regex uses `match` (anchored at start) but has no end anchor -- it matches
"CWE-89: SQL Injection" because it starts with "CWE-89". This works.

However, the plan does not specify what happens if a Semgrep rule's
`metadata.cwe` is missing, malformed, or uses a non-standard format
(e.g., `"89"` without the `CWE-` prefix, or a list with no entries). The
normalizer should skip or reject such findings.

The plan's Input Validation section (line 747) says each result is "validated
for required fields (`check_id`, `path`, `start`, `end`, `extra.severity`,
`extra.metadata.cwe`) before normalization." But it does not specify what the
validation entails for `metadata.cwe` beyond presence.

**Impact:** If a rule author omits or malforms the `cwe` metadata field, the
normalizer may produce a `RawFinding` with an invalid `vulnerability_class`
that fails downstream validation, or worse, produce a finding that cannot be
matched by the suppression system (which matches on `sink.cwe`).

**Remediation:** Specify that the normalizer validates `metadata.cwe[0]`
against the `^CWE-\d+` pattern before constructing the `RawFinding`. Malformed
CWE values should cause the result to be logged as a diagnostic and skipped.
Add a test for a Semgrep result with a missing or malformed `metadata.cwe`.

---

### F-17: `_compute_raw_confidence()` relocation creates a potential import cycle [Major]

**Description:** The plan states (line 205): "`raw_confidence`: Computed
using the same heuristic as `HunterOrchestrator._compute_raw_confidence()`."
And (line 312): "The `_compute_raw_confidence()` method is moved to a shared
location so both backends can use it."

The current `_compute_raw_confidence()` method (orchestrator.py lines 281-300)
is a simple function that checks `taint_path.sanitized` and
`len(taint_path.steps)`. Moving it is straightforward.

However, the plan does not specify WHERE it is moved to. The candidates are:

1. `hunter/scanner_backend.py` -- makes sense topologically, but `BackendResult`
   is defined there, and having confidence computation alongside the protocol
   class mixes concerns.
2. `hunter/models.py` -- reasonable, but the function operates on `TaintPath`
   which is already defined there; however, it is currently a method on
   `HunterOrchestrator`, suggesting it was intentionally kept with orchestration
   logic.
3. A new `hunter/confidence_heuristic.py` module -- cleanest separation but
   adds another file not listed in the task breakdown.

None of these options are specified in the "Files to Create" or "Files to
Modify" sections. The task breakdown lists `hunter/scanner_backend.py` as
containing only the protocol and `BackendResult`. Neither `SemgrepBackend`
nor `TreeSitterBackend` is listed as importing a shared confidence function.

**Impact:** Without a clear specification, implementers may duplicate the
confidence logic in both backends (violating DRY), or introduce an import
cycle if the shared function is placed poorly. This is an architecture gap
rather than a security issue, but it affects code quality.

**Remediation:** Specify the target location for `_compute_raw_confidence()`.
The cleanest option is to place it as a module-level function in
`hunter/scanner_backend.py` alongside `BackendResult`, since both backends
need it and it operates on `TaintPath` (which is in `hunter/models.py`, a
module that `scanner_backend.py` already depends on). Add this to the "Files
to Create" description for `scanner_backend.py`.

---

### F-18: Semgrep output `path` field may use relative paths that mismatch `discovered_files` absolute paths [Major]

**Description:** The SemgrepBackend post-filters results against the
`discovered_files` list (plan line 161: "Filter Semgrep results to include only
files present in the `discovered_files` list"). This filtering likely uses the
`path` field from Semgrep's JSON output.

Semgrep's `path` field in JSON output uses **relative paths from the scan
root** (e.g., `"path": "src/app.py"`). However, `DiscoveredFile.path` in the
existing DCS file discovery system contains **absolute paths** (populated by
`FileDiscovery.discover()` which uses `Path.resolve()`). The existing
orchestrator uses absolute paths throughout (e.g., `Source.file` and
`Sink.file` contain absolute paths, as validated by `_FILE_PATH_RE` which
accepts `/`).

If the post-filter compares Semgrep's relative `path` against
`DiscoveredFile.path` absolute paths using simple string equality, no findings
will match and ALL results will be filtered out.

The plan does not specify the path normalization strategy for this comparison.
The `Source.file` and `Sink.file` fields in the normalized `RawFinding` must
also contain absolute paths to match the existing convention and pass input
validation.

**Impact:** If implemented naively, the post-filter silently drops all Semgrep
findings, making the Semgrep backend appear to produce zero results. This
would be logged as a diagnostic ("findings were filtered out") but could be
mistaken for "Semgrep found nothing."

**Remediation:** Specify that the normalizer resolves Semgrep's relative
`path` field against `target_path` to produce an absolute path before both
the post-filter comparison and the `Source.file`/`Sink.file` construction.
The comparison should use resolved absolute paths. Add a test scenario that
verifies post-filtering works when Semgrep reports relative paths and
`discovered_files` contains absolute paths.

---

### F-19: Plan does not address `--max-target-bytes` default value [Minor]

**Description:** The subprocess command specification (lines 85-87) includes
`--max-target-bytes <b>` but does not specify what `<b>` is. Semgrep's default
is 1 MB per file. The plan introduces `DCS_SEMGREP_TIMEOUT` but does not
introduce a corresponding env var for max target bytes.

**Impact:** If a user scans a codebase with files larger than 1 MB (common for
generated code, minified JavaScript, or large C source files), Semgrep will
silently skip those files without DCS being aware of it.

**Remediation:** Either specify the default value for `--max-target-bytes`
explicitly (e.g., 5 MB to match common SAST tool defaults), or document that
Semgrep's default (1 MB) is used. Consider adding a `DCS_SEMGREP_MAX_FILE_SIZE`
env var for user control, or document the limitation.

---

### F-20: C output-parameter sources are still not addressed by Semgrep rules [Minor]

**Description:** CLAUDE.md Known Limitation #7 documents that C source functions
delivering tainted data via output parameters (`recv`, `fread`, `read`,
`scanf`, `getline`, `getdelim`) are not effective taint sources in the
tree-sitter engine. The existing `c.yaml` registry has these sources commented
out (lines 30-90).

Semgrep's taint mode CAN handle output-parameter sources via
`pattern-sources` with `by-side-effect: true` or `by-side-effect: only`. This
is a feature available in Semgrep OSS. The plan's C rules (lines 228-235) do
not include these output-parameter sources, meaning the Semgrep backend
inherits the same limitation as the tree-sitter backend despite having the
technical capability to resolve it.

**Impact:** This is a missed opportunity rather than a defect. The plan
explicitly states C detection parity with the tree-sitter engine, so it is
consistent with its own scope. However, the rationale for not leveraging
Semgrep's output-parameter source support should be documented.

**Remediation:** Add a note to the C rules section or the Non-Goals section
acknowledging that Semgrep's `by-side-effect` source support could resolve
Known Limitation #7 but is deferred to a future plan increment (it would
require validation and test fixture development). This turns a gap into a
documented backlog item.

---

### F-21: `DCS_SEMGREP_RULES_PATH` validation rejects `..` in the resolved path, but `Path.resolve()` eliminates `..` [Minor]

**Description:** The Input Validation Specification (line 746) states:
"`DCS_SEMGREP_RULES_PATH`: Resolved via `Path.resolve()` (resolves symlinks).
Rejected if the resolved path contains `..` components (defense in depth)."

`Path.resolve()` in Python normalizes the path and eliminates all `..`
components. After calling `Path.resolve()`, the resolved path will NEVER
contain `..`. The subsequent `..` check is therefore dead code -- it can
never trigger.

This is not a security vulnerability (the `Path.resolve()` call is the actual
defense), but the documented "defense in depth" provides no additional
protection and may mislead implementers into thinking the `..` check is the
primary guard.

**Impact:** No security impact. The `Path.resolve()` call provides the real
protection. The dead `..` check wastes a few CPU cycles but causes no harm.

**Remediation:** Change the specification to: "Resolved via `Path.resolve()`
(resolves symlinks and eliminates `..`). The resolved path is checked against
reasonable constraints (existing directory, contains `.yaml` files). Note:
`Path.resolve()` guarantees no `..` in the resolved path, so a separate `..`
check is redundant but included for explicit documentation of intent." Or
simply remove the redundant check and document that `Path.resolve()` handles
traversal prevention.

---

### F-22: Stage 0 validation may not exercise taint mode's $SOURCE metavar binding [Info]

**Description:** Stage 0 of the rollout plan (lines 438-451) instructs the
implementer to run Semgrep against test fixtures and "confirm the
`extra.metavars` field contains `$SOURCE` bindings with location data."

Whether `$SOURCE` metavar bindings appear in the output depends on how the
rule is written. If the rule's `pattern-sinks` does not reference `$SOURCE`
and the source/sink are in different expressions, Semgrep may not populate
`$SOURCE` in `extra.metavars`. The `$SOURCE` metavar is populated only when
the metavariable appears in the matched pattern text, not automatically.

In taint mode, sources and sinks are matched independently. The `extra.metavars`
will contain metavariables from the SINK pattern match (e.g., `$CURSOR`,
`$QUERY` from `$CURSOR.execute($QUERY, ...)`), not from the source pattern.
To get `$SOURCE` in the output, the message template must reference it
(Semgrep interpolates metavars in messages) or the sink pattern itself must
capture it.

**Impact:** Stage 0 may reveal that `$SOURCE` bindings are NOT present in taint
mode output, which would invalidate the source-location extraction strategy in
the normalization pipeline. This is exactly what Stage 0 is designed to catch,
so the risk is appropriately mitigated. However, the plan should note the
fallback: if `$SOURCE` is not in metavars, source location defaults to match
location (as already specified in line 200).

**Remediation:** Add a note to Stage 0 step 3 that if `$SOURCE` is not present
in metavars for taint-mode rules, the normalization pipeline falls back to
match-location-as-source (already specified in line 200). This expectation
should be validated in Stage 0 rather than discovered during Stage 1
implementation.

---

### F-23: Review Response Matrix claims scope retention but Stage 0 validates Python first [Info]

**Description:** The Review Response Matrix entry for finding `m-2` (line 781)
states: "Retained full scope (Python + Go + C) in this plan since the
tree-sitter registries already cover all three. Stage 0 validates the approach
with Python first."

The feasibility review recommended scoping to Python only (4 rule files
initially), deferring Go/C. The plan rejects this recommendation but partially
adopts it by having Stage 0 validate Python first. This is reasonable, but
the plan does not specify what happens if Stage 0 reveals problems with
Semgrep's Python taint mode. Specifically: does Stage 0 failure block
ALL rule development (Python + Go + C), or only block the Semgrep backend
work while allowing Go/C tree-sitter improvements to proceed?

**Impact:** Low. This is a project management question, not a design flaw.

**Remediation:** Add to Stage 0: "If Stage 0 reveals that Semgrep OSS taint
mode does not produce usable metavar bindings for the normalization pipeline,
the plan scope is reduced to the TreeSitterBackend adapter only (preserving
the `ScannerBackend` abstraction for future use) and Semgrep rule development
is deferred."

---

## STRIDE Security Analysis (Updated for Revised Plan)

### Context

This STRIDE analysis evaluates the revised plan's security posture after the
round 1 Critical findings were addressed. The analysis focuses on the NEW
trust boundary introduced by Semgrep subprocess invocation and any changes
to existing trust boundaries.

### Trust Boundary Diagram (Revised)

```
+-------------------------------------------------------------------+
| Host System (MCP server runs here natively)                       |
|                                                                   |
|  +------------------+     +-----------------------+               |
|  | MCP Server       |---->| Hunter Orchestrator   |               |
|  | (stdio)          |     |                       |               |
|  |                  |     | _select_backend()     |               |
|  | TRUST BOUNDARY 1 |     +----------+------------+               |
|  +------------------+                |                            |
|                                      v                            |
|                         +---------------------------+             |
|                         | ScannerBackend selection   |             |
|                         +------+------------+-------+             |
|                                |            |                     |
|                  +-------------+    +-------+---------+           |
|                  v                  v                  |           |
|  +------------------+   +---------------------+      |           |
|  | TreeSitterBackend|   | SemgrepBackend      |      |           |
|  | (in-process)     |   | (subprocess)        |      |           |
|  | Parses UNTRUSTED |   |                     |      |           |
|  | source code      |   | TRUST BOUNDARY 2    |      |           |
|  +------------------+   | (new)               |      |           |
|                         |   semgrep binary     |      |           |
|                         |   reads UNTRUSTED    |      |           |
|                         |   source code +      |      |           |
|                         |   DCS rule files     |      |           |
|                         |   outputs JSON       |      |           |
|                         |   --metrics=off      |      |           |
|                         +---------------------+      |           |
|                                                       |           |
|  +------------------------------------------------+  |           |
|  | Normalizer (host-side, in SemgrepBackend)       |  |           |
|  | Parses JSON output from Semgrep subprocess      |  |           |
|  | Constructs RawFinding from rule metadata +      |  |           |
|  | metavar bindings (NOT dataflow_trace)            |  |           |
|  | TRUST BOUNDARY 2a: JSON -> Pydantic models      |  |           |
|  +------------------------------------------------+  |           |
|                                                       |           |
|  +------------------------------------------------+  |           |
|  | Auditor (host-side orchestrator)                |  |           |
|  | Consumes RawFinding[] from either backend       |  |           |
|  | TRUST BOUNDARY 3: finding data -> templates     |  |           |
|  +---------------------+--------------------------+  |           |
|                        | subprocess                  |           |
|                        v                             |           |
|  +------------------------------------------------+  |           |
|  | Sandbox Container (ISOLATION BOUNDARY)          |  |           |
|  | TRUST BOUNDARY 4                                |  |           |
|  +------------------------------------------------+  |           |
+-------------------------------------------------------------------+
```

### S - Spoofing

| Threat | Risk | Analysis |
|--------|------|----------|
| Semgrep binary replaced with malicious binary | Medium | If an attacker replaces the `semgrep` binary on `$PATH`, the SemgrepBackend will invoke it. A trojan binary could output crafted JSON that injects false negatives (suppresses real findings) or false positives (floods the report). **Mitigation:** The plan documents (line 721) that "the Semgrep binary is trusted at the same level as the Python interpreter itself." This is an accurate trust model statement. The plan pins version range `>=1.50.0,<2.0.0` and warns on out-of-range versions, but does not verify binary integrity (hash/signature). This is acceptable because if the binary is compromised, the Python interpreter is equally compromisable. |
| Attacker-crafted `DCS_SEMGREP_RULES_PATH` suppresses findings | Low | The revised plan adds `Path.resolve()` validation and `..` rejection for the rules path (line 746). An attacker who controls this env var could point to a rules directory with permissive rules (few sources/sinks), but this requires host-level access to set environment variables. The validation prevents traversal but does not restrict the path to the project root -- a WARNING is logged for out-of-project paths, which is appropriate. |
| Semgrep output JSON crafted to produce findings with attacker-controlled metadata | Low | Semgrep output is parsed with `json.loads()` (safe). Each result is validated for required fields before normalization (line 747). The normalizer constructs `Source.function` and `Sink.function` from rule metadata (controlled by DCS, not by scanned code), not from Semgrep output directly. **However, see F-15:** if `abstract_content` from metavar bindings leaks into validated fields, injection is possible. |

### T - Tampering

| Threat | Risk | Analysis |
|--------|------|----------|
| Semgrep rules modified between scans | Medium | The revised plan computes `registry_version_hash` from Semgrep rule files (line 778), matching the tree-sitter approach. Rule tampering would change the hash, providing auditability. Rules are version-controlled in the repo. |
| Semgrep JSON output injected with extra fields | Low | The normalizer extracts specific known fields. Extra fields are ignored. `json.loads()` does not execute code. |
| Semgrep stderr contains misleading diagnostics | Low | Stderr is truncated to 4 KB (line 748), logged at WARNING, and never interpolated into templates or returned to MCP clients. |

### R - Repudiation

| Threat | Risk | Analysis |
|--------|------|----------|
| Scan results cannot be reproduced due to backend difference | Low | The revised plan adds `scanner_backend` to `ScanStats` (line 384) and logs which backend was selected. Combined with `registry_version_hash`, this provides reproducibility metadata. Semgrep version is also logged via the `is_available()` version check. |
| Backend silently switches between `auto` scans | Low | When `DCS_SCANNER_BACKEND=auto`, the backend may change if Semgrep is installed/uninstalled. This is logged at INFO level. The `scanner_backend` field in `ScanStats` makes the active backend visible in scan output. |

### I - Information Disclosure

| Threat | Risk | Analysis |
|--------|------|----------|
| Semgrep telemetry exfiltrates scan metadata | Low (mitigated) | The revised plan includes `--metrics=off` in the subprocess command (lines 85-87), verified by test scenario #14 and acceptance criterion #15. This is a meaningful improvement from round 1. |
| Host paths exposed in Semgrep JSON output | Low | Semgrep reports relative paths from the scan root. The normalizer must resolve these to absolute paths (see F-18). The absolute paths are the same paths already visible in tree-sitter findings. |
| Error messages expose internal structure | Low | Semgrep stderr is truncated, logged, not returned to clients. Error messages in `ToolError` responses are generic ("Semgrep backend requested but semgrep binary not found on $PATH") rather than stack traces. |

### D - Denial of Service

| Threat | Risk | Analysis |
|--------|------|----------|
| Crafted source code causes Semgrep to hang or consume excessive memory | Medium | Semgrep has its own `--timeout` per rule and `--max-target-bytes` per file. The external `DCS_SEMGREP_TIMEOUT` (120s default, line 321) caps total execution. Double protection mitigates this. **However:** the plan does not specify `--max-target-bytes` default (see F-19), so large files may cause Semgrep to use significant memory before timing out. |
| Semgrep post-filtering is O(N*M) on findings and discovered_files | Low | If Semgrep produces N findings and discovered_files has M entries, a naive post-filter is O(N*M). For realistic values (N < 10000, M < 10000), this is acceptable. Using a set lookup on discovered_files paths reduces to O(N). |
| Empty rules directory causes silent zero-result scan | Low (mitigated) | The revised plan validates that the rules directory contains at least one `.yaml` file in `is_available()` (line 158). An empty-results-with-non-empty-rules warning is also logged (line 163). Test scenarios #15 and #16 cover this. |

### E - Elevation of Privilege

| Threat | Risk | Analysis |
|--------|------|----------|
| Semgrep binary vulnerability exploited via crafted source code | Low | Semgrep's parser is written in OCaml (memory-safe). A parser vulnerability would require an OCaml-level exploit. The Semgrep subprocess runs as the current user (same as the MCP server). No privilege escalation is possible beyond the current user's permissions. |
| Semgrep rules execute arbitrary code | Not applicable | Semgrep rules are declarative YAML patterns. The Semgrep engine does not execute arbitrary code from rules. The `fix` key suggests code replacements, but DCS does not apply fixes (the Architect generates guidance only). |
| `DCS_SEMGREP_RULES_PATH` used to load rules that exploit a Semgrep parser bug | Very Low | If the Semgrep YAML parser has a vulnerability, a crafted rule file could potentially exploit it. This requires both a Semgrep bug and attacker control of the rules path. The path validation mitigates the latter. |

### STRIDE Summary

The revised plan's security posture is improved from round 1:

1. **Information disclosure** via telemetry is mitigated (`--metrics=off` now
   specified in the command).
2. **Tampering** of rules is auditable via `registry_version_hash`.
3. **DoS** via empty rules is caught by `is_available()` validation.
4. **Spoofing** via `DCS_SEMGREP_RULES_PATH` is mitigated by `Path.resolve()`
   validation.

The remaining risks are at the Medium-Low level and are consistent with the
existing threat model (the Semgrep binary is trusted at the same level as the
Python interpreter). The most actionable security finding is F-15 (metavar
`abstract_content` potentially leaking into validated fields), which should be
resolved before implementation.

---

## Supply Chain Risk Assessment

| Component | Risk Level | Change from Round 1 | Notes |
|-----------|-----------|---------------------|-------|
| `semgrep` binary (LGPL-2.1, optional dep) | Medium | Unchanged | Version pinned to `>=1.50.0,<2.0.0` (improved from round 1). Runtime version check warns on out-of-range versions. |
| Semgrep rule files (`registries/semgrep/`) | Low | Unchanged | User-authored, version-controlled. `registry_version_hash` provides integrity tracking. |
| No new Python core dependencies | None | Unchanged | Semgrep is in `[project.optional-dependencies]` only. |
| tree-sitter grammars (existing) | Unchanged | Unchanged | Retained as fallback. |

---

## Container Security Assessment

This plan does not introduce or modify any container security controls. The
sandbox architecture (Auditor, Fuzzer) is unchanged. The Semgrep binary runs
on the host alongside the MCP server, not in a container.

The decision to run Semgrep on the host (Non-Goal #6) is correct for the same
reasons the MCP server runs natively: containerizing Semgrep would either
require Docker socket access (root-equivalent) or add complexity for no
security benefit (Semgrep needs to read the same source files the MCP server
already has access to).

---

## Recommendations Summary

| Finding | Severity | Action Required |
|---------|----------|-----------------|
| F-15 | Major | Specify that Source.function uses rule metadata, not metavar abstract_content |
| F-16 | Major | Add CWE format validation for Semgrep rule metadata.cwe field |
| F-17 | Major | Specify target location for shared `_compute_raw_confidence()` |
| F-18 | Major | Specify path normalization for Semgrep relative paths vs DCS absolute paths |
| F-19 | Minor | Specify `--max-target-bytes` default value |
| F-20 | Minor | Document that Semgrep's output-parameter source support is deferred |
| F-21 | Minor | Fix redundant `..` check documentation (resolve() already eliminates ..) |
| F-22 | Info | Note that Stage 0 should validate $SOURCE metavar availability in taint mode |
| F-23 | Info | Specify Stage 0 failure mode (what gets deferred if validation fails) |

---

<!-- Context Metadata
reviewed_plan: semgrep-scanner-backend.md
reviewer: security-analyst
review_round: 2
prior_verdict: FAIL (2 Critical)
verdict: PASS
critical_findings_resolved: 2 (F-01, F-02)
new_critical_findings: 0
new_major_findings: 4
new_minor_findings: 3
new_info_findings: 2
stride_analysis: included
-->
