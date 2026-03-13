# Code Review: deep-code-security (Revision 3 — Final)

**Verdict: PASS**

**Reviewer:** code-reviewer agent v1.0.0
**Date:** 2026-03-13
**Scope:** Final verification of the one remaining Major issue (sandbox_timeout cap in `_handle_full`)

---

## Code Review Summary

All Critical and Major findings from the two prior review rounds are now resolved. The `sandbox_timeout` cap that was previously missing from `_handle_full` has been applied correctly and consistently with the existing fix in `_handle_verify`. No new issues were introduced. The six open Minor findings are unchanged and remain non-blocking.

---

## Verification of Previously Flagged Findings

### Major 1 — `sandbox_timeout` not capped in `_handle_full` [FIXED]

`/Users/imurphy/projects/deep-code-security/src/deep_code_security/mcp/server.py`, line 434

Line 434 now reads:

```python
sandbox_timeout = min(int(params.get("sandbox_timeout_seconds", 30)), 300)
```

This is identical to the fix already present at line 301 in `_handle_verify`. Both code paths now enforce the same 300-second ceiling. A caller invoking `deep_scan_full` with an arbitrarily large `sandbox_timeout_seconds` can no longer hold the `SandboxManager` semaphore for more than five minutes. Fix is correct.

---

## Critical Issues (Must Fix)

None.

---

## Major Findings (Should Fix)

None. All Major findings from prior reviews are resolved.

---

## Minor Findings (Consider)

The following minor findings remain open. None are blockers and none were introduced by any revision round.

### 1. `autoescape=False` in Jinja2 `SandboxedEnvironment` lacks an explanatory comment

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/auditor/exploit_generator.py`, line 20

`autoescape=False` is correct for code generation (HTML escaping would corrupt generated source), but a future reader may flag it in a security review without context. A one-line comment is sufficient.

### 2. `validate_taint_steps` skips regex validation on variable names

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/mcp/input_validator.py`, lines 192-198

Taint step variable names are only length-checked. Since these values are produced by the taint engine internally and not interpolated into exploit templates, risk is low. For consistency with the rest of the input validator, a relaxed alphanumeric+underscore+dot pattern would be cleaner.

### 3. `_EXCLUDED_MOUNT_PATTERNS` is defined but never applied

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/auditor/sandbox.py`, lines 24-39

The list of credential file patterns (`*.pem`, `.env`, `.git/config`, etc.) is not filtered at mount time. Docker/Podman do not support per-file exclusion in `--volume` mounts, so this is architecturally constrained. The `--network=none` policy limits exfiltration risk. The constant should either be used (e.g., to build a filtered copy of the target before mounting) or replaced with a comment explaining why it is not applied.

### 4. Coverage omission for `mcp/shared/*` inflates reported percentage

**File:** `/Users/imurphy/projects/deep-code-security/pyproject.toml`, line 83

`*/mcp/shared/*` is omitted from coverage. `server_base.py` contains `BaseMCPServer` and `ToolError`, both exercised by server tests. Removing this omission would give a more accurate denominator. Not a blocker now that `fail_under` is 90.

### 5. `confidence_to_status` return type annotation does not use an explicit cast

**File:** `/Users/imurphy/projects/deep-code-security/src/deep_code_security/auditor/confidence.py`, line 173

The function is typed to return `VerificationStatus` but returns bare string literals. Pydantic v2 accepts compatible literals; mypy may flag this without explicit casts. No functional impact.

### 6. `autoescape=False` in Jinja2 `SandboxedEnvironment` lacks an explanatory comment

See Minor finding 1 above. Listed separately in earlier reviews as finding 6 — consolidated here.

---

## What Went Well

The fix was applied precisely and consistently. The one-line change at `_handle_full` line 434 exactly mirrors the pattern established at `_handle_verify` line 301, eliminating the asymmetry that was the regression. No unrelated code was disturbed.

The full history of fixes across all three review rounds demonstrates a clean security posture: symlink resolution uses `is_relative_to()`, `/etc` and `/private/etc` are blocked, the shell-injection paths in `sandbox.py` are guarded by assertion, the session store is FIFO-bounded, the taint fallback is conservative, the parser has a size gate, and the coverage gate is at 90%. All Automatic FAIL triggers from the review policy are clear.

---

## Summary Table

| # | Severity | Status | File | Issue |
|---|----------|--------|------|-------|
| C1 | Critical | FIXED | `auditor/sandbox.py:327-339` | `sh -c` with interpolated `poc_filename` |
| C2 | Critical | FIXED | `mcp/path_validator.py:56` | `/etc` and `/private/etc` not blocked |
| C3 | Critical | FIXED | `shared/file_discovery.py:104,199` | `startswith` symlink check |
| M4 | Major | FIXED | `pyproject.toml:93` | `fail_under=80` below 90% goal |
| M5 | Major | FIXED | `mcp/server.py:57-60,263-270` | Unbounded session store |
| M6 | Major | FIXED | `hunter/taint_tracker.py:545-550` | Broad taint fallback |
| M7 | Major | FIXED | `mcp/server.py:301` | `sandbox_timeout` cap in `_handle_verify` |
| M8 | Major | FIXED | `hunter/parser.py:17,162-165` | No size guard in `parse_bytes` |
| M1 | Major | FIXED | `mcp/server.py:434` | `sandbox_timeout` not capped in `_handle_full` (regression, now resolved) |
| 1 | Minor | OPEN | `auditor/exploit_generator.py:20` | `autoescape=False` needs explanatory comment |
| 2 | Minor | OPEN | `mcp/input_validator.py:192-198` | Taint step variable names skip regex validation |
| 3 | Minor | OPEN | `auditor/sandbox.py:24-39` | `_EXCLUDED_MOUNT_PATTERNS` defined but never applied |
| 4 | Minor | OPEN | `pyproject.toml:83` | Coverage omission for `mcp/shared/*` |
| 5 | Minor | OPEN | `auditor/confidence.py:173` | `confidence_to_status` return type annotation |
