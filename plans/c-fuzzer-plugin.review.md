# Review: C Fuzzer Plugin Plan (Revised)

## Verdict: PASS

The revised plan resolves all three blocking issues from the prior review. The sentinel value is now a properly quoted string literal that passes `ast.literal_eval()`. The `CTargetPlugin` pseudo-code uses `@property` methods. The container security architecture has been redesigned to preserve the `/workspace` `noexec` invariant via a separate `/build` tmpfs mount and a `CContainerBackend` subclass instead of a parameterized base class. The plan is well-structured, thorough, and aligned with CLAUDE.md rules.

---

## Conflicts with CLAUDE.md

### None (blocking)

All prior blocking conflicts have been resolved.

### 1. Minor: `file_extensions` return type mismatch with ABC (non-blocking)

**Rule:** `TargetPlugin` ABC declares `file_extensions` as `-> list[str]` (base.py line 35).

The plan's Section 9 returns a `tuple` (`(".c",)`) from the `@property` and notes this is "compatible at runtime." This is correct at runtime (both are sequences), but a static type checker (mypy strict mode) would flag it. The plan acknowledges this and offers a fallback (`list((".c",))` on each call). The rationale -- avoiding mutable default arguments per CLAUDE.md -- is valid and the plan explicitly documents the trade-off. No action required, but implementers should pick one approach and note the choice.

### 2. Minor: Corpus serialization deserializes C inputs through expression validation (non-blocking, correctly handled)

**Rule:** "Expression strings re-validated on corpus replay load (closes TOCTOU gap)" (Security, Non-Negotiable)

The revised sentinel `"'__c_harness__'"` passes `ast.literal_eval()` (producing the Python string `__c_harness__`), so it survives expression re-validation in both `corpus/serialization.py` (`deserialize_fuzz_result`) and `replay/runner.py` (`_validate_fuzz_input_expressions`). This is correctly handled. No conflict.

---

## Historical Alignment Issues

### None (blocking)

### 1. Prior plan status references are now correct

The prior review flagged that `c-language-support.md` was cited as "(DRAFT)." The revised plan correctly references it as "(APPROVED)" (Context Alignment, line 893). The `sast-to-fuzz-pipeline.md` reference is also correctly marked "(APPROVED)."

### 2. Bridge scope expansion is properly documented

The plan explicitly acknowledges (Section 12, line 485 and Context Alignment Deviation 3, line 903) that it expands the `sast-to-fuzz-pipeline.md` v1 scope boundary (which limited the bridge to Python-only). The prior plan's "v1" qualifier anticipated future expansion. The plan notes: "The prior plan's 'v1' qualifier anticipated future expansion; this plan is that expansion." This is transparent and appropriate.

### 3. `fuzzer-container-backend.md` `/workspace` `noexec` invariant preserved

The approved `fuzzer-container-backend.md` established `noexec,nosuid` on the `/workspace` mount. The revised plan preserves this invariant completely: the `CContainerBackend` subclass keeps `/workspace` with `noexec,nosuid` for IPC and adds a separate `/build` tmpfs (without `noexec`) for compilation and binary execution. The parent `ContainerBackend._build_podman_cmd` is not modified, so the Python security posture is structurally guaranteed. This is a significant improvement over the prior draft's `workspace_noexec=False` parameter approach.

### 4. `merge-fuzzy-wuzzy.md` Non-Goals alignment confirmed

The `merge-fuzzy-wuzzy.md` plan lists C fuzzing as a deferred Non-Goal. The c-fuzzer-plugin plan correctly identifies itself as the separate effort and builds upon the established plugin architecture (TargetPlugin ABC, FuzzRunner, SandboxManager, JSON IPC protocol).

### 5. Context metadata block is present and accurate

The context metadata block (lines 998-1003) has `claude_md_exists: true` (correct), and lists both `recent_plans_consulted` and `archived_plans_consulted`. The `recent_plans_consulted` includes `c-language-support.md`, `scanner-tui.md`, and `semgrep-scanner-backend.md`. The `archived_plans_consulted` includes `merge-fuzzy-wuzzy.md`, `sast-to-fuzz-pipeline.md`, and `fuzzer-container-backend.md`. All are substantive references in the Context Alignment section. No missing prior plans.

---

## Required Edits

None. All prior required edits have been addressed in this revision.

---

## Optional Suggestions

- **`--plugin` CLI flag for `hunt-fuzz`:** The plan covers MCP `deep_scan_fuzz` plugin support (Section 14) and bridge integration (Section 12), but does not mention updating the `dcs hunt-fuzz` CLI command to accept `--plugin c`. The bridge resolver in `resolver.py` currently hardcodes a `finding.language.lower() != "python"` filter (line 65). The plan describes expanding this filter (Section 12), but the CLI command itself likely passes `plugin_name="python"` to `FuzzerConfig`. Consider adding `cli.py` to the Files to Modify list (item 29) with a note to add a `--plugin` option to `hunt-fuzz`.

- **Container image digest pinning:** The plan uses `gcc:13-bookworm` as the base image. The tag can be updated upstream with breaking gcc minor version bumps. Consider pinning to a specific digest (`gcc:13-bookworm@sha256:...`) for reproducible builds, with a comment documenting the pin date.

- **Corpus serialization metadata awareness:** The `deserialize_fuzz_result` function in `corpus/serialization.py` does not currently inspect `metadata["plugin"]`. If corpus replay is added for C in a future plan, the replay runner would need to detect `metadata["plugin"] == "c"` and skip Python-specific `eval()` execution. The plan lists corpus replay as a Non-Goal (correct for v1), but a brief note in the plan's Context Alignment section about this future consideration would be helpful.

- **`_c_worker.py` subprocess calls:** The plan states the C worker invokes gcc via subprocess with list-form arguments (Section 3, step 4). This is correct per CLAUDE.md ("All subprocess calls use list-form arguments"). Implementers should ensure the compilation command in step 4 uses `subprocess.run([...], shell=False)` (the default) and that `compile_flags` from `input.json` are individual list elements (not a single space-separated string), to prevent flag injection.

- **Test for `is_available()` backward compatibility:** The plan modifies `ContainerBackend.is_available()` to accept an optional `image` parameter (Section 8, "Per-language `is_available()`"). Consider adding a unit test confirming that calling `is_available()` with no arguments still checks the Python image (backward compatibility).
