# Learnings

Last updated: 2026-03-13

Patterns observed across /ship runs. Each entry records a recurring mistake or gap so future coders and QA agents can avoid repeating it.

---

## Coder Patterns

### Missed by coders, caught by reviewers

- **[2026-03-13] Sandbox timeout not capped on all code paths** — When a timeout parameter is capped in one handler (e.g., `_handle_verify`) but the same parameter is consumed in a sibling handler (e.g., `_handle_full`) without the same cap, callers can hold shared resources (semaphores, sandbox slots) indefinitely. Every code path that accepts a user-supplied timeout must apply the same ceiling. Severity: Major. Seen in: deep-code-security. #security #resource-management #consistency

- **[2026-03-13] `startswith` used for path containment instead of `is_relative_to` / trailing-separator guard** — Using `path.startswith(allowed)` for containment checks allows `/var/proj-secrets/file.py` to match an allowlist entry of `/var/proj`. The correct check appends `os.sep` before comparing (`startswith(allowed + os.sep)`) or uses `Path.is_relative_to()`. Seen in: deep-code-security. Severity: Critical. #security #path-validation

- **[2026-03-13] Sensitive path prefixes incomplete in path validator** — `/etc` and `/private/etc` (macOS) were not blocked alongside `/proc`, `/sys`, and `/dev`. Path validators must cover all OS-level sensitive trees, including platform-specific variants. Severity: Critical. Seen in: deep-code-security. #security #path-validation

- **[2026-03-13] Shell injection via interpolated filename in subprocess sh -c string** — Using `sh -c` with a PoC filename interpolated directly into the string enables injection if the filename is attacker-controlled. Fix: assert the filename equals an exact expected value before interpolation (e.g., `assert poc_filename == "poc.go"`). Severity: Critical. Seen in: deep-code-security. #security #shell-injection

- **[2026-03-13] Overly broad taint fallback generates false positives** — A `_check_sink_reachability` fallback that returns `True` whenever tainted variables are non-empty (regardless of whether the AST node for the sink line is found) produces false-positive findings. The safe fallback when no AST node is found is `(False, [], None)`. Severity: Major. Seen in: deep-code-security. #correctness #taint-analysis

- **[2026-03-13] Unbounded in-memory session store causes uncapped memory growth** — Storing scan results in a plain `dict` without an eviction policy allows unbounded memory growth under sustained use. Use an `OrderedDict` with a maximum entry cap and FIFO eviction, cleaning up all associated lookup structures together. Severity: Major. Seen in: deep-code-security. #resource-management #memory

- **[2026-03-13] Missing file size gate in parser allows oversized input** — Passing arbitrarily large byte buffers to a tree-sitter parser can exhaust memory or CPU. A size guard must be applied before parsing (e.g., reject files over 10 MB). Severity: Major. Seen in: deep-code-security. #resource-management #parser

- **[2026-03-13] Coverage threshold below stated project goal** — `fail_under` was set to 80 while the project goal is 90%. CI gates must match stated coverage requirements; a lower threshold masks under-tested branches that later become bug sources. Severity: Major. Seen in: deep-code-security. #testing #coverage

- **[2026-03-13] Defined exclusion list never applied at enforcement point** — `_EXCLUDED_MOUNT_PATTERNS` listing credential files (`.pem`, `.env`, `.git/config`, etc.) was defined but never used at mount time. Constants that encode security policy must either be enforced or replaced with a comment explaining the architectural reason they cannot be (e.g., Docker does not support per-file volume exclusions). Severity: Minor. Seen in: deep-code-security. #security #dead-code

- **[2026-03-13] `autoescape=False` on Jinja2 SandboxedEnvironment without explanation** — Disabling autoescaping is correct for code-generation templates (HTML escaping corrupts generated source), but without a comment future reviewers will flag it in security audits. Always add a one-line rationale comment next to intentional security-relevant defaults. Severity: Minor. Seen in: deep-code-security. #security #code-clarity

- **[2026-03-13] Return type annotation not satisfied by bare string literals** — A function typed to return an `Enum` subclass that instead returns bare string literals compiles and passes Pydantic v2 at runtime but may fail static analysis (mypy). Use explicit casts or return the enum member directly. Severity: Minor. Seen in: deep-code-security. #type-safety

---

## QA Patterns

### Coverage gaps

- **[2026-03-13] Taint path assertions too weak — assert list not assert non-empty** — Tests that call `find_taint_paths` and only assert `isinstance(paths, list)` or `len(sources) >= 0` confirm the engine runs without error but do not confirm a path was actually found. Assertions should be `len(paths) >= 1` (or stronger) to catch regressions where taint tracking silently stops producing findings. Seen in: deep-code-security. #testing #taint-analysis

- **[2026-03-13] YAML poisoning adversarial test absent despite `yaml.safe_load` usage** — Even when the registry loader correctly uses `yaml.safe_load()`, an explicit test asserting that `!!python/exec` and `!!python/object` tags raise `yaml.YAMLError` documents the security contract and catches future regressions if the loader is ever changed. Seen in: deep-code-security. #testing #security #yaml

- **[2026-03-13] Safe fixture missing for every vulnerable fixture** — The fixture philosophy requires a safe-variant file for every vulnerable-variant file. `vulnerable_samples/go/command_injection.go` existed without a corresponding `safe_samples/go/safe_command.go`. Missing safe fixtures leave false-positive detection untested for that language/vuln-type pair. Seen in: deep-code-security. #testing #fixtures

- **[2026-03-13] Safe-sample integration test assertion is vacuously true** — An integration test for safe samples used an assertion that matched all possible status values, making the test always pass regardless of whether a false positive was produced. The correct assertion is `assert status != "confirmed"`. Seen in: deep-code-security. #testing #false-positives

- **[2026-03-13] Coverage omit list includes actively-tested code** — Omitting `*/mcp/shared/*` from coverage measurement when `BaseMCPServer` and `ToolError` in that package are exercised by server tests inflates the reported percentage by reducing the denominator. Omit lists should only cover true stubs and thin entry-points, not vendored base classes exercised in tests. Seen in: deep-code-security. #testing #coverage

- **[2026-03-13] Edge cases for binary/syntax-error/oversized inputs untested until revision** — Parser and file-discovery components lacked tests for: files exceeding the size gate, files with binary content, files with syntax errors, and named pipe / block device paths. These edge cases should be included in the initial test plan for any component that ingests arbitrary filesystem paths. Seen in: deep-code-security. #testing #edge-cases

- **[2026-03-13] Sandbox timeout cap not tested with an injected kwarg assertion** — Verifying that a timeout cap is applied requires capturing the actual value passed downstream (e.g., via `patch.object` capturing kwargs) and asserting it equals the ceiling, not just that no exception is raised. Seen in: deep-code-security. #testing #security #resource-management
