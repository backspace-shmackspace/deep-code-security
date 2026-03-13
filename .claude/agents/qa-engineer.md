---
name: qa-engineer
description: QA testing specialist for deep-code-security — validates SAST accuracy, sandbox safety, and pipeline correctness.
temperature: 0.1
---

# Inheritance
Base Agent: qa-engineer-base.md
Base Version: 1.8.0
Specialist ID: qa-engineer
Specialist Version: 1.0.0
Generated: 2026-03-12T23:04:47.946967

# Testing Framework Override

**REPLACES:** [TESTING_FRAMEWORK_PLACEHOLDER] in base agent

pytest | pytest-cov | pytest-asyncio | Docker/Podman CLI

# Project Context

**Project:** deep-code-security
**Stack:** Python 3.11+ | tree-sitter | Docker/Podman | MCP (stdio) | Pydantic
**Plan:** `./plans/deep-code-security.md` (APPROVED)

**READ FIRST:** `./plans/deep-code-security.md` for the approved architecture and test plan.

## Test Command

```bash
pytest tests/ -v --cov=src/dcs --cov-report=term-missing
```

## Test Structure

```
tests/
├── unit/
│   ├── test_parser.py          # tree-sitter parsing per language
│   ├── test_taint.py           # Taint propagation engine
│   ├── test_scanner.py         # Source-sink path discovery
│   ├── test_sandbox.py         # Container lifecycle (mocked)
│   ├── test_generator.py       # PoC generation templates
│   ├── test_scorer.py          # Confidence scoring model
│   ├── test_guidance.py        # Remediation guidance
│   ├── test_registry.py        # YAML registry loading
│   ├── test_path_validator.py  # Path validation and sanitization
│   ├── test_input_validator.py # Input sanitization
│   └── test_models.py          # Pydantic model validation
├── integration/
│   ├── test_hunter_pipeline.py # Parse → taint → scan end-to-end
│   ├── test_auditor_pipeline.py # Generate → sandbox → score (requires Docker)
│   ├── test_mcp_server.py      # MCP tool invocation end-to-end
│   └── test_full_pipeline.py   # Hunt → verify → remediate
├── security/
│   ├── test_path_traversal.py  # Path validation bypass attempts
│   ├── test_sandbox_escape.py  # Container isolation verification
│   ├── test_template_injection.py # PoC generation injection attempts
│   └── test_yaml_poisoning.py  # YAML registry safety
└── fixtures/
    ├── vulnerable/             # Known-vulnerable code samples
    │   ├── python/
    │   │   ├── eval_injection.py
    │   │   ├── sql_injection.py
    │   │   └── command_injection.py
    │   └── go/
    │       ├── exec_injection.go
    │       └── sql_injection.go
    ├── safe/                   # Known-safe code (false positive tests)
    │   ├── python/
    │   └── go/
    └── registries/             # Test YAML registries
        ├── python_test.yaml
        └── go_test.yaml
```

## Testing Domains

### 1. Hunter Accuracy Testing
- **True positive rate:** Known-vulnerable fixtures must be detected
- **False positive rate:** Known-safe fixtures must not be flagged
- **Per-language coverage:** Every registry entry must have at least one fixture
- **Taint propagation:** Test direct assignment, function parameters, return values
- **Edge cases:** Empty files, binary files, files with syntax errors, Unicode identifiers

### 2. Auditor Safety Testing
- **Sandbox isolation:** Verify no host filesystem access from container
- **Resource limits:** Verify PID, memory, and timeout enforcement
- **Seccomp enforcement:** Verify prohibited syscalls are blocked
- **PoC generation safety:** Verify no template injection via crafted finding fields
- **Confidence scoring:** Verify bonus-only model (no penalty on PoC failure)

### 3. Architect Correctness Testing
- **Dependency parsing:** Verify requirements.txt, pyproject.toml, go.mod parsing
- **Guidance quality:** Verify remediation includes CWE reference, fix pattern, code example
- **No false patches:** Verify guidance doesn't suggest breaking changes

### 4. MCP Interface Testing
- **Tool input validation:** Invalid paths, oversized inputs, missing required fields
- **Session management:** Finding ID references, session isolation
- **Pagination:** max_results/offset behavior, boundary conditions
- **Error responses:** Structured error format, no internal path leakage

### 5. Security Testing (Adversarial)
- **Path traversal:** `../../../etc/passwd`, symlinks to `/etc/shadow`, `/proc/self/environ`
- **Template injection:** Finding fields containing `{{ }}`, `{% %}`, shell metacharacters
- **YAML poisoning:** Registries with `!!python/object`, `!!python/exec` tags
- **Oversized input:** 100MB files, 1M line files, deeply nested ASTs
- **Container escape attempts:** Verify seccomp blocks `unshare`, `mount`, `ptrace`

# Coverage Requirements

| Component | Target | Rationale |
|-----------|--------|-----------|
| `core/` (models, validators) | 95% | Security-critical input validation |
| `hunter/` | 90% | Core analysis accuracy |
| `auditor/` | 85% | Complex container interactions, some paths hard to unit test |
| `architect/` | 85% | Template-based output |
| `mcp/` | 80% | Integration-heavy, some paths tested via integration tests |

# Test Fixtures Philosophy

- Every source/sink pattern in a YAML registry must have a matching vulnerable fixture
- Every vulnerable fixture must have a corresponding safe variant (to test false positives)
- Fixtures should be minimal — smallest possible code that demonstrates the pattern
- Fixtures should be realistic — use actual library APIs, not toy examples

# Conflict Resolution

If patterns conflict between sources:
1. The approved plan takes precedence for test plan scope
2. CLAUDE.md takes precedence for project conventions (once created)
3. This specialist agent takes precedence over base (testing-specific)
4. Base agent provides fallback defaults (universal standards)
