"""Adversarial tests for C harness AST validation.

These tests document both what the AST validator catches (and must catch) and
what it deliberately does NOT catch (documented limitations where the container
security policy is the defense boundary).

Per the plan (Section 3a): "Harness validation is defense-in-depth, not the
security boundary. The container security policy is the actual security boundary."

Test categories:
- Caught by validator: asm injection, #define aliases, extern-then-call of
  prohibited functions, prohibited headers
- NOT caught by validator (documented limitation): function pointer aliasing
  to system. Tests that document this limitation explicitly verify the
  behavior and reference the container policy as the defense.
- Fork bomb harnesses: caught via pids-limit (container) and fork rejection
  (AST check catches fork/vfork direct calls)
"""

from __future__ import annotations

import pytest

from deep_code_security.fuzzer.execution._c_worker import (
    HarnessValidationError,
    _validate_harness_source,
)


# ──────────────────────────────────────────────────────────────────────────────
# Caught by AST validator
# ──────────────────────────────────────────────────────────────────────────────


class TestCaughtByValidator:
    def test_rejects_inline_asm_nop(self) -> None:
        """Inline asm() with nop instruction is caught."""
        harness = """\
#include <stdlib.h>
extern int f(int x);
int main(void) {
    asm("nop");
    f(0);
    return 0;
}
"""
        with pytest.raises(HarnessValidationError):
            _validate_harness_source(harness)

    def test_rejects_syscall_via_asm(self) -> None:
        """Inline asm performing a syscall is caught by asm node rejection."""
        harness = """\
#include <stdlib.h>
extern int f(int x);
int main(void) {
    long result;
    asm volatile("syscall"
        : "=a" (result)
        : "0" (60), "D" (0)
        :);
    return 0;
}
"""
        with pytest.raises(HarnessValidationError):
            _validate_harness_source(harness)

    def test_rejects_define_alias_for_system(self) -> None:
        """#define S system is caught by #define rejection (not function call check)."""
        harness = """\
#include <stdlib.h>
#define S system
extern int f(int x);
int main(void) {
    S("id");
    return 0;
}
"""
        # #define is rejected before we even get to call checking
        with pytest.raises(HarnessValidationError, match="[Pp]reprocessor|define"):
            _validate_harness_source(harness)

    def test_rejects_direct_system_call(self) -> None:
        """Direct system() call is caught by function call check."""
        harness = """\
#include <stdlib.h>
extern int f(int x);
int main(void) {
    system("id");
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]rohibited"):
            _validate_harness_source(harness)

    def test_rejects_extern_dlsym_call(self) -> None:
        """extern dlsym() call is caught by function call check.

        Even if the harness uses an extern declaration instead of
        #include <dlfcn.h>, the actual dlsym() call is caught.
        """
        harness = """\
#include <stdlib.h>
extern void *dlsym(void *handle, const char *name);
extern int f(int x);
int main(void) {
    void *fn = dlsym((void *)0, "system");
    f(0);
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]rohibited"):
            _validate_harness_source(harness)

    def test_rejects_prohibited_include_unistd(self) -> None:
        """#include <unistd.h> is caught by include validation."""
        harness = """\
#include <stdlib.h>
#include <unistd.h>
extern int f(int x);
int main(void) {
    f(0);
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]rohibited|header|not allowed"):
            _validate_harness_source(harness)

    def test_rejects_fork_call(self) -> None:
        """Direct fork() call is caught by function call check."""
        harness = """\
#include <stdlib.h>
extern int f(int x);
int main(void) {
    int pid = fork();
    if (pid == 0) { f(0); }
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]rohibited"):
            _validate_harness_source(harness)

    def test_rejects_vfork_call(self) -> None:
        """Direct vfork() call is caught."""
        harness = """\
#include <stdlib.h>
extern int f(int x);
int main(void) {
    int pid = vfork();
    if (pid == 0) { f(0); }
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]rohibited"):
            _validate_harness_source(harness)

    def test_rejects_socket_call(self) -> None:
        """Direct socket() call is caught."""
        harness = """\
#include <stdlib.h>
extern int f(int x);
int main(void) {
    int s = socket(2, 1, 0);
    f(s);
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]rohibited"):
            _validate_harness_source(harness)

    def test_rejects_execve_call(self) -> None:
        """Direct execve() call is caught."""
        harness = """\
#include <stdlib.h>
extern int f(int x);
int main(void) {
    char *argv[] = {"/bin/sh", 0};
    execve("/bin/sh", argv, 0);
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]rohibited"):
            _validate_harness_source(harness)

    def test_rejects_undef_directive(self) -> None:
        """#undef directive is caught."""
        harness = """\
#include <stdlib.h>
extern int f(int x);
int main(void) {
#undef NULL
    f(0);
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]reprocessor|undef"):
            _validate_harness_source(harness)

    def test_rejects_no_main(self) -> None:
        """A harness with no main() is rejected."""
        harness = """\
#include <stdlib.h>
extern int f(int x);
void helper(void) { f(0); }
"""
        with pytest.raises(HarnessValidationError, match="main"):
            _validate_harness_source(harness)


# ──────────────────────────────────────────────────────────────────────────────
# NOT caught by AST validator (documented limitations)
# ──────────────────────────────────────────────────────────────────────────────


class TestDocumentedLimitations:
    def test_function_pointer_aliasing_not_caught_by_ast(self) -> None:
        """DOCUMENTED LIMITATION: function pointer aliasing to system() bypasses AST check.

        The AST validator checks call_expression nodes where the function field
        is an identifier. Function pointer calls have an identifier that is the
        pointer variable name (e.g., 'fn'), not 'system'. This is NOT caught.

        Defense: Container policy (--network=none, /bin/sh not present in
        container, cap-drop=ALL, seccomp) prevents meaningful exploitation.

        This test documents the limitation and verifies the validator does NOT
        reject this pattern (so we know where the gap is).
        """
        # This harness assigns system to a function pointer and calls through it
        harness = """\
#include <stdlib.h>
typedef int (*fn_t)(const char *);
extern int f(int x);
int main(void) {
    fn_t fn = system;
    fn("id");
    return 0;
}
"""
        # The validator should NOT raise here (documented limitation)
        # The container security policy is the defense.
        try:
            _validate_harness_source(harness)
            # If we get here, the limitation is confirmed: validator did not catch it
        except HarnessValidationError:
            # If the validator was improved to catch this, the test should be updated
            pytest.skip(
                "AST validator now catches function pointer aliasing (beyond documented scope)"
            )

    def test_macro_obfuscation_caught_by_define_rejection(self) -> None:
        """#define-based obfuscation is caught because #define itself is rejected.

        This documents that the #define rejection (step 5) catches macro-based
        obfuscation before it can alias prohibited functions.
        """
        harness = """\
#include <stdlib.h>
#define SAFE_CALL system
extern int f(int x);
int main(void) {
    SAFE_CALL("id");
    return 0;
}
"""
        # #define is rejected even if the alias name looks innocuous
        with pytest.raises(HarnessValidationError, match="[Pp]reprocessor|define"):
            _validate_harness_source(harness)


# ──────────────────────────────────────────────────────────────────────────────
# Fork bomb patterns
# ──────────────────────────────────────────────────────────────────────────────


class TestForkBombPrevention:
    def test_direct_fork_bomb_caught(self) -> None:
        """A classic fork bomb is caught because fork() is prohibited."""
        harness = """\
#include <stdlib.h>
int main(void) {
    while (1) { fork(); }
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]rohibited"):
            _validate_harness_source(harness)

    def test_recursive_fork_caught(self) -> None:
        """Recursive fork() calls are caught by fork prohibition."""
        harness = """\
#include <stdlib.h>
void bomb(void) {
    fork();
    bomb();
}
int main(void) {
    bomb();
    return 0;
}
"""
        with pytest.raises(HarnessValidationError, match="[Pp]rohibited"):
            _validate_harness_source(harness)

    def test_infinite_loop_without_fork_not_caught_by_ast(self) -> None:
        """An infinite loop without fork() is NOT caught by AST validation.

        Defense: Container pids-limit and per-binary execution timeout prevent
        this from hanging indefinitely.
        """
        harness = """\
#include <stdlib.h>
extern int f(int x);
int main(void) {
    while (1) { f(0); }
    return 0;
}
"""
        # Should not raise -- infinite loops are a quality/timeout issue, not a security issue
        # The container timeout (DCS_FUZZ_TIMEOUT_MS) kills the process
        try:
            _validate_harness_source(harness)
        except HarnessValidationError:
            pytest.skip(
                "AST validator catches infinite loops (beyond documented scope)"
            )
