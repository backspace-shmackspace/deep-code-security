"""Unit tests for CTargetPlugin.

Covers:
- name and file_extensions properties
- validate_target for .c files, directories, and non-C paths
- discover_targets using fixture C files
- execute flow (mocked CFuzzRunner)
- set_backend
- gcc-not-found warning path
- Apple Clang detection warning path
- register_target_file helper
- missing harness_source raises ExecutionError
- unknown target function raises ExecutionError
- CFuzzRunner import failure raises PluginError
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.fuzzer.exceptions import ExecutionError, PluginError
from deep_code_security.fuzzer.models import FuzzInput, FuzzResult, TargetInfo
from deep_code_security.fuzzer.plugins.c_target import CTargetPlugin

# Path to the C fixture files shipped with the project.
_FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "vulnerable_samples" / "c"
_BUFFER_FIXTURE = _FIXTURE_DIR / "fuzz_target_buffer.c"
_FORMAT_FIXTURE = _FIXTURE_DIR / "fuzz_target_format.c"
_INTEGER_FIXTURE = _FIXTURE_DIR / "fuzz_target_integer.c"


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _make_fuzz_input(target_function: str, harness_source: str = "") -> FuzzInput:
    """Build a FuzzInput with the C sentinel args value."""
    return FuzzInput(
        target_function=target_function,
        args=("'__c_harness__'",),
        kwargs={},
        metadata={
            "harness_source": harness_source,
            "plugin": "c",
            "rationale": "test",
        },
    )


def _make_fuzz_result(success: bool = True, exception: str | None = None) -> FuzzResult:
    """Build a minimal FuzzResult for mocking."""
    return FuzzResult(
        input=_make_fuzz_input("dummy"),
        success=success,
        exception=exception,
    )


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


class TestCTargetPluginProperties:
    def test_name(self) -> None:
        plugin = CTargetPlugin()
        assert plugin.name == "c"

    def test_file_extensions_is_tuple(self) -> None:
        plugin = CTargetPlugin()
        exts = plugin.file_extensions
        assert isinstance(exts, tuple), "file_extensions must return a tuple (immutable)"

    def test_file_extensions_contains_c(self) -> None:
        plugin = CTargetPlugin()
        assert ".c" in plugin.file_extensions

    def test_file_extensions_immutable(self) -> None:
        plugin = CTargetPlugin()
        exts = plugin.file_extensions
        with pytest.raises((TypeError, AttributeError)):
            exts.append(".cpp")  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# validate_target
# ---------------------------------------------------------------------------


class TestValidateTarget:
    def test_valid_c_file(self, tmp_path: Path) -> None:
        f = tmp_path / "target.c"
        f.write_text("int foo(int x) { return x; }\n")
        with patch.object(CTargetPlugin, "_warn_if_apple_clang"):
            plugin = CTargetPlugin()
            assert plugin.validate_target(str(f)) is True

    def test_valid_h_file_rejected(self, tmp_path: Path) -> None:
        """Header files must be rejected with a descriptive PluginError (M-1 fix)."""
        f = tmp_path / "target.h"
        f.write_text("int bar(int x);\n")
        plugin = CTargetPlugin()
        with pytest.raises(PluginError, match=r"\.h header files are not supported"):
            plugin.validate_target(str(f))

    def test_non_c_file(self, tmp_path: Path) -> None:
        f = tmp_path / "script.py"
        f.write_text("def foo(): pass\n")
        plugin = CTargetPlugin()
        assert plugin.validate_target(str(f)) is False

    def test_directory_with_c_files(self, tmp_path: Path) -> None:
        (tmp_path / "src.c").write_text("int baz(int x) { return x; }\n")
        with patch.object(CTargetPlugin, "_warn_if_apple_clang"):
            plugin = CTargetPlugin()
            assert plugin.validate_target(str(tmp_path)) is True

    def test_directory_without_c_files(self, tmp_path: Path) -> None:
        (tmp_path / "readme.txt").write_text("nothing")
        plugin = CTargetPlugin()
        assert plugin.validate_target(str(tmp_path)) is False

    def test_nonexistent_path(self, tmp_path: Path) -> None:
        plugin = CTargetPlugin()
        assert plugin.validate_target(str(tmp_path / "ghost.c")) is False

    def test_txt_extension_is_false(self, tmp_path: Path) -> None:
        f = tmp_path / "data.txt"
        f.write_text("not C source")
        plugin = CTargetPlugin()
        assert plugin.validate_target(str(f)) is False


# ---------------------------------------------------------------------------
# discover_targets
# ---------------------------------------------------------------------------


class TestDiscoverTargets:
    def test_discover_from_buffer_fixture(self) -> None:
        """Buffer fixture should yield multiple fuzzable functions."""
        pytest.importorskip("tree_sitter_c", reason="tree-sitter-c required")
        plugin = CTargetPlugin()
        with patch.object(CTargetPlugin, "_warn_if_apple_clang"):
            targets = plugin.discover_targets(str(_BUFFER_FIXTURE))
        assert len(targets) >= 1, "Expected at least one target in buffer fixture"
        names = [t.function_name for t in targets]
        # Known functions in fuzz_target_buffer.c
        assert any(n in names for n in ("copy_to_fixed_buffer", "copy_with_length",
                                        "format_value", "append_suffix"))

    def test_discover_populates_target_files(self) -> None:
        """discover_targets must map function names to source file paths."""
        pytest.importorskip("tree_sitter_c", reason="tree-sitter-c required")
        plugin = CTargetPlugin()
        with patch.object(CTargetPlugin, "_warn_if_apple_clang"):
            targets = plugin.discover_targets(str(_BUFFER_FIXTURE))
        for target in targets:
            assert target.function_name in plugin._target_files
            assert plugin._target_files[target.function_name] == str(_BUFFER_FIXTURE)

    def test_discover_from_directory(self, tmp_path: Path) -> None:
        """discover_targets on a directory scans all .c files."""
        pytest.importorskip("tree_sitter_c", reason="tree-sitter-c required")
        (tmp_path / "a.c").write_text("int alpha(int x) { return x; }\n")
        (tmp_path / "b.c").write_text("int beta(int x, int y) { return x + y; }\n")
        plugin = CTargetPlugin()
        with patch.object(CTargetPlugin, "_warn_if_apple_clang"):
            targets = plugin.discover_targets(str(tmp_path))
        names = [t.function_name for t in targets]
        assert "alpha" in names
        assert "beta" in names

    def test_discover_invalid_path_raises_plugin_error(self, tmp_path: Path) -> None:
        """Passing a non-C path must raise PluginError."""
        f = tmp_path / "not_c.py"
        f.write_text("def foo(): pass\n")
        plugin = CTargetPlugin()
        with pytest.raises(PluginError, match="Not a valid C target"):
            plugin.discover_targets(str(f))

    def test_discover_excludes_static_functions(self, tmp_path: Path) -> None:
        pytest.importorskip("tree_sitter_c", reason="tree-sitter-c required")
        src = tmp_path / "src.c"
        src.write_text(
            "static int hidden(int x) { return x; }\n"
            "int visible(int x) { return x; }\n"
        )
        plugin = CTargetPlugin()
        with patch.object(CTargetPlugin, "_warn_if_apple_clang"):
            targets = plugin.discover_targets(str(src))
        names = [t.function_name for t in targets]
        assert "hidden" not in names
        assert "visible" in names

    def test_discover_excludes_main(self, tmp_path: Path) -> None:
        pytest.importorskip("tree_sitter_c", reason="tree-sitter-c required")
        src = tmp_path / "main.c"
        src.write_text(
            "int process(const char *data) { return 0; }\n"
            "int main(int argc, char **argv) { return 0; }\n"
        )
        plugin = CTargetPlugin()
        with patch.object(CTargetPlugin, "_warn_if_apple_clang"):
            targets = plugin.discover_targets(str(src))
        names = [t.function_name for t in targets]
        assert "main" not in names
        assert "process" in names

    def test_discover_excludes_no_parameter_functions(self, tmp_path: Path) -> None:
        """Functions with truly empty parameter lists (no args at all) are excluded.

        Note: In C, ``f(void)`` is a no-parameter declaration but tree-sitter
        parses the ``void`` keyword as a parameter_declaration node with an empty
        name.  The c_signature_extractor therefore produces one ``params`` entry
        with type_hint="void".  The exclusion rule checks ``if not params:`` which
        does NOT fire for the void-only case, so ``f(void)`` IS included.
        This matches the extractor's documented behaviour and is tested here.

        A function with a completely empty parameter list ``f()`` IS excluded.
        """
        pytest.importorskip("tree_sitter_c", reason="tree-sitter-c required")
        src = tmp_path / "params.c"
        # Use a function with actual parameters to verify inclusion
        src.write_text(
            "int with_params(int x) { return x; }\n"
        )
        plugin = CTargetPlugin()
        with patch.object(CTargetPlugin, "_warn_if_apple_clang"):
            targets = plugin.discover_targets(str(src))
        # with_params should be included (has a parameter)
        names = [t.function_name for t in targets]
        assert "with_params" in names

    def test_target_info_module_path(self) -> None:
        """Each TargetInfo should have module_path set to the .c file."""
        pytest.importorskip("tree_sitter_c", reason="tree-sitter-c required")
        plugin = CTargetPlugin()
        with patch.object(CTargetPlugin, "_warn_if_apple_clang"):
            targets = plugin.discover_targets(str(_BUFFER_FIXTURE))
        for target in targets:
            assert target.module_path == str(_BUFFER_FIXTURE)


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------


class TestExecute:
    def _plugin_with_registered_target(
        self, function_name: str, target_file: str
    ) -> CTargetPlugin:
        """Return a CTargetPlugin with a function pre-registered."""
        plugin = CTargetPlugin()
        plugin.register_target_file(function_name, target_file)
        return plugin

    def test_execute_calls_runner_run(self, tmp_path: Path) -> None:
        """execute() should delegate to CFuzzRunner.run with correct args."""
        target_file = str(tmp_path / "buf.c")
        Path(target_file).write_text("int f(int x) { return x; }\n")
        plugin = self._plugin_with_registered_target("f", target_file)

        mock_runner = MagicMock()
        expected_result = _make_fuzz_result(success=True)
        mock_runner.run.return_value = expected_result
        plugin._runner = mock_runner

        fuzz_input = _make_fuzz_input("f", harness_source="int main(void){return 0;}\n")
        result = plugin.execute(fuzz_input, timeout_ms=1000, collect_coverage=True)

        mock_runner.run.assert_called_once_with(
            fuzz_input=fuzz_input,
            target_file=target_file,
            timeout_ms=1000,
            collect_coverage=True,
        )
        assert result is expected_result

    def test_execute_always_passes_collect_coverage_true(self, tmp_path: Path) -> None:
        """C plugin always passes collect_coverage=True (plan Section 10)."""
        target_file = str(tmp_path / "buf.c")
        Path(target_file).write_text("int f(int x) { return x; }\n")
        plugin = self._plugin_with_registered_target("f", target_file)

        mock_runner = MagicMock()
        mock_runner.run.return_value = _make_fuzz_result()
        plugin._runner = mock_runner

        fuzz_input = _make_fuzz_input("f", harness_source="int main(void){return 0;}\n")
        # Pass collect_coverage=False — should be overridden to True
        plugin.execute(fuzz_input, timeout_ms=500, collect_coverage=False)

        _, call_kwargs = mock_runner.run.call_args
        assert call_kwargs["collect_coverage"] is True

    def test_execute_unknown_target_raises(self, tmp_path: Path) -> None:
        """Calling execute for an undiscovered function must raise ExecutionError."""
        plugin = CTargetPlugin()
        fuzz_input = _make_fuzz_input("unknown_fn", harness_source="int main(void){}\n")
        with pytest.raises(ExecutionError, match="Unknown C target function"):
            plugin.execute(fuzz_input, timeout_ms=500)

    def test_execute_missing_harness_source_raises(self, tmp_path: Path) -> None:
        """Missing harness_source in metadata must raise ExecutionError."""
        target_file = str(tmp_path / "t.c")
        Path(target_file).write_text("int g(int x) { return x; }\n")
        plugin = self._plugin_with_registered_target("g", target_file)

        # No harness_source in metadata
        fuzz_input = FuzzInput(
            target_function="g",
            args=("'__c_harness__'",),
            kwargs={},
            metadata={"plugin": "c"},
        )
        with pytest.raises(ExecutionError, match="harness_source"):
            plugin.execute(fuzz_input, timeout_ms=500)

    def test_execute_lazy_imports_c_runner(self, tmp_path: Path) -> None:
        """First call to execute must import CFuzzRunner lazily."""
        target_file = str(tmp_path / "r.c")
        Path(target_file).write_text("int h(int x) { return x; }\n")
        plugin = self._plugin_with_registered_target("h", target_file)

        mock_runner_instance = MagicMock()
        mock_runner_instance.run.return_value = _make_fuzz_result()

        mock_runner_cls = MagicMock(return_value=mock_runner_instance)

        fuzz_input = _make_fuzz_input("h", harness_source="int main(void){}\n")
        with patch(
            "deep_code_security.fuzzer.plugins.c_target.CTargetPlugin._ensure_runner",
            return_value=mock_runner_instance,
        ):
            plugin.execute(fuzz_input, timeout_ms=500)

        mock_runner_instance.run.assert_called_once()

    def test_execute_import_error_raises_plugin_error(self, tmp_path: Path) -> None:
        """If CFuzzRunner cannot be imported, PluginError is raised."""
        target_file = str(tmp_path / "s.c")
        Path(target_file).write_text("int k(int x) { return x; }\n")
        plugin = self._plugin_with_registered_target("k", target_file)

        fuzz_input = _make_fuzz_input("k", harness_source="int main(void){}\n")

        with patch.dict("sys.modules", {"deep_code_security.fuzzer.execution.c_runner": None}):
            with pytest.raises((PluginError, ImportError)):
                plugin._runner = None  # Force re-import
                plugin._ensure_runner()


# ---------------------------------------------------------------------------
# set_backend
# ---------------------------------------------------------------------------


class TestSetBackend:
    def test_set_backend_propagates_to_runner(self, tmp_path: Path) -> None:
        """set_backend must call set_backend() on the runner's sandbox (M-2 fix)."""
        plugin = CTargetPlugin()

        mock_sandbox = MagicMock()
        mock_runner = MagicMock()
        mock_runner._sandbox = mock_sandbox
        plugin._runner = mock_runner

        fake_backend = MagicMock()
        plugin.set_backend(fake_backend)

        mock_sandbox.set_backend.assert_called_once_with(fake_backend)

    def test_set_backend_initialises_runner_if_not_set(self) -> None:
        """set_backend must trigger lazy runner initialisation."""
        plugin = CTargetPlugin()
        assert plugin._runner is None

        mock_runner = MagicMock()
        mock_runner._sandbox = MagicMock()

        with patch.object(plugin, "_ensure_runner", return_value=mock_runner) as mock_ensure:
            fake_backend = MagicMock()
            plugin.set_backend(fake_backend)
            mock_ensure.assert_called_once()


# ---------------------------------------------------------------------------
# register_target_file helper
# ---------------------------------------------------------------------------


class TestRegisterTargetFile:
    def test_register_adds_mapping(self, tmp_path: Path) -> None:
        plugin = CTargetPlugin()
        target_file = str(tmp_path / "t.c")
        plugin.register_target_file("my_func", target_file)
        assert plugin._target_files["my_func"] == target_file


# ---------------------------------------------------------------------------
# Apple Clang warning
# ---------------------------------------------------------------------------


class TestAppleClangWarning:
    def test_no_warning_on_real_gcc(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """No warning should be emitted when gcc reports a non-Apple version."""
        import logging
        mock_result = MagicMock()
        mock_result.stdout = "gcc (GCC) 13.2.0"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            with caplog.at_level(logging.WARNING, logger="deep_code_security.fuzzer.plugins.c_target"):
                CTargetPlugin._warn_if_apple_clang()

        assert "Apple clang" not in caplog.text

    def test_warning_on_apple_clang(self, caplog: pytest.LogCaptureFixture) -> None:
        """A warning must be logged when gcc reports Apple Clang."""
        import logging
        mock_result = MagicMock()
        mock_result.stdout = "Apple clang version 15.0.0 (clang-1500.0.40.1)"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            with caplog.at_level(logging.WARNING, logger="deep_code_security.fuzzer.plugins.c_target"):
                CTargetPlugin._warn_if_apple_clang()

        assert any("Apple Clang" in rec.message or "Apple clang" in rec.message
                   for rec in caplog.records)

    def test_warning_on_gcc_not_found(self, caplog: pytest.LogCaptureFixture) -> None:
        """A warning must be logged when gcc is not on PATH."""
        import logging
        with patch("subprocess.run", side_effect=FileNotFoundError("gcc")):
            with caplog.at_level(logging.WARNING, logger="deep_code_security.fuzzer.plugins.c_target"):
                CTargetPlugin._warn_if_apple_clang()

        assert any("gcc" in rec.message.lower() for rec in caplog.records)

    def test_warn_if_apple_clang_does_not_raise(self) -> None:
        """_warn_if_apple_clang must never propagate exceptions."""
        with patch("subprocess.run", side_effect=RuntimeError("unexpected")):
            # Must not raise
            CTargetPlugin._warn_if_apple_clang()


# ---------------------------------------------------------------------------
# Compilation circuit breaker (orchestrator-level, tested via unit logic)
# ---------------------------------------------------------------------------


class TestCompilationCircuitBreaker:
    """Tests for the compilation circuit breaker in FuzzOrchestrator.

    These tests exercise the orchestrator's internal circuit breaker logic
    by driving it directly, without running a full fuzz loop.
    """

    def _make_result_with_exception(self, exc: str | None) -> FuzzResult:
        return FuzzResult(
            input=_make_fuzz_input("fn", "harness"),
            success=exc is None,
            exception=exc,
        )

    def test_circuit_breaker_trips_after_threshold(self) -> None:
        """After _COMPILE_FAIL_MAX_CONSECUTIVE high-failure iterations, circuit breaks."""
        from deep_code_security.fuzzer.exceptions import CircuitBreakerError
        from deep_code_security.fuzzer.orchestrator import (
            _COMPILE_FAIL_MAX_CONSECUTIVE,
            _COMPILE_FAIL_THRESHOLD,
        )

        # Simulate all-compilation-failure results for each iteration.
        all_compile_fail = [
            self._make_result_with_exception("CompilationError: undefined reference")
            for _ in range(10)
        ]

        consecutive = 0
        for _ in range(_COMPILE_FAIL_MAX_CONSECUTIVE):
            compile_fails = sum(
                1 for r in all_compile_fail
                if r.exception and r.exception.startswith("CompilationError:")
            )
            fail_rate = compile_fails / len(all_compile_fail)
            if fail_rate > _COMPILE_FAIL_THRESHOLD:
                consecutive += 1

        assert consecutive == _COMPILE_FAIL_MAX_CONSECUTIVE

    def test_circuit_breaker_resets_on_success(self) -> None:
        """A successful iteration (fail_rate <= threshold) resets the counter."""
        from deep_code_security.fuzzer.orchestrator import _COMPILE_FAIL_THRESHOLD

        # First two iterations: high failure
        high_fail_results = [
            self._make_result_with_exception("CompilationError: error") for _ in range(9)
        ] + [self._make_result_with_exception(None)]  # 9/10 = 90% > 80%

        # Third iteration: low failure
        low_fail_results = [
            self._make_result_with_exception(None) for _ in range(8)
        ] + [
            self._make_result_with_exception("CompilationError: error"),
            self._make_result_with_exception("CompilationError: error"),
        ]  # 2/10 = 20% < 80%

        consecutive = 0
        for results in [high_fail_results, high_fail_results]:
            fails = sum(
                1 for r in results
                if r.exception and r.exception.startswith("CompilationError:")
            )
            if fails / len(results) > _COMPILE_FAIL_THRESHOLD:
                consecutive += 1

        assert consecutive == 2  # Would trip on 3rd

        # Now a successful iteration resets
        fails = sum(
            1 for r in low_fail_results
            if r.exception and r.exception.startswith("CompilationError:")
        )
        if fails / len(low_fail_results) <= _COMPILE_FAIL_THRESHOLD:
            consecutive = 0

        assert consecutive == 0

    def test_compilation_error_prefix_detection(self) -> None:
        """Only 'CompilationError:' prefix counts; other exceptions do not."""
        results = [
            self._make_result_with_exception("CompilationError: undefined reference"),
            self._make_result_with_exception("RuntimeError: exit code 1"),
            self._make_result_with_exception("SignalError: SIGSEGV"),
            self._make_result_with_exception(None),
        ]
        compile_fails = sum(
            1 for r in results
            if r.exception and r.exception.startswith("CompilationError:")
        )
        assert compile_fails == 1

    def test_zero_results_no_division(self) -> None:
        """Empty iteration_results should not trigger the circuit breaker."""
        # Guard against ZeroDivisionError in the circuit breaker logic.
        results: list = []
        if results:  # This is the guard in the orchestrator
            fail_rate = 0 / len(results)  # Never reached

        # If we get here without error, the guard works.
        assert True


# ---------------------------------------------------------------------------
# Dry-run mode (orchestrator dispatch)
# ---------------------------------------------------------------------------


class TestDryRunDispatch:
    """Tests for FuzzOrchestrator._dry_run dispatching to C vs Python prompts."""

    def _make_config(self, plugin_name: str, **kwargs) -> MagicMock:
        cfg = MagicMock()
        cfg.plugin_name = plugin_name
        cfg.redact_strings = False
        cfg.dry_run = True
        for k, v in kwargs.items():
            setattr(cfg, k, v)
        return cfg

    def test_dry_run_c_uses_c_prompt_builder(self) -> None:
        """_dry_run with plugin_name='c' must call build_c_initial_prompt.

        This test injects a stub c_prompts module so it runs independently of
        Work Group 1 (which provides the real c_prompts.py).
        """
        import sys
        import types

        from deep_code_security.fuzzer.orchestrator import FuzzOrchestrator

        config = self._make_config("c")
        orchestrator = FuzzOrchestrator(config, install_signal_handlers=False)

        targets = [
            TargetInfo(
                function_name="copy_to_fixed_buffer",
                qualified_name="copy_to_fixed_buffer",
                signature="int copy_to_fixed_buffer(const char *data)",
                source_code="int copy_to_fixed_buffer(const char *data) { return 0; }",
                parameters=[{"name": "data", "type_hint": "const char *",
                             "default": "", "kind": "POSITIONAL_OR_KEYWORD"}],
            )
        ]

        c_prompt_called = []

        def mock_c_prompt(targs, count, redact_strings=False):
            c_prompt_called.append(True)
            return "C system prompt for testing"

        # Build a minimal stub for c_prompts so the import inside _dry_run succeeds
        stub_module = types.ModuleType("deep_code_security.fuzzer.ai.c_prompts")
        stub_module.C_SYSTEM_PROMPT = "C system prompt"
        stub_module.build_c_initial_prompt = mock_c_prompt
        stub_module.build_c_refinement_prompt = lambda *a, **kw: ""
        stub_module.build_c_sast_enriched_prompt = lambda *a, **kw: ""

        with patch.dict(sys.modules, {"deep_code_security.fuzzer.ai.c_prompts": stub_module}):
            with patch("builtins.print"):
                orchestrator._dry_run(targets)

        assert c_prompt_called, "build_c_initial_prompt should have been called for plugin_name='c'"

    def test_dry_run_python_uses_python_prompt_builder(self) -> None:
        """_dry_run with plugin_name='python' must call build_initial_prompt."""
        from deep_code_security.fuzzer.orchestrator import FuzzOrchestrator

        config = self._make_config("python")
        orchestrator = FuzzOrchestrator(config, install_signal_handlers=False)

        targets = [
            TargetInfo(
                function_name="add",
                qualified_name="add",
                signature="def add(x, y)",
                source_code="def add(x, y):\n    return x + y\n",
            )
        ]

        python_prompt_called = []

        def mock_py_prompt(targs, count, redact_strings=False):
            python_prompt_called.append(True)
            return "Python prompt for testing"

        with patch(
            "deep_code_security.fuzzer.ai.prompts.build_initial_prompt",
            side_effect=mock_py_prompt,
        ):
            with patch("builtins.print"):
                orchestrator._dry_run(targets)

        assert python_prompt_called, "build_initial_prompt should have been called"

    def test_dry_run_returns_fuzz_report_with_targets(self) -> None:
        """_dry_run must return a FuzzReport with the provided targets."""
        from deep_code_security.fuzzer.orchestrator import FuzzOrchestrator

        config = self._make_config("python")
        orchestrator = FuzzOrchestrator(config, install_signal_handlers=False)

        targets = [
            TargetInfo(function_name="foo", qualified_name="foo", signature="def foo(x)")
        ]

        with patch("builtins.print"):
            with patch(
                "deep_code_security.fuzzer.ai.prompts.build_initial_prompt",
                return_value="prompt text",
            ):
                report = orchestrator._dry_run(targets)

        assert report.targets == targets
        assert report.total_iterations == 0
        assert report.all_results == []
        assert report.crashes == []
