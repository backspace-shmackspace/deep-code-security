"""Unit tests for SemgrepBackend.

All subprocess calls are mocked so no real ``semgrep`` binary is required.
Fixture JSON files in ``tests/fixtures/semgrep_output/`` contain known
Semgrep OSS output (confirmed to NOT contain ``dataflow_trace``).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.hunter.models import RawFinding
from deep_code_security.hunter.scanner_backend import BackendResult
from deep_code_security.hunter.semgrep_backend import SemgrepBackend
from deep_code_security.mcp.input_validator import validate_raw_finding
from deep_code_security.shared.config import reset_config
from deep_code_security.shared.file_discovery import DiscoveredFile
from deep_code_security.shared.language import Language

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "semgrep_output"


def _load_fixture(name: str) -> dict[str, Any]:
    """Load a semgrep_output fixture file as a dict."""
    return json.loads((FIXTURES_DIR / name).read_text())


def _make_discovered_file(path: Path) -> DiscoveredFile:
    """Create a DiscoveredFile for the given resolved path."""
    return DiscoveredFile(
        path=path.resolve(),
        language=Language.PYTHON,
        size_bytes=1024,
    )


def _make_subprocess_result(
    stdout: bytes,
    returncode: int = 1,
    stderr: bytes = b"",
) -> MagicMock:
    """Build a mock CompletedProcess suitable for patching subprocess.run."""
    mock_proc = MagicMock()
    mock_proc.stdout = stdout
    mock_proc.stderr = stderr
    mock_proc.returncode = returncode
    return mock_proc


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_config():
    """Reset global config singleton and SemgrepBackend class-level caches before each test.

    SemgrepBackend caches the binary lookup in _binary_cache and the version in
    _cached_version to avoid repeated subprocess calls.  Tests that mock
    shutil.which or subprocess.run must reset these caches so each test gets
    a fresh lookup and is not affected by a previous test's cached state.
    """
    reset_config()
    SemgrepBackend._binary_cache = None
    SemgrepBackend._available_cache = None
    SemgrepBackend._cached_version = None
    yield
    reset_config()
    SemgrepBackend._binary_cache = None
    SemgrepBackend._available_cache = None
    SemgrepBackend._cached_version = None


@pytest.fixture
def cwe89_fixture() -> dict[str, Any]:
    return _load_fixture("python_cwe89_sql_injection.json")


@pytest.fixture
def cwe78_fixture() -> dict[str, Any]:
    return _load_fixture("python_cwe78_command_injection.json")


@pytest.fixture
def empty_fixture() -> dict[str, Any]:
    return _load_fixture("empty_results.json")


@pytest.fixture
def malformed_fixture() -> dict[str, Any]:
    return _load_fixture("malformed_result.json")


@pytest.fixture
def backend() -> SemgrepBackend:
    return SemgrepBackend()


# ---------------------------------------------------------------------------
# 1. Normalization from OSS fixture (no dataflow_trace)
# ---------------------------------------------------------------------------


class TestNormalizeResult:
    """Tests for _normalize_result() -- OSS JSON without dataflow_trace."""

    def test_normalize_cwe89_source_from_metavar(
        self, backend: SemgrepBackend, tmp_path: Path, cwe89_fixture: dict[str, Any]
    ) -> None:
        """$SOURCE metavar present -> Source location comes from metavar start."""
        raw_result = cwe89_fixture["results"][0]
        finding = backend._normalize_result(raw_result, tmp_path)

        assert finding is not None
        # $SOURCE.start.line = 40, $SOURCE.start.col = 12
        assert finding.source.line == 40
        assert finding.source.column == 12

    def test_normalize_cwe89_source_function_from_metadata(
        self, backend: SemgrepBackend, tmp_path: Path, cwe89_fixture: dict[str, Any]
    ) -> None:
        """Source function comes from metadata.source_function."""
        raw_result = cwe89_fixture["results"][0]
        finding = backend._normalize_result(raw_result, tmp_path)

        assert finding is not None
        assert finding.source.function == "request.form"
        assert finding.source.category == "web_input"

    def test_normalize_cwe89_sink_location_is_match_location(
        self, backend: SemgrepBackend, tmp_path: Path, cwe89_fixture: dict[str, Any]
    ) -> None:
        """Sink location comes from match start (line/col), not from metavar."""
        raw_result = cwe89_fixture["results"][0]
        finding = backend._normalize_result(raw_result, tmp_path)

        assert finding is not None
        # match start.line = 42, match start.col = 8
        assert finding.sink.line == 42
        assert finding.sink.column == 8

    def test_normalize_cwe89_sink_metadata(
        self, backend: SemgrepBackend, tmp_path: Path, cwe89_fixture: dict[str, Any]
    ) -> None:
        """Sink function, category, and CWE come from metadata."""
        raw_result = cwe89_fixture["results"][0]
        finding = backend._normalize_result(raw_result, tmp_path)

        assert finding is not None
        assert finding.sink.function == "cursor.execute"
        assert finding.sink.category == "sql_injection"
        assert finding.sink.cwe == "CWE-89"

    def test_normalize_cwe89_taint_path_two_steps(
        self, backend: SemgrepBackend, tmp_path: Path, cwe89_fixture: dict[str, Any]
    ) -> None:
        """Synthetic TaintPath always has exactly 2 steps (source + sink)."""
        raw_result = cwe89_fixture["results"][0]
        finding = backend._normalize_result(raw_result, tmp_path)

        assert finding is not None
        assert len(finding.taint_path.steps) == 2

    def test_normalize_cwe89_taint_path_sanitized_false(
        self, backend: SemgrepBackend, tmp_path: Path, cwe89_fixture: dict[str, Any]
    ) -> None:
        """sanitized is always False for Semgrep OSS findings."""
        raw_result = cwe89_fixture["results"][0]
        finding = backend._normalize_result(raw_result, tmp_path)

        assert finding is not None
        assert finding.taint_path.sanitized is False

    def test_normalize_cwe89_vulnerability_class(
        self, backend: SemgrepBackend, tmp_path: Path, cwe89_fixture: dict[str, Any]
    ) -> None:
        """vulnerability_class is the full CWE string from metadata."""
        raw_result = cwe89_fixture["results"][0]
        finding = backend._normalize_result(raw_result, tmp_path)

        assert finding is not None
        assert finding.vulnerability_class == "CWE-89: SQL Injection"

    def test_normalize_cwe89_sink_file_is_absolute(
        self, backend: SemgrepBackend, tmp_path: Path, cwe89_fixture: dict[str, Any]
    ) -> None:
        """Sink.file is an absolute resolved path."""
        raw_result = cwe89_fixture["results"][0]
        finding = backend._normalize_result(raw_result, tmp_path)

        assert finding is not None
        assert Path(finding.sink.file).is_absolute()


# ---------------------------------------------------------------------------
# 2. $SOURCE metavar presence/absence
# ---------------------------------------------------------------------------


class TestSourceMetavar:
    """Tests for source location derivation from $SOURCE metavar."""

    def test_no_source_metavar_source_location_falls_back_to_match(
        self, backend: SemgrepBackend, tmp_path: Path, cwe89_fixture: dict[str, Any]
    ) -> None:
        """When $SOURCE metavar is absent, source location equals match location."""
        raw_result = cwe89_fixture["results"][0]
        # Remove the $SOURCE metavar
        raw_result["extra"]["metavars"] = {}

        finding = backend._normalize_result(raw_result, tmp_path)

        assert finding is not None
        # Without $SOURCE, source location should match the sink location
        assert finding.source.line == raw_result["start"]["line"]
        assert finding.source.column == raw_result["start"]["col"]

    def test_source_metavar_present_overrides_match_location(
        self, backend: SemgrepBackend, tmp_path: Path, cwe89_fixture: dict[str, Any]
    ) -> None:
        """When $SOURCE is present, source location differs from match location."""
        raw_result = cwe89_fixture["results"][0]
        finding = backend._normalize_result(raw_result, tmp_path)

        assert finding is not None
        # $SOURCE.start.line=40 != match start.line=42
        assert finding.source.line != raw_result["start"]["line"]


# ---------------------------------------------------------------------------
# 3. Subprocess command construction
# ---------------------------------------------------------------------------


class TestSubprocessInvocation:
    """Tests that the correct subprocess command is constructed."""

    def _run_scan_with_mock(
        self,
        backend: SemgrepBackend,
        tmp_path: Path,
        fixture_data: dict[str, Any],
    ) -> tuple[list[str], BackendResult]:
        """Helper: mock subprocess.run, run scan, return (captured_cmd, result)."""
        app_file = tmp_path / "app.py"
        app_file.touch()
        discovered = [_make_discovered_file(app_file)]

        proc_mock = _make_subprocess_result(
            stdout=json.dumps(fixture_data).encode(), returncode=1
        )

        captured_cmd: list[str] = []

        def _fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return proc_mock

        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch("deep_code_security.hunter.semgrep_backend.subprocess.run", side_effect=_fake_run),
            patch(
                "deep_code_security.hunter.semgrep_backend.get_config",
                return_value=_make_mock_config(tmp_path),
            ),
        ):
            result = backend.scan_files(tmp_path, discovered, "medium")

        return captured_cmd, result

    def test_metrics_off_in_command(
        self, backend: SemgrepBackend, tmp_path: Path, empty_fixture: dict[str, Any]
    ) -> None:
        """``--metrics=off`` must appear in the semgrep command."""
        cmd, _ = self._run_scan_with_mock(backend, tmp_path, empty_fixture)
        assert "--metrics=off" in cmd

    def test_command_is_list_not_string(
        self, backend: SemgrepBackend, tmp_path: Path, empty_fixture: dict[str, Any]
    ) -> None:
        """The subprocess command must be a list (never shell=True)."""
        captured_cmds: list[Any] = []

        app_file = tmp_path / "app.py"
        app_file.touch()
        discovered = [_make_discovered_file(app_file)]

        proc_mock = _make_subprocess_result(
            stdout=json.dumps(empty_fixture).encode(), returncode=0
        )

        def _capture_run(cmd, **kwargs):
            captured_cmds.append(cmd)
            # Verify shell is not set to True
            assert kwargs.get("shell", False) is False, "shell=True must never be used"
            return proc_mock

        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch("deep_code_security.hunter.semgrep_backend.subprocess.run", side_effect=_capture_run),
            patch(
                "deep_code_security.hunter.semgrep_backend.get_config",
                return_value=_make_mock_config(tmp_path),
            ),
        ):
            backend.scan_files(tmp_path, discovered, "medium")

        assert len(captured_cmds) == 1
        assert isinstance(captured_cmds[0], list)

    def test_no_git_ignore_in_command(
        self, backend: SemgrepBackend, tmp_path: Path, empty_fixture: dict[str, Any]
    ) -> None:
        """``--no-git-ignore`` must appear in the command."""
        cmd, _ = self._run_scan_with_mock(backend, tmp_path, empty_fixture)
        assert "--no-git-ignore" in cmd

    def test_timeout_arg_in_command(
        self, backend: SemgrepBackend, tmp_path: Path, empty_fixture: dict[str, Any]
    ) -> None:
        """``--timeout`` flag must appear in the command."""
        cmd, _ = self._run_scan_with_mock(backend, tmp_path, empty_fixture)
        assert "--timeout" in cmd

    def test_max_target_bytes_in_command(
        self, backend: SemgrepBackend, tmp_path: Path, empty_fixture: dict[str, Any]
    ) -> None:
        """``--max-target-bytes`` must appear in the command."""
        cmd, _ = self._run_scan_with_mock(backend, tmp_path, empty_fixture)
        assert "--max-target-bytes" in cmd


# ---------------------------------------------------------------------------
# 4. Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Tests for graceful error handling."""

    def test_timeout_returns_empty_result(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        """When subprocess times out, BackendResult has empty findings and a diagnostic."""
        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch(
                "deep_code_security.hunter.semgrep_backend.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=["semgrep"], timeout=125),
            ),
            patch(
                "deep_code_security.hunter.semgrep_backend.get_config",
                return_value=_make_mock_config(tmp_path),
            ),
        ):
            result = backend.scan_files(tmp_path, [], "medium")

        assert result.findings == []
        assert result.backend_name == "semgrep"
        assert any("timed out" in d.lower() for d in result.diagnostics)

    def test_non_zero_exit_returns_empty_result_with_diagnostic(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        """Non-zero exit code (e.g. 2 = error) returns empty findings with diagnostic."""
        proc_mock = _make_subprocess_result(
            stdout=b"",
            returncode=2,
            stderr=b"FATAL: rule parse error",
        )
        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch("deep_code_security.hunter.semgrep_backend.subprocess.run", return_value=proc_mock),
            patch(
                "deep_code_security.hunter.semgrep_backend.get_config",
                return_value=_make_mock_config(tmp_path),
            ),
        ):
            result = backend.scan_files(tmp_path, [], "medium")

        assert result.findings == []
        assert len(result.diagnostics) >= 1
        assert any("2" in d for d in result.diagnostics)

    def test_malformed_json_returns_empty_result(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        """Malformed JSON from semgrep returns empty findings with diagnostic."""
        proc_mock = _make_subprocess_result(
            stdout=b"this is not json", returncode=1
        )
        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch("deep_code_security.hunter.semgrep_backend.subprocess.run", return_value=proc_mock),
            patch(
                "deep_code_security.hunter.semgrep_backend.get_config",
                return_value=_make_mock_config(tmp_path),
            ),
        ):
            result = backend.scan_files(tmp_path, [], "medium")

        assert result.findings == []
        assert any("parse" in d.lower() or "json" in d.lower() for d in result.diagnostics)


# ---------------------------------------------------------------------------
# 5. Post-filtering
# ---------------------------------------------------------------------------


class TestPostFiltering:
    """Tests that results are filtered against discovered_files."""

    def test_finding_excluded_when_file_not_in_discovered(
        self, backend: SemgrepBackend, tmp_path: Path, cwe89_fixture: dict[str, Any]
    ) -> None:
        """Finding for a file not in discovered_files is excluded."""
        # cwe89_fixture references "app.py" under tmp_path, but discovered_files
        # contains a different file.
        other_file = tmp_path / "other.py"
        other_file.touch()
        discovered = [_make_discovered_file(other_file)]

        proc_mock = _make_subprocess_result(
            stdout=json.dumps(cwe89_fixture).encode(), returncode=1
        )

        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch("deep_code_security.hunter.semgrep_backend.subprocess.run", return_value=proc_mock),
            patch(
                "deep_code_security.hunter.semgrep_backend.get_config",
                return_value=_make_mock_config(tmp_path),
            ),
        ):
            result = backend.scan_files(tmp_path, discovered, "medium")

        assert result.findings == []
        assert any("post-filter" in d.lower() or "filtered" in d.lower() for d in result.diagnostics)

    def test_finding_included_when_file_in_discovered(
        self, backend: SemgrepBackend, tmp_path: Path, cwe89_fixture: dict[str, Any]
    ) -> None:
        """Finding is included when the file is present in discovered_files."""
        # cwe89_fixture references "app.py" -- create it under tmp_path
        app_file = tmp_path / "app.py"
        app_file.touch()
        discovered = [_make_discovered_file(app_file)]

        proc_mock = _make_subprocess_result(
            stdout=json.dumps(cwe89_fixture).encode(), returncode=1
        )

        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch("deep_code_security.hunter.semgrep_backend.subprocess.run", return_value=proc_mock),
            patch(
                "deep_code_security.hunter.semgrep_backend.get_config",
                return_value=_make_mock_config(tmp_path),
            ),
        ):
            result = backend.scan_files(tmp_path, discovered, "medium")

        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# 6. is_available()
# ---------------------------------------------------------------------------


class TestIsAvailable:
    """Tests for SemgrepBackend.is_available()."""

    def test_is_available_false_when_binary_not_found(self, tmp_path: Path) -> None:
        """Returns False when shutil.which('semgrep') returns None."""
        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value=None),
            patch(
                "deep_code_security.hunter.semgrep_backend.get_config",
                return_value=_make_mock_config(tmp_path),
            ),
        ):
            assert SemgrepBackend.is_available() is False

    def test_is_available_true_when_binary_found_and_rules_exist(
        self, tmp_path: Path
    ) -> None:
        """Returns True when semgrep binary found and rules directory has .yaml files."""
        rules_dir = tmp_path / "semgrep"
        rules_dir.mkdir()
        (rules_dir / "test.yaml").write_text("rules: []")

        mock_cfg = _make_mock_config(tmp_path, rules_path=rules_dir)

        # _check_version uses text=True, so stdout must be a str (not bytes).
        version_proc = MagicMock()
        version_proc.stdout = "1.78.0"
        version_proc.stderr = ""
        version_proc.returncode = 0

        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch("deep_code_security.hunter.semgrep_backend.subprocess.run", return_value=version_proc),
            patch("deep_code_security.hunter.semgrep_backend.get_config", return_value=mock_cfg),
        ):
            assert SemgrepBackend.is_available() is True

    def test_is_available_false_when_rules_dir_missing(self, tmp_path: Path) -> None:
        """Returns False when the rules directory does not exist."""
        non_existent_rules = tmp_path / "missing_semgrep_rules"
        mock_cfg = _make_mock_config(tmp_path, rules_path=non_existent_rules)

        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch("deep_code_security.hunter.semgrep_backend.get_config", return_value=mock_cfg),
        ):
            assert SemgrepBackend.is_available() is False

    def test_is_available_false_when_rules_dir_empty(self, tmp_path: Path) -> None:
        """Returns False when the rules directory exists but contains no .yaml files."""
        empty_rules = tmp_path / "empty_semgrep"
        empty_rules.mkdir()
        # No .yaml files

        mock_cfg = _make_mock_config(tmp_path, rules_path=empty_rules)

        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch("deep_code_security.hunter.semgrep_backend.get_config", return_value=mock_cfg),
        ):
            assert SemgrepBackend.is_available() is False


# ---------------------------------------------------------------------------
# 7. Malformed / missing required fields
# ---------------------------------------------------------------------------


class TestMalformedResults:
    """Tests that malformed Semgrep results are skipped gracefully."""

    def test_malformed_result_missing_cwe_is_skipped(
        self, backend: SemgrepBackend, tmp_path: Path, malformed_fixture: dict[str, Any]
    ) -> None:
        """Result missing extra.metadata.cwe is logged and skipped, no crash."""
        app_file = tmp_path / "app.py"
        app_file.touch()
        discovered = [_make_discovered_file(app_file)]

        proc_mock = _make_subprocess_result(
            stdout=json.dumps(malformed_fixture).encode(), returncode=1
        )

        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch("deep_code_security.hunter.semgrep_backend.subprocess.run", return_value=proc_mock),
            patch(
                "deep_code_security.hunter.semgrep_backend.get_config",
                return_value=_make_mock_config(tmp_path),
            ),
        ):
            result = backend.scan_files(tmp_path, discovered, "medium")

        # Must not crash and must return an empty findings list
        assert isinstance(result, BackendResult)
        assert result.findings == []

    def test_normalize_result_returns_none_for_missing_check_id(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        """_normalize_result returns None if check_id is missing."""
        raw = {
            "path": "app.py",
            "start": {"line": 1, "col": 0},
            "end": {"line": 1, "col": 10},
            "extra": {
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-89: SQL Injection"]},
                "metavars": {},
            },
        }
        assert backend._normalize_result(raw, tmp_path) is None

    def test_normalize_result_returns_none_for_empty_cwe_list(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        """_normalize_result returns None if cwe list is empty."""
        raw = {
            "check_id": "test.rule",
            "path": "app.py",
            "start": {"line": 1, "col": 0},
            "end": {"line": 1, "col": 10},
            "extra": {
                "severity": "ERROR",
                "metadata": {"cwe": []},
                "metavars": {},
            },
        }
        assert backend._normalize_result(raw, tmp_path) is None


# ---------------------------------------------------------------------------
# 8. Severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    """Tests for Semgrep severity -> DCS severity mapping."""

    def _make_result_with_severity(
        self,
        semgrep_severity: str,
        dcs_severity: str | None = None,
    ) -> dict[str, Any]:
        meta: dict[str, Any] = {
            "cwe": ["CWE-78: OS Command Injection"],
            "source_category": "web_input",
            "source_function": "request.args",
            "sink_category": "command_injection",
            "sink_function": "os.system",
        }
        if dcs_severity is not None:
            meta["dcs_severity"] = dcs_severity
        return {
            "check_id": "test.rule",
            "path": "app.py",
            "start": {"line": 5, "col": 0},
            "end": {"line": 5, "col": 20},
            "extra": {
                "severity": semgrep_severity,
                "metadata": meta,
                "metavars": {},
            },
        }

    def test_error_maps_to_critical(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        raw = self._make_result_with_severity("ERROR")
        finding = backend._normalize_result(raw, tmp_path)
        assert finding is not None
        assert finding.severity == "critical"

    def test_warning_maps_to_high(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        raw = self._make_result_with_severity("WARNING")
        finding = backend._normalize_result(raw, tmp_path)
        assert finding is not None
        assert finding.severity == "high"

    def test_info_maps_to_medium(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        raw = self._make_result_with_severity("INFO")
        finding = backend._normalize_result(raw, tmp_path)
        assert finding is not None
        assert finding.severity == "medium"

    def test_dcs_severity_overrides_semgrep_severity(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        """When dcs_severity is in metadata, it takes precedence."""
        raw = self._make_result_with_severity("WARNING", dcs_severity="critical")
        finding = backend._normalize_result(raw, tmp_path)
        assert finding is not None
        assert finding.severity == "critical"

    def test_dcs_severity_low_override(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        """dcs_severity='low' overrides ERROR."""
        raw = self._make_result_with_severity("ERROR", dcs_severity="low")
        finding = backend._normalize_result(raw, tmp_path)
        assert finding is not None
        assert finding.severity == "low"


# ---------------------------------------------------------------------------
# 9. input_validator compatibility
# ---------------------------------------------------------------------------


class TestInputValidatorCompatibility:
    """Verifies that SemgrepBackend findings pass input_validator checks."""

    def test_raw_finding_passes_input_validator(
        self, backend: SemgrepBackend, tmp_path: Path, cwe89_fixture: dict[str, Any]
    ) -> None:
        """A normalised RawFinding must pass validate_raw_finding without error."""
        raw_result = cwe89_fixture["results"][0]
        # Resolve the path so the file appears to exist under tmp_path
        app_file = tmp_path / "app.py"
        app_file.touch()

        finding = backend._normalize_result(raw_result, tmp_path)
        assert finding is not None

        # This must not raise InputValidationError
        validated = validate_raw_finding(finding)
        assert isinstance(validated, RawFinding)

    def test_cwe78_finding_passes_input_validator(
        self, backend: SemgrepBackend, tmp_path: Path, cwe78_fixture: dict[str, Any]
    ) -> None:
        """CWE-78 normalised finding also passes validate_raw_finding."""
        raw_result = cwe78_fixture["results"][0]
        runner_file = tmp_path / "runner.py"
        runner_file.touch()

        finding = backend._normalize_result(raw_result, tmp_path)
        assert finding is not None

        validated = validate_raw_finding(finding)
        assert isinstance(validated, RawFinding)


# ---------------------------------------------------------------------------
# 10. Coverage gap: private helpers and scan_files branches
# ---------------------------------------------------------------------------


class TestPrivateHelpers:
    """Branch coverage for module-level private helpers."""

    def test_parse_semgrep_version_invalid_returns_none(self) -> None:
        """_parse_semgrep_version returns None when parts cannot be converted to int."""
        from deep_code_security.hunter.semgrep_backend import _parse_semgrep_version

        assert _parse_semgrep_version("not.a.version") is None
        assert _parse_semgrep_version("1.x.0") is None

    def test_check_version_unparseable_output(self) -> None:
        """_check_version warns and returns raw string when version cannot be parsed."""
        from deep_code_security.hunter.semgrep_backend import _check_version

        proc = MagicMock()
        proc.stdout = "garbage output"
        proc.returncode = 0
        with patch("deep_code_security.hunter.semgrep_backend.subprocess.run", return_value=proc):
            result = _check_version("/usr/bin/semgrep")
        # Returns raw string (non-empty) when version is unparseable
        assert result == "garbage output"

    def test_check_version_out_of_range_warns(self) -> None:
        """_check_version logs a warning when the version is outside [1.50.0, 2.0.0)."""
        from deep_code_security.hunter.semgrep_backend import _check_version

        proc = MagicMock()
        proc.stdout = "0.80.0"  # below _MIN_VERSION
        proc.returncode = 0
        with patch("deep_code_security.hunter.semgrep_backend.subprocess.run", return_value=proc):
            result = _check_version("/usr/bin/semgrep")
        assert result == "0.80.0"

    def test_check_version_oserror_returns_none(self) -> None:
        """_check_version returns None when subprocess raises OSError."""
        from deep_code_security.hunter.semgrep_backend import _check_version

        with patch(
            "deep_code_security.hunter.semgrep_backend.subprocess.run",
            side_effect=OSError("binary not found"),
        ):
            result = _check_version("/usr/bin/semgrep")
        assert result is None

    def test_extract_cwe_id_fallback(self) -> None:
        """_extract_cwe_id returns the stripped input when no CWE-xxx pattern matches."""
        from deep_code_security.hunter.semgrep_backend import _extract_cwe_id

        assert _extract_cwe_id("  no-match  ") == "no-match"
        assert _extract_cwe_id("CWE-89: SQL Injection") == "CWE-89"

    def test_detect_language_from_path_variants(self) -> None:
        """_detect_language_from_path covers all supported extensions."""
        from deep_code_security.hunter.semgrep_backend import _detect_language_from_path

        assert _detect_language_from_path(Path("a.go")) == "go"
        assert _detect_language_from_path(Path("a.c")) == "c"
        assert _detect_language_from_path(Path("a.h")) == "c"
        assert _detect_language_from_path(Path("a.cpp")) == "cpp"
        assert _detect_language_from_path(Path("a.cc")) == "cpp"
        assert _detect_language_from_path(Path("a.hpp")) == "cpp"
        assert _detect_language_from_path(Path("a.js")) == "javascript"
        assert _detect_language_from_path(Path("a.mjs")) == "javascript"
        assert _detect_language_from_path(Path("a.ts")) == "typescript"
        assert _detect_language_from_path(Path("a.tsx")) == "typescript"
        assert _detect_language_from_path(Path("a.java")) == "java"
        assert _detect_language_from_path(Path("a.rb")) == "ruby"
        assert _detect_language_from_path(Path("a.php")) == "php"
        assert _detect_language_from_path(Path("a.xyz")) == "unknown"

    def test_version_property_returns_none_when_not_cached(
        self, backend: SemgrepBackend
    ) -> None:
        """backend.version returns None when _cached_version is empty/None."""
        SemgrepBackend._cached_version = None
        assert backend.version is None
        SemgrepBackend._cached_version = ""
        assert backend.version is None


class TestScanFilesBranches:
    """Branch coverage for scan_files() code paths not hit by the main tests."""

    def test_scan_files_returns_empty_when_binary_not_on_path(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        """scan_files returns empty BackendResult when shutil.which returns None."""
        app = tmp_path / "app.py"
        app.touch()
        discovered = [_make_discovered_file(app)]

        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value=None),
            patch(
                "deep_code_security.hunter.semgrep_backend.get_config",
                return_value=_make_mock_config(tmp_path),
            ),
        ):
            result = backend.scan_files(tmp_path, discovered, "medium")

        assert result.findings == []
        assert any("not found" in d.lower() for d in result.diagnostics)

    def test_scan_files_returns_empty_on_oserror(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        """scan_files returns empty BackendResult when subprocess raises OSError."""
        app = tmp_path / "app.py"
        app.touch()
        discovered = [_make_discovered_file(app)]

        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch(
                "deep_code_security.hunter.semgrep_backend.subprocess.run",
                side_effect=OSError("exec error"),
            ),
            patch(
                "deep_code_security.hunter.semgrep_backend.get_config",
                return_value=_make_mock_config(tmp_path),
            ),
        ):
            result = backend.scan_files(tmp_path, discovered, "medium")

        assert result.findings == []
        assert any("Failed to launch" in d for d in result.diagnostics)

    def test_scan_files_logs_stderr_on_success(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        """scan_files handles non-empty stderr without failing when exit code is OK."""
        app = tmp_path / "app.py"
        app.touch()
        discovered = [_make_discovered_file(app)]

        proc = _make_subprocess_result(
            stdout=b'{"results": [], "errors": []}',
            returncode=0,
            stderr=b"Some semgrep warning output",
        )
        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch("deep_code_security.hunter.semgrep_backend.subprocess.run", return_value=proc),
            patch(
                "deep_code_security.hunter.semgrep_backend.get_config",
                return_value=_make_mock_config(tmp_path),
            ),
        ):
            result = backend.scan_files(tmp_path, discovered, "medium")

        assert isinstance(result, BackendResult)
        assert result.findings == []

    def test_scan_files_skips_result_with_empty_path(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        """scan_files silently skips results where the path field is empty."""
        app = tmp_path / "app.py"
        app.touch()
        discovered = [_make_discovered_file(app)]

        data = {
            "results": [
                {
                    "check_id": "test.rule",
                    "path": "",  # empty path — must be skipped
                    "start": {"line": 1, "col": 0},
                    "end": {"line": 1, "col": 5},
                    "extra": {
                        "severity": "ERROR",
                        "metadata": {
                            "cwe": ["CWE-89: SQL Injection"],
                            "source_category": "web_input",
                            "source_function": "request.form",
                            "sink_category": "sql_injection",
                            "sink_function": "cursor.execute",
                        },
                        "metavars": {},
                    },
                }
            ],
            "errors": [],
        }
        proc = _make_subprocess_result(stdout=json.dumps(data).encode(), returncode=1)
        with (
            patch("deep_code_security.hunter.semgrep_backend.shutil.which", return_value="/usr/bin/semgrep"),
            patch("deep_code_security.hunter.semgrep_backend.subprocess.run", return_value=proc),
            patch(
                "deep_code_security.hunter.semgrep_backend.get_config",
                return_value=_make_mock_config(tmp_path),
            ),
        ):
            result = backend.scan_files(tmp_path, discovered, "medium")

        assert result.findings == []

    def test_normalize_result_returns_none_for_missing_path(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        """_normalize_result returns None when path key is missing."""
        raw = {
            "check_id": "test.rule",
            # no "path" key
            "start": {"line": 1, "col": 0},
            "extra": {
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-89: SQL Injection"]},
                "metavars": {},
            },
        }
        assert backend._normalize_result(raw, tmp_path) is None

    def test_normalize_result_returns_none_for_missing_start(
        self, backend: SemgrepBackend, tmp_path: Path
    ) -> None:
        """_normalize_result returns None when start key is missing."""
        raw = {
            "check_id": "test.rule",
            "path": "app.py",
            # no "start" key
            "extra": {
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-89: SQL Injection"]},
                "metavars": {},
            },
        }
        assert backend._normalize_result(raw, tmp_path) is None


# ---------------------------------------------------------------------------
# Helper: lightweight mock config
# ---------------------------------------------------------------------------


def _make_mock_config(
    tmp_path: Path,
    rules_path: Path | None = None,
    timeout: int = 120,
) -> MagicMock:
    """Return a mock Config with the minimum fields SemgrepBackend needs."""
    mock_cfg = MagicMock()
    mock_cfg.semgrep_timeout = timeout
    if rules_path is not None:
        mock_cfg.semgrep_rules_path = rules_path
    else:
        # Default: a non-existent path (most tests mock shutil.which anyway)
        mock_cfg.semgrep_rules_path = tmp_path / "registries" / "semgrep"
    return mock_cfg
