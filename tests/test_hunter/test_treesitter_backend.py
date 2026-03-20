"""Tests for the TreeSitterBackend scanner backend adapter.

Covers:
- ``is_available()`` always returns True
- ``name`` attribute is ``"treesitter"``
- ``scan_files()`` returns a valid ``BackendResult`` instance
- ``BackendResult.backend_name`` is ``"treesitter"``
- ``BackendResult.findings`` is a list (possibly empty for safe fixtures)
- Mocked underlying module calls (isolation tests)
- Real scan on known-vulnerable Python fixtures produces at least one finding
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath, TaintStep
from deep_code_security.hunter.registry import clear_registry_cache
from deep_code_security.hunter.scanner_backend import BackendResult
from deep_code_security.hunter.treesitter_backend import TreeSitterBackend
from deep_code_security.shared.config import reset_config
from deep_code_security.shared.file_discovery import DiscoveredFile, FileDiscovery
from deep_code_security.shared.language import Language

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------

REGISTRY_DIR = Path(__file__).parent.parent.parent / "registries"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
VULNERABLE_PYTHON = FIXTURES_DIR / "vulnerable_samples" / "python"
SAFE_PYTHON = FIXTURES_DIR / "safe_samples" / "python"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_caches():
    """Clear registry cache and config singleton around each test."""
    clear_registry_cache()
    yield
    clear_registry_cache()
    reset_config()


@pytest.fixture
def backend() -> TreeSitterBackend:
    """Return a fresh TreeSitterBackend with registry path set."""
    os.environ["DCS_REGISTRY_PATH"] = str(REGISTRY_DIR)
    reset_config()
    b = TreeSitterBackend()
    return b


@pytest.fixture
def vulnerable_python_files() -> list[DiscoveredFile]:
    """Return discovered files from the vulnerable Python fixtures directory."""
    discovery = FileDiscovery(max_files=1000)
    files, _ = discovery.discover(VULNERABLE_PYTHON, languages=[Language.PYTHON])
    return files


@pytest.fixture
def safe_python_files() -> list[DiscoveredFile]:
    """Return discovered files from the safe Python fixtures directory."""
    discovery = FileDiscovery(max_files=1000)
    files, _ = discovery.discover(SAFE_PYTHON, languages=[Language.PYTHON])
    return files


# ---------------------------------------------------------------------------
# Protocol attribute tests
# ---------------------------------------------------------------------------


class TestTreeSitterBackendProtocol:
    """Verify protocol contract attributes."""

    def test_name_is_treesitter(self) -> None:
        """The ``name`` attribute must be the string ``"treesitter"``."""
        backend = TreeSitterBackend()
        assert backend.name == "treesitter"

    def test_is_available_returns_true(self) -> None:
        """``is_available()`` must always return True.

        Tree-sitter is a core dependency; there is no optional binary to locate.
        """
        assert TreeSitterBackend.is_available() is True

    def test_is_available_returns_true_on_instance(self) -> None:
        """``is_available()`` works when called on an instance (classmethod)."""
        backend = TreeSitterBackend()
        assert type(backend).is_available() is True


# ---------------------------------------------------------------------------
# BackendResult shape tests
# ---------------------------------------------------------------------------


class TestBackendResultShape:
    """Verify that scan_files() always returns a well-formed BackendResult."""

    def test_scan_files_returns_backend_result(
        self, backend: TreeSitterBackend, vulnerable_python_files: list[DiscoveredFile]
    ) -> None:
        """``scan_files()`` must return a ``BackendResult`` instance."""
        result = backend.scan_files(
            target_path=VULNERABLE_PYTHON,
            discovered_files=vulnerable_python_files,
            severity_threshold="medium",
        )
        assert isinstance(result, BackendResult)

    def test_backend_name_in_result(
        self, backend: TreeSitterBackend, vulnerable_python_files: list[DiscoveredFile]
    ) -> None:
        """``BackendResult.backend_name`` must be ``"treesitter"``."""
        result = backend.scan_files(
            target_path=VULNERABLE_PYTHON,
            discovered_files=vulnerable_python_files,
            severity_threshold="medium",
        )
        assert result.backend_name == "treesitter"

    def test_findings_is_list(
        self, backend: TreeSitterBackend, vulnerable_python_files: list[DiscoveredFile]
    ) -> None:
        """``BackendResult.findings`` must be a list (may be empty)."""
        result = backend.scan_files(
            target_path=VULNERABLE_PYTHON,
            discovered_files=vulnerable_python_files,
            severity_threshold="medium",
        )
        assert isinstance(result.findings, list)

    def test_count_fields_are_non_negative(
        self, backend: TreeSitterBackend, vulnerable_python_files: list[DiscoveredFile]
    ) -> None:
        """Numeric count fields must be >= 0."""
        result = backend.scan_files(
            target_path=VULNERABLE_PYTHON,
            discovered_files=vulnerable_python_files,
            severity_threshold="medium",
        )
        assert result.sources_found >= 0
        assert result.sinks_found >= 0
        assert result.taint_paths_found >= 0

    def test_diagnostics_is_list(
        self, backend: TreeSitterBackend, vulnerable_python_files: list[DiscoveredFile]
    ) -> None:
        """``BackendResult.diagnostics`` must be a list."""
        result = backend.scan_files(
            target_path=VULNERABLE_PYTHON,
            discovered_files=vulnerable_python_files,
            severity_threshold="medium",
        )
        assert isinstance(result.diagnostics, list)

    def test_empty_discovered_files_returns_empty_result(
        self, backend: TreeSitterBackend
    ) -> None:
        """An empty ``discovered_files`` list produces a BackendResult with no findings."""
        result = backend.scan_files(
            target_path=VULNERABLE_PYTHON,
            discovered_files=[],
            severity_threshold="medium",
        )
        assert isinstance(result, BackendResult)
        assert result.backend_name == "treesitter"
        assert result.findings == []
        assert result.sources_found == 0
        assert result.sinks_found == 0
        assert result.taint_paths_found == 0


# ---------------------------------------------------------------------------
# Real-scan detection test
# ---------------------------------------------------------------------------


class TestRealScan:
    """Verify that the backend detects known-vulnerable fixtures."""

    def test_vulnerable_python_produces_findings(
        self, backend: TreeSitterBackend, vulnerable_python_files: list[DiscoveredFile]
    ) -> None:
        """Scanning the vulnerable Python fixtures must return at least one finding.

        The fixtures in ``tests/fixtures/vulnerable_samples/python/`` contain
        deliberately introduced SQL injection, command injection, and code
        injection vulnerabilities.  The tree-sitter backend must detect at
        least one of them.
        """
        result = backend.scan_files(
            target_path=VULNERABLE_PYTHON,
            discovered_files=vulnerable_python_files,
            severity_threshold="low",
        )
        assert len(result.findings) > 0, (
            "Expected at least one finding from vulnerable Python fixtures, got none. "
            f"Diagnostics: {result.diagnostics}"
        )

    def test_findings_are_raw_finding_instances(
        self, backend: TreeSitterBackend, vulnerable_python_files: list[DiscoveredFile]
    ) -> None:
        """All entries in ``findings`` must be ``RawFinding`` instances."""
        result = backend.scan_files(
            target_path=VULNERABLE_PYTHON,
            discovered_files=vulnerable_python_files,
            severity_threshold="low",
        )
        for finding in result.findings:
            assert isinstance(finding, RawFinding), (
                f"Expected RawFinding, got {type(finding)}"
            )

    def test_findings_have_valid_severity(
        self, backend: TreeSitterBackend, vulnerable_python_files: list[DiscoveredFile]
    ) -> None:
        """Every finding must have a recognized severity level."""
        valid_severities = {"critical", "high", "medium", "low"}
        result = backend.scan_files(
            target_path=VULNERABLE_PYTHON,
            discovered_files=vulnerable_python_files,
            severity_threshold="low",
        )
        for finding in result.findings:
            assert finding.severity in valid_severities, (
                f"Unexpected severity {finding.severity!r} in finding {finding.id}"
            )

    def test_safe_python_produces_fewer_findings_than_vulnerable(
        self, backend: TreeSitterBackend
    ) -> None:
        """The safe fixtures should produce fewer findings than the vulnerable ones.

        This is a sanity check that the backend is actually sensitive to
        the presence of vulnerability patterns.  We use ``severity_threshold="low"``
        so both scans are as inclusive as possible.
        """
        discovery = FileDiscovery(max_files=1000)

        vuln_files, _ = discovery.discover(VULNERABLE_PYTHON, languages=[Language.PYTHON])
        safe_files, _ = discovery.discover(SAFE_PYTHON, languages=[Language.PYTHON])

        vuln_result = backend.scan_files(
            target_path=VULNERABLE_PYTHON,
            discovered_files=vuln_files,
            severity_threshold="low",
        )
        safe_result = backend.scan_files(
            target_path=SAFE_PYTHON,
            discovered_files=safe_files,
            severity_threshold="low",
        )

        assert len(vuln_result.findings) > len(safe_result.findings), (
            f"Expected more findings in vulnerable ({len(vuln_result.findings)}) "
            f"than safe ({len(safe_result.findings)}) fixtures"
        )


# ---------------------------------------------------------------------------
# Isolation tests (mocked underlying modules)
# ---------------------------------------------------------------------------


class TestIsolatedWithMocks:
    """Test the adapter in isolation by mocking the pipeline modules."""

    def _make_discovered_file(self, path: Path, language: Language) -> DiscoveredFile:
        return DiscoveredFile(path=path, language=language, size_bytes=1024)

    def _make_raw_finding(self, file_path: str) -> RawFinding:
        """Construct a minimal valid RawFinding for mock returns."""
        source = Source(
            file=file_path,
            line=10,
            column=4,
            function="request.form",
            category="web_input",
            language="python",
        )
        sink = Sink(
            file=file_path,
            line=15,
            column=4,
            function="cursor.execute",
            category="sql_injection",
            cwe="CWE-89",
            language="python",
        )
        step_source = TaintStep(
            file=file_path,
            line=10,
            column=4,
            variable="user_input",
            transform="assignment",
        )
        step_sink = TaintStep(
            file=file_path,
            line=15,
            column=4,
            variable="query",
            transform="concatenation",
        )
        taint_path = TaintPath(steps=[step_source, step_sink], sanitized=False)
        return RawFinding(
            source=source,
            sink=sink,
            taint_path=taint_path,
            vulnerability_class="CWE-89: SQL Injection",
            severity="high",
            language="python",
            raw_confidence=0.6,
        )

    def test_scan_files_calls_find_sources_and_sinks(self) -> None:
        """The adapter must call find_sources and find_sinks for each discovered file.

        The taint engine pipeline (find_sources, find_sinks, TaintEngine) is
        mocked to avoid real file I/O.  The source, sink, and taint_path values
        returned by the mocked pipeline must be real Pydantic model instances so
        that ``RawFinding`` construction succeeds.
        """
        backend = TreeSitterBackend()

        fake_file = Path("/fake/app.py")
        discovered = [self._make_discovered_file(fake_file, Language.PYTHON)]

        # Use real Pydantic instances so RawFinding validation succeeds.
        real_source = Source(
            file="/fake/app.py",
            line=10,
            column=4,
            function="request.form",
            category="web_input",
            language="python",
        )
        real_sink = Sink(
            file="/fake/app.py",
            line=15,
            column=4,
            function="cursor.execute",
            category="sql_injection",
            cwe="CWE-89",
            language="python",
        )
        real_taint_path = TaintPath(
            steps=[
                TaintStep(
                    file="/fake/app.py",
                    line=10,
                    column=4,
                    variable="user_input",
                    transform="assignment",
                ),
                TaintStep(
                    file="/fake/app.py",
                    line=15,
                    column=4,
                    variable="query",
                    transform="concatenation",
                ),
            ],
            sanitized=False,
        )

        mock_registry = MagicMock()
        mock_registry.registry_hash = "abc123"
        mock_registry.sinks = {
            "sql_injection": [MagicMock(severity="high", cwe="CWE-89")]
        }

        with (
            patch.object(backend, "_get_registry", return_value=mock_registry),
            patch.object(backend._parser, "parse_file", return_value=MagicMock()),
            patch.object(backend._parser, "get_language_object", return_value=MagicMock()),
            patch(
                "deep_code_security.hunter.treesitter_backend.find_sources",
                return_value=[real_source],
            ) as mock_find_sources,
            patch(
                "deep_code_security.hunter.treesitter_backend.find_sinks",
                return_value=[real_sink],
            ) as mock_find_sinks,
            patch(
                "deep_code_security.hunter.treesitter_backend.TaintEngine"
            ) as MockTaintEngine,
        ):
            mock_engine = MockTaintEngine.return_value
            mock_engine.find_taint_paths.return_value = [
                (real_source, real_sink, real_taint_path)
            ]

            result = backend.scan_files(
                target_path=Path("/fake"),
                discovered_files=discovered,
                severity_threshold="medium",
            )

        mock_find_sources.assert_called_once()
        mock_find_sinks.assert_called_once()
        assert isinstance(result, BackendResult)
        assert result.backend_name == "treesitter"
        assert result.sources_found == 1
        assert result.sinks_found == 1
        assert result.taint_paths_found == 1
        assert len(result.findings) == 1
        assert result.findings[0].vulnerability_class == "CWE-89: SQL Injection"

    def test_parse_error_adds_diagnostic_and_skips_file(self) -> None:
        """A ``ParseError`` during file parsing must be recorded in diagnostics."""
        from deep_code_security.hunter.parser import ParseError

        backend = TreeSitterBackend()

        fake_file = Path("/fake/broken.py")
        discovered = [self._make_discovered_file(fake_file, Language.PYTHON)]

        mock_registry = MagicMock()
        mock_registry.registry_hash = "def456"
        mock_registry.sinks = {}

        with (
            patch.object(backend, "_get_registry", return_value=mock_registry),
            patch.object(
                backend._parser,
                "parse_file",
                side_effect=ParseError("syntax error"),
            ),
            patch.object(backend._parser, "get_language_object", return_value=MagicMock()),
        ):
            result = backend.scan_files(
                target_path=Path("/fake"),
                discovered_files=discovered,
                severity_threshold="medium",
            )

        assert isinstance(result, BackendResult)
        assert result.findings == []
        assert len(result.diagnostics) == 1
        assert "broken.py" in result.diagnostics[0]

    def test_no_registry_skips_file_silently(self) -> None:
        """When no registry exists for a language, the file is skipped without error."""
        backend = TreeSitterBackend()

        fake_file = Path("/fake/app.go")
        discovered = [self._make_discovered_file(fake_file, Language.GO)]

        with patch.object(backend, "_get_registry", return_value=None):
            result = backend.scan_files(
                target_path=Path("/fake"),
                discovered_files=discovered,
                severity_threshold="medium",
            )

        assert isinstance(result, BackendResult)
        assert result.findings == []
        assert result.diagnostics == []

    def test_severity_threshold_filters_findings(self) -> None:
        """Findings below the threshold must be excluded from the result."""
        backend = TreeSitterBackend()

        fake_file = Path("/fake/app.py")
        discovered = [self._make_discovered_file(fake_file, Language.PYTHON)]

        mock_source = MagicMock()
        mock_sink = MagicMock()
        mock_sink.category = "some_low_risk_sink"
        mock_sink.cwe = "CWE-22"

        mock_taint_path = MagicMock()
        mock_taint_path.sanitized = False
        mock_taint_path.steps = [MagicMock(), MagicMock()]

        # Registry reports "low" severity for the sink
        mock_registry = MagicMock()
        mock_registry.registry_hash = "fed789"
        mock_registry.sinks = {
            "some_low_risk_sink": [MagicMock(severity="low")]
        }

        with (
            patch.object(backend, "_get_registry", return_value=mock_registry),
            patch.object(backend._parser, "parse_file", return_value=MagicMock()),
            patch.object(backend._parser, "get_language_object", return_value=MagicMock()),
            patch(
                "deep_code_security.hunter.treesitter_backend.find_sources",
                return_value=[mock_source],
            ),
            patch(
                "deep_code_security.hunter.treesitter_backend.find_sinks",
                return_value=[mock_sink],
            ),
            patch(
                "deep_code_security.hunter.treesitter_backend.TaintEngine"
            ) as MockTaintEngine,
        ):
            mock_engine = MockTaintEngine.return_value
            mock_engine.find_taint_paths.return_value = [(mock_source, mock_sink, mock_taint_path)]

            # Ask for "high" threshold — the "low"-severity finding should be excluded
            result = backend.scan_files(
                target_path=Path("/fake"),
                discovered_files=discovered,
                severity_threshold="high",
            )

        assert result.findings == []
        assert result.taint_paths_found == 1  # path was found but filtered out
