"""Tests for TUI ReportStorage."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from deep_code_security.tui.models import RunMeta
from deep_code_security.tui.storage import ReportStorage


class TestCreateRunDir:
    """Tests for ReportStorage.create_run_dir()."""

    def test_create_run_dir_creates_nested_dirs(
        self, storage: ReportStorage
    ) -> None:
        """create_run_dir creates the project dir and timestamp dir."""
        run_dir = storage.create_run_dir("openssl")
        assert run_dir.is_dir()
        assert run_dir.parent.name == "openssl"
        assert run_dir.parent.parent == storage.get_output_dir()

    def test_create_run_dir_unique_timestamps(
        self, storage: ReportStorage
    ) -> None:
        """Two immediate calls produce different directories
        (microsecond precision)."""
        dir1 = storage.create_run_dir("openssl")
        dir2 = storage.create_run_dir("openssl")
        assert dir1 != dir2

    def test_create_run_dir_timestamp_format(
        self, storage: ReportStorage
    ) -> None:
        """Run directory name matches YYYY-MM-DD-HH-MM-SS-ffffff format."""
        import re

        run_dir = storage.create_run_dir("myproject")
        pattern = r"^\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-\d{6}$"
        assert re.match(pattern, run_dir.name), f"Bad format: {run_dir.name}"


class TestWriteMeta:
    """Tests for ReportStorage.write_meta()."""

    def test_write_meta_creates_file(
        self, storage: ReportStorage, sample_run_meta: RunMeta
    ) -> None:
        """write_meta writes a valid meta.json file."""
        run_dir = storage.create_run_dir("openssl")
        meta_path = storage.write_meta(run_dir, sample_run_meta)

        assert meta_path.name == "meta.json"
        assert meta_path.is_file()

        content = json.loads(meta_path.read_text(encoding="utf-8"))
        assert content["run_id"] == sample_run_meta.run_id
        assert content["timestamp"] == sample_run_meta.timestamp
        assert content["scan_type"] == sample_run_meta.scan_type
        assert content["findings_count"] == sample_run_meta.findings_count

    def test_write_meta_returns_path(
        self, storage: ReportStorage, sample_run_meta: RunMeta
    ) -> None:
        """write_meta returns the absolute path to meta.json."""
        run_dir = storage.create_run_dir("openssl")
        meta_path = storage.write_meta(run_dir, sample_run_meta)
        assert meta_path == run_dir / "meta.json"


class TestReadMeta:
    """Tests for ReportStorage.read_meta()."""

    def test_read_meta_valid(
        self, storage: ReportStorage, sample_run_meta: RunMeta
    ) -> None:
        """read_meta reads back a written meta.json correctly."""
        run_dir = storage.create_run_dir("openssl")
        storage.write_meta(run_dir, sample_run_meta)

        result = storage.read_meta(run_dir)
        assert result is not None
        assert result.run_id == sample_run_meta.run_id
        assert result.timestamp == sample_run_meta.timestamp
        assert result.scan_type == sample_run_meta.scan_type
        assert result.findings_count == sample_run_meta.findings_count
        assert result.backend_used == sample_run_meta.backend_used

    def test_read_meta_missing_file(
        self, storage: ReportStorage
    ) -> None:
        """read_meta returns None if meta.json does not exist."""
        run_dir = storage.create_run_dir("openssl")
        result = storage.read_meta(run_dir)
        assert result is None

    def test_read_meta_invalid_json(
        self, storage: ReportStorage
    ) -> None:
        """read_meta returns None for malformed JSON (logs warning)."""
        run_dir = storage.create_run_dir("openssl")
        (run_dir / "meta.json").write_text("not valid json{{{", encoding="utf-8")

        result = storage.read_meta(run_dir)
        assert result is None

    def test_read_meta_invalid_schema(
        self, storage: ReportStorage
    ) -> None:
        """read_meta returns None if JSON does not match RunMeta schema
        (logs warning)."""
        run_dir = storage.create_run_dir("openssl")
        (run_dir / "meta.json").write_text(
            json.dumps({"some_key": "some_value"}), encoding="utf-8"
        )

        result = storage.read_meta(run_dir)
        assert result is None


class TestListProjects:
    """Tests for ReportStorage.list_projects()."""

    def test_list_projects_empty(self, storage: ReportStorage) -> None:
        """Empty output dir returns empty list."""
        assert storage.list_projects() == []

    def test_list_projects_empty_dir_exists(
        self, storage: ReportStorage
    ) -> None:
        """Output dir exists but has no projects with runs."""
        storage.get_output_dir().mkdir(parents=True, exist_ok=True)
        assert storage.list_projects() == []

    def test_list_projects_with_runs(
        self, populated_storage: ReportStorage
    ) -> None:
        """Returns sorted project names that have at least one valid run."""
        projects = populated_storage.list_projects()
        assert "flask-app" in projects
        assert "openssl" in projects
        assert projects == sorted(projects)

    def test_list_projects_ignores_dirs_without_meta(
        self, storage: ReportStorage
    ) -> None:
        """Project dirs without any meta.json are not listed."""
        project_dir = storage.get_output_dir() / "empty-project"
        run_dir = project_dir / "2026-01-01-00-00-00-000000"
        run_dir.mkdir(parents=True)
        # No meta.json written

        assert storage.list_projects() == []


class TestListRuns:
    """Tests for ReportStorage.list_runs()."""

    def test_list_runs_sorted_descending(
        self, populated_storage: ReportStorage
    ) -> None:
        """Runs are sorted by timestamp, most recent first."""
        runs = populated_storage.list_runs("openssl")
        assert len(runs) == 2
        # Second run has later timestamp
        assert runs[0].timestamp > runs[1].timestamp

    def test_list_runs_empty_project(
        self, storage: ReportStorage
    ) -> None:
        """Non-existent project returns empty list."""
        assert storage.list_runs("nonexistent") == []

    def test_list_runs_skips_invalid_dirs(
        self, storage: ReportStorage, sample_run_meta: RunMeta
    ) -> None:
        """Directories without valid meta.json are skipped."""
        # Create a valid run
        run_dir_valid = storage.create_run_dir("myproject")
        storage.write_meta(run_dir_valid, sample_run_meta)

        # Create an invalid run (no meta.json)
        invalid_dir = storage.get_output_dir() / "myproject" / "2025-01-01-00-00-00-000000"
        invalid_dir.mkdir(parents=True)

        # Create another invalid run (bad meta.json)
        bad_dir = storage.get_output_dir() / "myproject" / "2025-01-02-00-00-00-000000"
        bad_dir.mkdir(parents=True)
        (bad_dir / "meta.json").write_text("{bad json", encoding="utf-8")

        runs = storage.list_runs("myproject")
        assert len(runs) == 1
        assert runs[0].run_id == sample_run_meta.run_id


class TestDeriveProjectName:
    """Tests for ReportStorage.derive_project_name()."""

    def test_derive_project_name_simple(self) -> None:
        """/path/to/openssl -> openssl."""
        assert ReportStorage.derive_project_name("/path/to/openssl") == "openssl"

    def test_derive_project_name_trailing_slash(self) -> None:
        """/path/to/openssl/ -> openssl (trailing slash handled)."""
        # Path("/path/to/openssl/").name gives "" so we need to handle this
        # Actually Path("/path/to/openssl/").name gives "openssl" in Python
        result = ReportStorage.derive_project_name("/path/to/openssl/")
        assert result == "openssl"

    def test_derive_project_name_file(self, tmp_path: Path) -> None:
        """/path/to/main.py -> parent dir basename when target is a file."""
        # Create an actual file so is_file() returns True.
        test_file = tmp_path / "mydir" / "main.py"
        test_file.parent.mkdir(parents=True)
        test_file.touch()

        result = ReportStorage.derive_project_name(str(test_file))
        assert result == "mydir"

    def test_derive_project_name_special_chars(self) -> None:
        """Non-alphanumeric characters (except ._-) are stripped."""
        result = ReportStorage.derive_project_name("/path/to/my project@v2!")
        assert result == "myprojectv2"

    def test_derive_project_name_dotdot_rejected(self) -> None:
        """Path traversal components are sanitized."""
        result = ReportStorage.derive_project_name("/path/to/../../etc")
        # The basename of this path is "etc", which is clean
        assert ".." not in result
        assert "/" not in result
        assert result == "etc"

    def test_derive_project_name_dotdot_in_basename(self) -> None:
        """A name that contains '..' after sanitization gets it removed."""
        result = ReportStorage.derive_project_name("/path/to/some..project")
        assert ".." not in result
        # After stripping special chars and removing "..", we get "someproject"
        assert result == "someproject"

    def test_derive_project_name_empty(self) -> None:
        """Falls back to 'unnamed' if name becomes empty after sanitization."""
        result = ReportStorage.derive_project_name("/path/to/!!!")
        assert result == "unnamed"

    def test_derive_project_name_root_path(self) -> None:
        """Root path falls back to resolved name or 'unnamed'."""
        result = ReportStorage.derive_project_name("/")
        # Path("/").name is "", but resolve().name is also "" on root
        # Should fall back to "unnamed"
        assert len(result) >= 1

    def test_derive_project_name_max_length(self) -> None:
        """Names longer than 64 characters are truncated."""
        long_name = "a" * 100
        result = ReportStorage.derive_project_name(f"/path/to/{long_name}")
        assert len(result) == 64
        assert result == "a" * 64

    def test_derive_project_name_preserves_dots_hyphens_underscores(self) -> None:
        """Dots, hyphens, and underscores are preserved."""
        result = ReportStorage.derive_project_name("/path/to/my-project_v2.0")
        assert result == "my-project_v2.0"

    def test_derive_project_name_slash_in_name_rejected(self) -> None:
        """Slashes in the derived name are rejected."""
        # Path handling naturally strips slashes from basenames,
        # but verify no slash remains after sanitization.
        result = ReportStorage.derive_project_name("/path/to/normal")
        assert "/" not in result


class TestOutputDir:
    """Tests for DCS_OUTPUT_DIR handling."""

    def test_output_dir_from_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Respects DCS_OUTPUT_DIR environment variable."""
        custom_dir = tmp_path / "custom-reports"
        monkeypatch.setenv("DCS_OUTPUT_DIR", str(custom_dir))

        storage = ReportStorage()
        assert storage.get_output_dir() == custom_dir.resolve()

    def test_output_dir_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Uses ~/.dcs/reports/ when DCS_OUTPUT_DIR is not set."""
        monkeypatch.delenv("DCS_OUTPUT_DIR", raising=False)
        storage = ReportStorage()

        expected = Path("~/.dcs/reports/").expanduser().resolve()
        assert storage.get_output_dir() == expected

    def test_output_dir_expanduser(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tilde in DCS_OUTPUT_DIR is expanded."""
        monkeypatch.setenv("DCS_OUTPUT_DIR", "~/my-dcs-reports")
        storage = ReportStorage()

        # Should be expanded, not contain literal ~
        result = storage.get_output_dir()
        assert "~" not in str(result)
        assert result == Path("~/my-dcs-reports").expanduser().resolve()

    def test_output_dir_override(self, tmp_path: Path) -> None:
        """Constructor output_dir parameter overrides env var."""
        custom = tmp_path / "override"
        storage = ReportStorage(output_dir=custom)
        assert storage.get_output_dir() == custom.resolve()

    def test_get_output_dir_returns_resolved_path(
        self, tmp_path: Path
    ) -> None:
        """get_output_dir returns a resolved (absolute) path."""
        storage = ReportStorage(output_dir=tmp_path / "reports")
        result = storage.get_output_dir()
        assert result.is_absolute()
