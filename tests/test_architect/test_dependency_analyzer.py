"""Tests for dependency analyzer."""

from __future__ import annotations

from pathlib import Path

from deep_code_security.architect.dependency_analyzer import DependencyAnalyzer
from deep_code_security.auditor.models import VerifiedFinding
from deep_code_security.hunter.models import RawFinding, Sink, Source, TaintPath


def make_verified_finding(language: str, cwe: str) -> VerifiedFinding:
    source = Source(
        file="/test.py", line=5, column=0,
        function="request.form", category="web_input", language=language
    )
    sink = Sink(
        file="/test.py", line=10, column=0,
        function="cursor.execute", category="sql_injection",
        cwe=cwe, language=language
    )
    raw = RawFinding(
        source=source, sink=sink,
        taint_path=TaintPath(steps=[]),
        vulnerability_class=f"{cwe}: Test",
        severity="critical",
        language=language,
        raw_confidence=0.7,
    )
    return VerifiedFinding(
        finding=raw, exploit_results=[],
        confidence_score=70, verification_status="likely",
    )


class TestDependencyAnalyzer:
    """Tests for DependencyAnalyzer."""

    def test_parse_requirements_txt(self, tmp_path: Path) -> None:
        """Parses requirements.txt correctly."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\npsycopg2-binary==2.9.1\n# comment\n", encoding="utf-8")
        analyzer = DependencyAnalyzer()
        deps = analyzer._parse_requirements_txt(req.read_text())
        assert "flask>=2.0" in deps
        assert "psycopg2-binary==2.9.1" in deps

    def test_parse_pyproject_toml(self, tmp_path: Path) -> None:
        """Parses pyproject.toml dependencies section."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\nname = "test"\n[project.dependencies]\ndependencies = [\n"flask>=2.0",\n"pydantic>=2.0"\n]\n',
            encoding="utf-8",
        )
        analyzer = DependencyAnalyzer()
        deps = analyzer._parse_pyproject_toml(pyproject.read_text())
        assert isinstance(deps, list)

    def test_parse_go_mod(self, tmp_path: Path) -> None:
        """Parses go.mod require section."""
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            "module myapp\n\ngo 1.22\n\nrequire (\n    github.com/gin-gonic/gin v1.9.0\n    github.com/lib/pq v1.10.9\n)\n",
            encoding="utf-8",
        )
        analyzer = DependencyAnalyzer()
        deps = analyzer._parse_go_mod(go_mod.read_text())
        assert any("gin" in d for d in deps)
        assert any("pq" in d for d in deps)

    def test_analyze_python_project(self, tmp_path: Path) -> None:
        """Analyze returns DependencyImpact for Python project."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\npsycopg2-binary==2.9.1\n", encoding="utf-8")
        analyzer = DependencyAnalyzer()
        vf = make_verified_finding("python", "CWE-89")
        result = analyzer.analyze(tmp_path, vf)
        assert result is not None
        assert "requirements.txt" in result.manifest_file
        assert result.breaking_risk in ("none", "minor", "major")

    def test_analyze_go_project(self, tmp_path: Path) -> None:
        """Analyze returns DependencyImpact for Go project."""
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            "module myapp\n\ngo 1.22\n\nrequire (\n    github.com/gin-gonic/gin v1.9.0\n)\n",
            encoding="utf-8",
        )
        analyzer = DependencyAnalyzer()
        vf = make_verified_finding("go", "CWE-78")
        result = analyzer.analyze(tmp_path, vf)
        assert result is not None
        assert "go.mod" in result.manifest_file

    def test_analyze_no_manifest(self, tmp_path: Path) -> None:
        """Analyze returns None when no manifest file exists."""
        analyzer = DependencyAnalyzer()
        vf = make_verified_finding("python", "CWE-89")
        result = analyzer.analyze(tmp_path, vf)
        assert result is None
