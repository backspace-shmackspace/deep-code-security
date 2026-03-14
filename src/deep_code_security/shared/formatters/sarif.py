"""SARIF 2.1.0 formatter — produces conformant SARIF JSON for DefectDojo and other tools."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from deep_code_security.shared.formatters.protocol import FullScanResult, HuntResult

__all__ = ["SarifFormatter"]

# SARIF severity mapping
_SEVERITY_MAP: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

_TOOL_NAME = "deep-code-security"


def _get_tool_version() -> str:
    """Get tool version from package metadata."""
    try:
        from deep_code_security import __version__

        return __version__
    except (ImportError, AttributeError):
        return "1.0.0"


def _extract_cwe_id(vulnerability_class: str, cwe_field: str = "") -> str:
    """Extract CWE ID from vulnerability class or cwe field."""
    for text in (vulnerability_class, cwe_field):
        match = re.search(r"CWE-\d+", text)
        if match:
            return match.group(0)
    return "CWE-unknown"


def _make_relative_uri(file_path: str, target_path: str) -> str:
    """Make a file path relative to target path for SARIF URI."""
    if not target_path:
        return file_path
    try:
        fp = Path(file_path)
        tp = Path(target_path)
        rel = fp.relative_to(tp)
        return str(PurePosixPath(rel))
    except ValueError:
        # File is not under target_path — return as-is
        return file_path


def _build_rules(findings: list[Any]) -> list[dict[str, Any]]:
    """Build tool.driver.rules[] from unique vulnerability classes."""
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        cwe_id = _extract_cwe_id(f.vulnerability_class, f.sink.cwe)
        if cwe_id in seen:
            continue

        short_desc = re.sub(r"^CWE-\d+:\s*", "", f.vulnerability_class)
        if not short_desc:
            short_desc = f.vulnerability_class

        seen[cwe_id] = {
            "id": cwe_id,
            "shortDescription": {"text": short_desc},
            "fullDescription": {
                "text": f"Potential {short_desc} vulnerability detected via taint analysis."
            },
            "defaultConfiguration": {
                "level": _SEVERITY_MAP.get(f.severity, "warning"),
            },
            "properties": {
                "tags": [cwe_id],
            },
        }

    return list(seen.values())


def _build_result(
    finding: Any,
    target_path: str,
    verified: Any | None = None,
    guidance_item: Any | None = None,
) -> dict[str, Any]:
    """Build a single SARIF result from a finding."""
    cwe_id = _extract_cwe_id(finding.vulnerability_class, finding.sink.cwe)
    level = _SEVERITY_MAP.get(finding.severity, "warning")

    result: dict[str, Any] = {
        "ruleId": cwe_id,
        "level": level,
        "message": {
            "text": finding.vulnerability_class,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _make_relative_uri(finding.sink.file, target_path),
                        "uriBaseId": "SRCROOT",
                    },
                    "region": {
                        "startLine": finding.sink.line,
                        "startColumn": finding.sink.column + 1,
                    },
                },
            }
        ],
        "relatedLocations": [
            {
                "id": 0,
                "message": {"text": f"Taint source: {finding.source.function}"},
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _make_relative_uri(finding.source.file, target_path),
                        "uriBaseId": "SRCROOT",
                    },
                    "region": {
                        "startLine": finding.source.line,
                        "startColumn": finding.source.column + 1,
                    },
                },
            }
        ],
        "taxa": [
            {
                "toolComponent": {"name": "CWE"},
                "id": cwe_id,
            }
        ],
    }

    # Build codeFlows from taint path
    if finding.taint_path and finding.taint_path.steps:
        thread_flow_locations = []
        for i, step in enumerate(finding.taint_path.steps):
            thread_flow_locations.append(
                {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _make_relative_uri(step.file, target_path),
                                "uriBaseId": "SRCROOT",
                            },
                            "region": {
                                "startLine": step.line,
                                "startColumn": step.column + 1,
                            },
                        },
                        "message": {
                            "text": f"Step {i + 1}: {step.variable} ({step.transform})"
                        },
                    }
                }
            )
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": thread_flow_locations,
                    }
                ]
            }
        ]

    # Property bag for tool-specific metadata
    properties: dict[str, Any] = {
        "finding_id": finding.id,
        "raw_confidence": finding.raw_confidence,
    }

    if verified is not None:
        properties["confidence_score"] = verified.confidence_score
        properties["verification_status"] = verified.verification_status

    if guidance_item is not None:
        properties["remediation_guidance"] = {
            "vulnerability_explanation": guidance_item.vulnerability_explanation,
            "fix_pattern": guidance_item.fix_pattern,
            "code_example": guidance_item.code_example,
            "effort_estimate": guidance_item.effort_estimate,
            "references": guidance_item.references,
            "test_suggestions": guidance_item.test_suggestions,
        }

    result["properties"] = properties

    return result


class SarifFormatter:
    """Produce SARIF 2.1.0 conformant JSON output."""

    def format_hunt(self, data: HuntResult, target_path: str = "") -> str:
        """Format hunt phase results as SARIF 2.1.0."""
        results = [_build_result(f, target_path) for f in data.findings]
        rules = _build_rules(data.findings)
        sarif = self._build_sarif_envelope(results, rules, target_path)
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def format_full_scan(self, data: FullScanResult, target_path: str = "") -> str:
        """Format full-scan results as SARIF 2.1.0."""
        verified_by_id: dict[str, Any] = {}
        for v in data.verified:
            verified_by_id[v.finding.id] = v

        guidance_by_id: dict[str, Any] = {}
        for g in data.guidance:
            guidance_by_id[g.finding_id] = g

        results = []
        for f in data.findings:
            verified = verified_by_id.get(f.id)
            guidance_item = guidance_by_id.get(f.id)
            results.append(_build_result(f, target_path, verified, guidance_item))

        rules = _build_rules(data.findings)
        sarif = self._build_sarif_envelope(results, rules, target_path)
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def _build_sarif_envelope(
        self,
        results: list[dict[str, Any]],
        rules: list[dict[str, Any]],
        target_path: str,
    ) -> dict[str, Any]:
        """Build the complete SARIF 2.1.0 envelope."""
        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": _TOOL_NAME,
                    "version": _get_tool_version(),
                    "informationUri": "https://github.com/deep-code-security/deep-code-security",
                    "rules": rules,
                },
            },
            "results": results,
            "taxonomies": [
                {
                    "name": "CWE",
                    "version": "4.13",
                    "informationUri": "https://cwe.mitre.org/",
                    "isComprehensive": False,
                }
            ],
        }

        if target_path:
            run["originalUriBaseIds"] = {
                "SRCROOT": {
                    "uri": Path(target_path).as_uri() + "/",
                }
            }

        return {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [run],
        }
