"""Resolve SAST findings to fuzzable function targets."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from deep_code_security.bridge.models import (
    BridgeConfig,
    BridgeResult,
    FuzzTarget,
    SASTContext,
)
from deep_code_security.fuzzer.analyzer.signature_extractor import (
    extract_targets_from_file,
)
from deep_code_security.fuzzer.models import TargetInfo
from deep_code_security.hunter.models import RawFinding

__all__ = ["resolve_findings_to_targets"]

logger = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# CWE IDs recognised by the C hunter that are relevant for fuzzing.
_C_FUZZABLE_CWES: frozenset[str] = frozenset(
    {
        "CWE-119",  # Improper Restriction of Operations within Bounds
        "CWE-120",  # Buffer Copy without Checking Size of Input
        "CWE-134",  # Use of Externally-Controlled Format String
        "CWE-190",  # Integer Overflow or Wraparound
        "CWE-676",  # Use of Potentially Dangerous Function
    }
)


def resolve_findings_to_targets(
    findings: list[RawFinding],
    config: BridgeConfig | None = None,
) -> BridgeResult:
    """Convert SAST findings into fuzz targets.

    Groups findings by file, uses signature_extractor to identify function
    boundaries, maps each sink to its containing function, checks for
    fuzzable parameters, then aggregates SAST context per function.

    Args:
        findings: RawFinding list from the Hunter phase.
        config: Optional bridge configuration (max_targets, etc.).

    Returns:
        BridgeResult with fuzz targets and skip diagnostics.
    """
    if config is None:
        max_targets_env = os.environ.get("DCS_BRIDGE_MAX_TARGETS", "10")
        try:
            max_targets = max(1, int(max_targets_env))
        except ValueError:
            max_targets = 10
        config = BridgeConfig(max_targets=max_targets)

    total_findings = len(findings)
    skipped_findings = 0
    skipped_reasons: list[str] = []
    not_directly_fuzzable = 0

    # Maps (file_path, qualified_name) -> merged data
    target_map: dict[tuple[str, str], _TargetAccumulator] = {}

    # Determine which C plugin names are permitted by the allowlist.
    allowed_plugins_env: str = os.environ.get("DCS_FUZZ_ALLOWED_PLUGINS", "python")
    allowed_plugins: frozenset[str] = frozenset(
        p.strip().lower() for p in allowed_plugins_env.split(",") if p.strip()
    )

    # Group findings by sink file for batch parsing.
    # Dispatch key: file extension determines the extractor to use.
    by_file: dict[str, list[RawFinding]] = {}
    for finding in findings:
        lang = finding.language.lower()
        sink_file = finding.sink.file
        sink_ext = Path(sink_file).suffix.lower()

        if lang == "python" or sink_ext == ".py":
            by_file.setdefault(sink_file, []).append(finding)
        elif lang == "c" or sink_ext == ".c":
            if "c" not in allowed_plugins:
                logger.warning(
                    "C finding skipped: 'c' not in DCS_FUZZ_ALLOWED_PLUGINS (%r). "
                    "Set DCS_FUZZ_ALLOWED_PLUGINS=python,c to enable.",
                    allowed_plugins_env,
                )
                skipped_findings += 1
                skipped_reasons.append(
                    f"C plugin not enabled (DCS_FUZZ_ALLOWED_PLUGINS={allowed_plugins_env!r}): "
                    f"{sink_file}"
                )
            else:
                by_file.setdefault(sink_file, []).append(finding)
        else:
            skipped_findings += 1
            skipped_reasons.append(f"unsupported language: {finding.language}")
            continue

    for sink_file, file_findings in by_file.items():
        # Parse the file for function boundaries.
        # Dispatch extractor based on file extension.
        file_path = Path(sink_file)
        if not file_path.exists():
            for finding in file_findings:
                skipped_findings += 1
                skipped_reasons.append(
                    f"sink file not found: {sink_file}"
                )
            continue

        sink_ext = file_path.suffix.lower()
        is_c_file = sink_ext == ".c"

        try:
            if is_c_file:
                targets_in_file = _extract_c_targets(file_path)
            else:
                targets_in_file = extract_targets_from_file(
                    file_path,
                    allow_side_effects=True,
                    include_instance_methods=True,
                )
        except SyntaxError as e:
            for finding in file_findings:
                skipped_findings += 1
                skipped_reasons.append(
                    f"syntax error in {sink_file}: {e}"
                )
            continue
        except Exception as e:  # noqa: BLE001
            for finding in file_findings:
                skipped_findings += 1
                skipped_reasons.append(
                    f"error parsing {sink_file}: {e}"
                )
            continue

        for finding in file_findings:
            sink_line = finding.sink.line
            containing = _find_containing_function(targets_in_file, sink_line)

            if containing is None:
                skipped_findings += 1
                skipped_reasons.append(
                    f"sink at line {sink_line} is not inside a function in {sink_file}"
                )
                continue

            # Fuzzability check: zero fuzzable parameters means we cannot inject data
            param_count = len(containing.parameters)
            if param_count == 0:
                not_directly_fuzzable += 1
                skipped_findings += 1
                skipped_reasons.append(
                    f"function {containing.qualified_name} has no fuzzable parameters "
                    "(taint source is likely a framework global, not a function argument)"
                )
                continue

            key = (sink_file, containing.qualified_name)
            if key not in target_map:
                target_map[key] = _TargetAccumulator(
                    file_path=sink_file,
                    function_name=containing.qualified_name,
                    requires_instance=containing.is_instance_method,
                    parameter_count=param_count,
                    plugin_name="c" if is_c_file else "python",
                )
            acc = target_map[key]
            acc.add_finding(finding)

    # Build FuzzTarget list from accumulators
    fuzz_targets: list[FuzzTarget] = [acc.build() for acc in target_map.values()]

    # Cap by max_targets, sorted by severity descending then finding_count descending
    if len(fuzz_targets) > config.max_targets:
        logger.warning(
            "Capped fuzz targets from %d to %d; increase DCS_BRIDGE_MAX_TARGETS to include more.",
            len(fuzz_targets),
            config.max_targets,
        )
        fuzz_targets.sort(
            key=lambda t: (
                _SEVERITY_ORDER.get(t.sast_context.severity, 0),
                t.sast_context.finding_count,
            ),
            reverse=True,
        )
        fuzz_targets = fuzz_targets[: config.max_targets]

    return BridgeResult(
        fuzz_targets=fuzz_targets,
        skipped_findings=skipped_findings,
        skipped_reasons=skipped_reasons,
        total_findings=total_findings,
        not_directly_fuzzable=not_directly_fuzzable,
    )


def _extract_c_targets(file_path: Path) -> list[TargetInfo]:
    """Extract fuzzable C function targets using the C signature extractor.

    Thin wrapper that imports lazily so the C extractor is only loaded when
    a C file is actually encountered, keeping the Python-only path fast.

    Args:
        file_path: Absolute path to the .c file.

    Returns:
        List of TargetInfo objects for each fuzzable function.
    """
    from deep_code_security.fuzzer.analyzer.c_signature_extractor import (
        extract_c_targets_from_file,
    )

    return extract_c_targets_from_file(file_path)


def _find_containing_function(
    targets: list[TargetInfo],
    line: int,
) -> TargetInfo | None:
    """Find the function whose line range contains the given line number.

    Uses TargetInfo.lineno and TargetInfo.end_lineno to determine containment.
    Returns the innermost matching function (smallest range).

    Args:
        targets: List of TargetInfo with lineno/end_lineno populated.
        line: 1-based line number to look up.

    Returns:
        The innermost containing TargetInfo, or None if not found.
    """
    best: TargetInfo | None = None
    best_range = 0

    for target in targets:
        if target.lineno is None or target.end_lineno is None:
            continue
        if target.lineno <= line <= target.end_lineno:
            span = target.end_lineno - target.lineno
            # Prefer innermost (smallest span)
            if best is None or span < best_range:
                best = target
                best_range = span

    return best


class _TargetAccumulator:
    """Accumulates SAST context across multiple findings for the same function."""

    def __init__(
        self,
        file_path: str,
        function_name: str,
        requires_instance: bool,
        parameter_count: int,
        plugin_name: str = "python",
    ) -> None:
        self.file_path = file_path
        self.function_name = function_name
        self.requires_instance = requires_instance
        self.parameter_count = parameter_count
        self.plugin_name = plugin_name
        self.finding_ids: list[str] = []
        self.cwe_ids: list[str] = []
        self.vulnerability_classes: list[str] = []
        self.sink_functions: list[str] = []
        self.source_categories: list[str] = []
        self.severities: list[str] = []

    def add_finding(self, finding: RawFinding) -> None:
        """Add a finding to this accumulator."""
        self.finding_ids.append(finding.id)

        # Extract CWE ID from sink.cwe (e.g., "CWE-78")
        cwe = finding.sink.cwe
        if cwe and cwe not in self.cwe_ids:
            self.cwe_ids.append(cwe)

        vc = finding.vulnerability_class
        if vc and vc not in self.vulnerability_classes:
            self.vulnerability_classes.append(vc)

        sink_fn = finding.sink.function
        if sink_fn and sink_fn not in self.sink_functions:
            self.sink_functions.append(sink_fn)

        src_cat = finding.source.category
        if src_cat and src_cat not in self.source_categories:
            self.source_categories.append(src_cat)

        self.severities.append(finding.severity)

    def build(self) -> FuzzTarget:
        """Build the final FuzzTarget from accumulated data."""
        # Highest severity wins
        max_severity = max(
            self.severities,
            key=lambda s: _SEVERITY_ORDER.get(s, 0),
            default="medium",
        )

        sast_context = SASTContext(
            cwe_ids=self.cwe_ids,
            vulnerability_classes=self.vulnerability_classes,
            sink_functions=self.sink_functions,
            source_categories=self.source_categories,
            severity=max_severity,
            finding_count=len(self.finding_ids),
        )

        return FuzzTarget(
            file_path=self.file_path,
            function_name=self.function_name,
            sast_context=sast_context,
            finding_ids=list(self.finding_ids),
            requires_instance=self.requires_instance,
            parameter_count=self.parameter_count,
        )
