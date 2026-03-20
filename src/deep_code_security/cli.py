"""CLI entry point for standalone deep-code-security usage."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click

if TYPE_CHECKING:
    from deep_code_security.fuzzer.config import FuzzerConfig
    from deep_code_security.fuzzer.models import FuzzReport
    from deep_code_security.shared.formatters.protocol import FuzzReportResult

from deep_code_security.architect.orchestrator import ArchitectOrchestrator
from deep_code_security.auditor.confidence import compute_confidence
from deep_code_security.auditor.models import VerifiedFinding
from deep_code_security.auditor.orchestrator import AuditorOrchestrator
from deep_code_security.hunter.orchestrator import HunterOrchestrator
from deep_code_security.mcp.path_validator import PathValidationError, validate_path
from deep_code_security.shared.config import get_config
from deep_code_security.shared.formatters import get_formatter, supports_fuzz, supports_hybrid
from deep_code_security.shared.formatters.protocol import (
    FullScanResult,
    HuntResult,
    SuppressionSummary,
)
from deep_code_security.shared.suppressions import SuppressionResult

# Protected write paths (rejected for --output-dir)
_PROTECTED_WRITE_DIRS = {"src", "registries", ".git"}


def _resolve_format(output_format: str, json_output: bool) -> str:
    """Resolve output format, handling deprecated --json-output flag."""
    if json_output:
        click.echo(
            "Warning: --json-output is deprecated. Use --format json instead.",
            err=True,
        )
        return "json"
    return output_format


def _write_output(
    output: str,
    output_file: str | None,
    force: bool,
    config_allowed_paths: list[str],
) -> None:
    """Write formatted output to stdout or file."""
    if output_file is None:
        click.echo(output)
        return

    try:
        validated_output = validate_path(output_file, config_allowed_paths)
    except PathValidationError as e:
        click.echo(f"Error: Output file path validation failed: {e}", err=True)
        sys.exit(1)

    output_path = Path(validated_output)

    if output_path.exists() and not force:
        click.echo(
            f"Error: Output file {output_file!r} already exists. "
            f"Use --force to overwrite.",
            err=True,
        )
        sys.exit(1)

    try:
        output_path.write_text(output, encoding="utf-8")
        click.echo(f"Output written to {validated_output}", err=True)
    except OSError as e:
        click.echo(f"Error: Could not write to {output_file!r}: {e}", err=True)
        sys.exit(1)


def _validate_write_path(output_dir: str) -> None:
    """Reject write paths inside protected directories."""
    p = Path(output_dir).resolve()
    for part in p.parts:
        if part in _PROTECTED_WRITE_DIRS:
            click.echo(
                f"Error: Output directory {output_dir!r} is inside protected "
                f"directory '{part}'. Choose a different location.",
                err=True,
            )
            sys.exit(1)


@click.group()
@click.version_option(package_name="deep-code-security")
def cli() -> None:
    """deep-code-security -- Multi-language SAST with agentic verification."""
    pass


@cli.command()
@click.argument("path")
@click.option(
    "--language", "-l", multiple=True,
    help="Filter to specific language (python, go, c). Repeat for multiple.",
)
@click.option(
    "--severity", default="medium",
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Minimum severity threshold (default: medium).",
)
@click.option("--max-results", default=100, help="Maximum findings per page.")
@click.option("--offset", default=0, help="Pagination offset.")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["text", "json", "sarif", "html"]),
    default="text",
    help="Output format (default: text).",
)
@click.option(
    "--json-output", is_flag=True, hidden=True,
    help="[DEPRECATED] Use --format json instead.",
)
@click.option(
    "--output-file", "-o", type=click.Path(),
    help="Write output to file instead of stdout.",
)
@click.option(
    "--force", is_flag=True, default=False,
    help="Overwrite existing output file.",
)
@click.option(
    "--ignore-suppressions", "ignore_suppressions", is_flag=True, default=False,
    help="Ignore .dcs-suppress.yaml and report all findings.",
)
def hunt(
    path: str,
    language: tuple[str, ...],
    severity: str,
    max_results: int,
    offset: int,
    output_format: str,
    json_output: bool,
    output_file: str | None,
    force: bool,
    ignore_suppressions: bool,
) -> None:
    """Run the Hunter phase: discover vulnerabilities via AST analysis."""
    config = get_config()

    fmt_name = _resolve_format(output_format, json_output)

    try:
        validated_path = validate_path(path, config.allowed_paths_str)
    except PathValidationError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    hunter = HunterOrchestrator(config=config)

    click.echo(f"Scanning {validated_path}...", err=True)

    try:
        findings, stats, total_count, has_more = hunter.scan(
            target_path=validated_path,
            languages=list(language) if language else None,
            severity_threshold=severity,
            max_results=max_results,
            offset=offset,
            ignore_suppressions=ignore_suppressions,
        )
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    # Build suppression summary from orchestrator result
    suppression_result = hunter.last_suppression_result
    suppression_summary: SuppressionSummary | None = None
    suppressed_findings = []
    if isinstance(suppression_result, SuppressionResult):
        suppression_summary = SuppressionSummary(
            suppressed_count=len(suppression_result.suppressed_findings),
            total_rules=suppression_result.total_rules,
            expired_rules=suppression_result.expired_rules,
            suppression_reasons=suppression_result.suppression_reasons,
            suppression_file=suppression_result.suppression_file_path,
        )
        suppressed_findings = suppression_result.suppressed_findings
        if suppression_summary.suppressed_count > 0:
            _expired_note = (
                f", {suppression_summary.expired_rules} expired"
                if suppression_summary.expired_rules
                else ""
            )
            click.echo(
                f"Suppressions: {suppression_summary.suppressed_count} finding(s) suppressed "
                f"({suppression_summary.total_rules} rule(s){_expired_note})",
                err=True,
            )

    _suppressed_ids = (
        list(suppression_result.suppression_reasons.keys())
        if isinstance(suppression_result, SuppressionResult)
        else []
    )
    hunt_result = HuntResult(
        findings=findings,
        stats=stats,
        total_count=total_count,
        has_more=has_more,
        suppression_summary=suppression_summary,
        suppressed_finding_ids=_suppressed_ids,
        suppressed_findings=suppressed_findings,
    )

    formatter = get_formatter(fmt_name)
    output = formatter.format_hunt(hunt_result, target_path=validated_path)

    _write_output(output, output_file, force, config.allowed_paths_str)


@cli.command()
@click.option(
    "--finding-id", multiple=True, required=True,
    help="Finding UUID from a previous hunt. Repeat for multiple.",
)
@click.option("--target-path", required=True, help="Path to target codebase.")
@click.option("--timeout", default=30, help="Sandbox timeout in seconds.")
@click.option("--max-verifications", default=50, help="Maximum findings to verify.")
@click.option("--json-output", is_flag=True, help="Output raw JSON to stdout.")
def verify(
    finding_id: tuple[str, ...],
    target_path: str,
    timeout: int,
    max_verifications: int,
    json_output: bool,
) -> None:
    """Run the Auditor phase: verify findings with sandbox exploit execution."""
    click.echo("Note: verify requires findings from a previous 'hunt' run.", err=True)
    click.echo(
        "For standalone use, run 'dcs full-scan' instead.", err=True
    )
    sys.exit(1)


@cli.command()
@click.argument("path")
@click.option(
    "--language", "-l", multiple=True,
    help="Filter to specific language (python, go, c).",
)
@click.option(
    "--severity", default="medium",
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Minimum severity threshold.",
)
@click.option("--skip-verify", is_flag=True, help="Skip sandbox verification (faster).")
@click.option("--max-results", default=100, help="Maximum findings to return.")
@click.option("--max-verifications", default=50, help="Maximum findings to verify.")
@click.option("--timeout", default=30, help="Sandbox timeout in seconds.")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["text", "json", "sarif", "html"]),
    default="text",
    help="Output format (default: text).",
)
@click.option(
    "--json-output", is_flag=True, hidden=True,
    help="[DEPRECATED] Use --format json instead.",
)
@click.option(
    "--output-file", "-o", type=click.Path(),
    help="Write output to file instead of stdout.",
)
@click.option(
    "--force", is_flag=True, default=False,
    help="Overwrite existing output file.",
)
@click.option(
    "--ignore-suppressions", "ignore_suppressions", is_flag=True, default=False,
    help="Ignore .dcs-suppress.yaml and report all findings.",
)
def full_scan(
    path: str,
    language: tuple[str, ...],
    severity: str,
    skip_verify: bool,
    max_results: int,
    max_verifications: int,
    timeout: int,
    output_format: str,
    json_output: bool,
    output_file: str | None,
    force: bool,
    ignore_suppressions: bool,
) -> None:
    """Run all three phases: Hunt -> Verify -> Remediate."""
    config = get_config()

    fmt_name = _resolve_format(output_format, json_output)

    try:
        validated_path = validate_path(path, config.allowed_paths_str)
    except PathValidationError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    hunter = HunterOrchestrator(config=config)
    auditor = AuditorOrchestrator(config=config)
    architect = ArchitectOrchestrator(config=config)

    click.echo(f"[1/3] Scanning {validated_path}...", err=True)

    try:
        findings, hunt_stats, total_count, has_more = hunter.scan(
            target_path=validated_path,
            languages=list(language) if language else None,
            severity_threshold=severity,
            max_results=max_results,
            offset=0,
            ignore_suppressions=ignore_suppressions,
        )
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    click.echo(
        f"  Found {total_count} findings in {hunt_stats.files_scanned} files",
        err=True,
    )

    # Phase 2: Verify
    verified = []
    verify_stats = None
    if not skip_verify and findings:
        from deep_code_security.mcp.input_validator import (
            InputValidationError,
            validate_raw_finding,
        )
        click.echo(f"[2/3] Verifying up to {max_verifications} findings...", err=True)
        validated = []
        for f in findings:
            try:
                validated.append(validate_raw_finding(f))
            except InputValidationError:
                pass
        verified, verify_stats = auditor.verify(
            findings=validated,
            target_path=validated_path,
            sandbox_timeout=timeout,
            max_verifications=max_verifications,
        )
        click.echo(f"  Verified {verify_stats.verified_count} findings", err=True)
    elif findings and skip_verify:
        click.echo("[2/3] Skipping verification (--skip-verify)", err=True)
        for f in findings:
            confidence, status = compute_confidence(f, [])
            verified.append(VerifiedFinding(
                finding=f,
                exploit_results=[],
                confidence_score=confidence,
                verification_status=status,
            ))

    # Phase 3: Remediate
    guidance = []
    remediate_stats = None
    if verified:
        click.echo(f"[3/3] Generating guidance for {len(verified)} findings...", err=True)
        guidance, remediate_stats = architect.remediate(
            verified_findings=verified,
            target_path=validated_path,
        )

    # Build suppression summary from orchestrator result
    suppression_result = hunter.last_suppression_result
    suppression_summary_fs: SuppressionSummary | None = None
    suppressed_findings_fs = []
    if isinstance(suppression_result, SuppressionResult):
        suppression_summary_fs = SuppressionSummary(
            suppressed_count=len(suppression_result.suppressed_findings),
            total_rules=suppression_result.total_rules,
            expired_rules=suppression_result.expired_rules,
            suppression_reasons=suppression_result.suppression_reasons,
            suppression_file=suppression_result.suppression_file_path,
        )
        suppressed_findings_fs = suppression_result.suppressed_findings
        if suppression_summary_fs.suppressed_count > 0:
            _expired_note_fs = (
                f", {suppression_summary_fs.expired_rules} expired"
                if suppression_summary_fs.expired_rules
                else ""
            )
            click.echo(
                f"Suppressions: {suppression_summary_fs.suppressed_count} "
                f"finding(s) suppressed "
                f"({suppression_summary_fs.total_rules} rule(s){_expired_note_fs})",
                err=True,
            )

    _suppressed_ids_fs = (
        list(suppression_result.suppression_reasons.keys())
        if isinstance(suppression_result, SuppressionResult)
        else []
    )
    full_scan_result = FullScanResult(
        findings=findings,
        verified=verified,
        guidance=guidance,
        hunt_stats=hunt_stats,
        verify_stats=verify_stats,
        remediate_stats=remediate_stats,
        total_count=total_count,
        has_more=has_more,
        suppression_summary=suppression_summary_fs,
        suppressed_finding_ids=_suppressed_ids_fs,
        suppressed_findings=suppressed_findings_fs,
    )

    formatter = get_formatter(fmt_name)
    output = formatter.format_full_scan(full_scan_result, target_path=validated_path)

    _write_output(output, output_file, force, config.allowed_paths_str)


@cli.command()
def status() -> None:
    """Check sandbox health, registry info, and fuzzer availability."""
    config = get_config()
    auditor = AuditorOrchestrator(config=config)

    sandbox_available = auditor.sandbox.is_available()
    runtime = getattr(auditor.sandbox, "_runtime_cmd", None) or "none"

    registry_path = config.registry_path
    registries = []
    if registry_path.exists():
        registries = [f.stem for f in registry_path.glob("*.yaml") if f.is_file()]

    # Determine active scanner backend
    from deep_code_security.hunter.scanner_backend import select_backend  # noqa: PLC0415
    try:
        _backend = select_backend(config.scanner_backend)
        scanner_backend_label = _backend.name
        # Append version info if available (format: "semgrep (v1.78.0)")
        _version = getattr(_backend, "version", None)
        if _version:
            _ver_str = _version if _version.startswith("v") else f"v{_version}"
            scanner_backend_label = f"{scanner_backend_label} ({_ver_str})"
    except RuntimeError as exc:
        scanner_backend_label = f"unavailable ({exc})"

    click.echo(f"Sandbox available: {sandbox_available}")
    click.echo(f"Container runtime: {runtime}")
    click.echo(f"Scanner backend: {scanner_backend_label}")
    click.echo(f"Registries: {', '.join(sorted(registries)) or 'none'}")
    click.echo(f"Allowed paths: {', '.join(config.allowed_paths_str)}")

    # Fuzzer availability
    try:
        import anthropic  # noqa: F401
        anthropic_available = True
    except ImportError:
        anthropic_available = False

    click.echo(f"Anthropic SDK: {'installed' if anthropic_available else 'not installed'}")

    from deep_code_security.fuzzer.consent import has_stored_consent
    click.echo(f"Fuzz consent: {'stored' if has_stored_consent() else 'not stored'}")

    click.echo(f"Vertex AI: {'configured' if config.fuzz_use_vertex else 'not configured'}")


# ---------- Fuzzer CLI Commands ----------


@cli.command()
@click.argument("target")
@click.option("--function", "-F", multiple=True, help="Specific function(s) to fuzz.")
@click.option("--iterations", "-n", default=10, help="Maximum fuzzing iterations.")
@click.option("--inputs-per-iter", default=10, help="Inputs per iteration.")
@click.option("--timeout", default=5000, metavar="MS", help="Per-input timeout in ms.")
@click.option("--model", default="claude-sonnet-4-6", help="Claude model to use.")
@click.option("--output-dir", default="./fuzzy-output", metavar="PATH", help="Output directory.")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["text", "json", "sarif", "html"]),
    default="text",
)
@click.option(
    "--output-file", "-o", default=None, metavar="PATH",
    help="Write output to file.",
)
@click.option("--force", is_flag=True, default=False, help="Overwrite existing output file.")
@click.option("--max-cost", default=5.00, metavar="USD", help="API cost budget.")
@click.option("--consent", "consent_flag", is_flag=True, help="Consent to API transmission.")
@click.option("--dry-run", is_flag=True, help="Preview what would be sent.")
@click.option("--vertex", is_flag=True, help="Use Vertex AI backend.")
@click.option("--gcp-project", default=None, help="GCP project ID.")
@click.option("--gcp-region", default="us-east5", help="GCP region.")
@click.option("--allow-side-effects", is_flag=True, help="Include functions with side effects.")
@click.option("--verbose", is_flag=True, help="Verbose output.")
@click.option("--plugin", default="python", help="Fuzzer plugin to use.")
@click.option("--seed-corpus", default=None, metavar="PATH", help="Seed corpus directory.")
def fuzz(
    target: str,
    function: tuple[str, ...],
    iterations: int,
    inputs_per_iter: int,
    timeout: int,
    model: str,
    output_dir: str,
    output_format: str,
    output_file: str | None,
    force: bool,
    max_cost: float,
    consent_flag: bool,
    dry_run: bool,
    vertex: bool,
    gcp_project: str | None,
    gcp_region: str,
    allow_side_effects: bool,
    verbose: bool,
    plugin: str,
    seed_corpus: str | None,
) -> None:
    """Run AI-powered fuzzer against a Python target."""
    config = get_config()

    # Validate target path
    try:
        validated_target = validate_path(target, config.allowed_paths_str)
    except PathValidationError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    # Validate output directory (write-path protection)
    _validate_write_path(output_dir)

    # Build FuzzerConfig from DCS config + CLI overrides
    from deep_code_security.fuzzer.config import FuzzerConfig

    fuzzer_config = FuzzerConfig.from_dcs_config(
        config,
        target_path=validated_target,
        target_functions=list(function) if function else [],
        max_iterations=iterations,
        inputs_per_iteration=inputs_per_iter,
        timeout_ms=timeout,
        model=model,
        output_dir=output_dir,
        max_cost_usd=max_cost,
        consent=consent_flag or config.fuzz_consent,
        dry_run=dry_run,
        use_vertex=vertex or config.fuzz_use_vertex,
        gcp_project=gcp_project or config.fuzz_gcp_project,
        gcp_region=gcp_region,
        allow_side_effects=allow_side_effects,
        verbose=verbose,
        plugin_name=plugin,
        seed_corpus_path=seed_corpus,
        report_format=output_format,
    )

    # Run fuzzer
    from deep_code_security.fuzzer.orchestrator import FuzzOrchestrator

    orchestrator = FuzzOrchestrator(
        config=fuzzer_config,
        install_signal_handlers=True,
    )

    try:
        report = orchestrator.run()
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    # Format output
    formatter = get_formatter(output_format)
    if not supports_fuzz(formatter):
        click.echo(
            f"Error: Formatter '{output_format}' does not support fuzz output.",
            err=True,
        )
        sys.exit(1)

    # Build FuzzReportResult DTO
    fuzz_result = _build_fuzz_report_result(report, fuzzer_config)
    output = formatter.format_fuzz(fuzz_result, target_path=validated_target)

    _write_output(output, output_file, force, config.allowed_paths_str)


@cli.command()
@click.argument("corpus_dir")
@click.option("--target", required=True, help="Path to the target module.")
@click.option("--timeout", default=5000, metavar="MS", help="Per-input timeout in ms.")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["text", "json", "sarif", "html"]),
    default="text",
)
@click.option("--output-file", "-o", default=None, metavar="PATH")
@click.option("--force", is_flag=True, default=False)
def replay(
    corpus_dir: str,
    target: str,
    timeout: int,
    output_format: str,
    output_file: str | None,
    force: bool,
) -> None:
    """Re-execute saved crash inputs to check for regressions."""
    config = get_config()

    try:
        validated_target = validate_path(target, config.allowed_paths_str)
    except PathValidationError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    corpus_path = Path(corpus_dir)
    if not corpus_path.exists():
        click.echo(f"Error: Corpus directory not found: {corpus_dir}", err=True)
        sys.exit(1)

    from deep_code_security.fuzzer.corpus.manager import CorpusManager
    from deep_code_security.fuzzer.replay.runner import ReplayRunner

    corpus = CorpusManager(corpus_path)
    crashes = corpus.get_all_crashes()

    if not crashes:
        click.echo("No crash inputs found in corpus.", err=True)
        sys.exit(0)

    try:
        runner = ReplayRunner(
            target_path=validated_target,
            timeout_ms=timeout,
        )
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    click.echo(f"Replaying {len(crashes)} crash inputs...", err=True)
    results = runner.replay_all(crashes)

    # Build DTO
    from deep_code_security.shared.formatters.protocol import ReplayResultDTO, ReplayResultEntry

    entries = [
        ReplayResultEntry(
            status=r.status,
            target_function=r.original.input.target_function,
            original_exception=r.original_exception,
            replayed_exception=r.replayed_exception,
            args=list(r.original.input.args),
            kwargs=dict(r.original.input.kwargs),
        )
        for r in results
    ]

    dto = ReplayResultDTO(
        results=entries,
        fixed_count=sum(1 for r in results if r.status == "fixed"),
        still_failing_count=sum(1 for r in results if r.status == "still_failing"),
        error_count=sum(1 for r in results if r.status == "error"),
        total_count=len(results),
        target_path=validated_target,
    )

    formatter = get_formatter(output_format)
    if not supports_fuzz(formatter):
        click.echo(
            f"Error: Formatter '{output_format}' does not support replay output.",
            err=True,
        )
        sys.exit(1)

    output = formatter.format_replay(dto, target_path=validated_target)
    _write_output(output, output_file, force, config.allowed_paths_str)


@cli.command()
@click.argument("corpus_dir")
@click.option("--crashes-only", is_flag=True, help="Show only crash entries.")
def corpus(corpus_dir: str, crashes_only: bool) -> None:
    """Inspect corpus contents."""
    corpus_path = Path(corpus_dir)
    if not corpus_path.exists():
        click.echo(f"Error: Corpus directory not found: {corpus_dir}", err=True)
        sys.exit(1)

    from deep_code_security.fuzzer.corpus.manager import CorpusManager

    mgr = CorpusManager(corpus_path)
    summary = mgr.get_summary()

    click.echo(f"Corpus: {corpus_dir}")
    click.echo(f"  Total inputs: {summary['total_inputs']}")
    click.echo(f"  Crash files: {summary['crash_files']}")
    click.echo(f"  Interesting files: {summary['interesting_count']}")
    click.echo(f"  Unique crash signatures: {summary['crash_count']}")

    if crashes_only:
        crashes = mgr.get_all_crashes()
        if crashes:
            click.echo(f"\nCrashes ({len(crashes)}):")
            for c in crashes[:20]:
                click.echo(
                    f"  {c.input.target_function}: {(c.exception or '')[:80]}"
                )
            if len(crashes) > 20:
                click.echo(f"  ... and {len(crashes) - 20} more")


@cli.command("fuzz-plugins")
def fuzz_plugins() -> None:
    """List available fuzzer plugins."""
    from deep_code_security.fuzzer.plugins.registry import registry

    plugins = registry.list_plugins()
    if plugins:
        click.echo("Available fuzzer plugins:")
        for name in plugins:
            click.echo(f"  - {name}")
    else:
        click.echo("No fuzzer plugins found.")
        click.echo("Install plugins or check DCS_FUZZ_ALLOWED_PLUGINS.")


@cli.command()
@click.argument("output_dir")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["text", "json", "sarif"]),
    default=None,
)
def report(output_dir: str, output_format: str | None) -> None:
    """View saved fuzz reports from output directory."""
    output_path = Path(output_dir)
    if not output_path.exists():
        click.echo(f"Error: Output directory not found: {output_dir}", err=True)
        sys.exit(1)

    # Look for report files
    extensions = {".txt": "text", ".json": "json", ".sarif": "sarif"}
    found = []
    for ext, fmt in extensions.items():
        report_file = output_path / f"report{ext}"
        if report_file.exists():
            found.append((report_file, fmt))

    if not found:
        click.echo(f"No report files found in {output_dir}", err=True)
        sys.exit(1)

    # Select format
    if output_format:
        match = [f for f in found if f[1] == output_format]
        if not match:
            click.echo(
                f"No {output_format} report found. Available: "
                f"{', '.join(f[1] for f in found)}",
                err=True,
            )
            sys.exit(1)
        report_file = match[0][0]
    else:
        report_file = found[0][0]

    content = report_file.read_text(encoding="utf-8")
    click.echo(content)


@cli.command("hunt-fuzz")
@click.argument("path")
@click.option(
    "--language", "-l", multiple=True,
    help="Filter to specific language (python, go, c). Repeat for multiple.",
)
@click.option(
    "--severity", default="medium",
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Minimum severity threshold (default: medium).",
)
@click.option("--max-findings", default=100, help="Maximum findings per page.")
@click.option(
    "--max-fuzz-targets", default=10, type=int,
    help="Max fuzz targets (default: 10, env: DCS_BRIDGE_MAX_TARGETS).",
)
@click.option("--iterations", "-n", default=5, help="Maximum fuzzing iterations.")
@click.option("--inputs-per-iter", default=10, help="Inputs per iteration.")
@click.option("--timeout", default=5000, metavar="MS", help="Per-input timeout in ms.")
@click.option("--model", default="claude-sonnet-4-6", help="Claude model to use.")
@click.option("--output-dir", default="./fuzzy-output", metavar="PATH", help="Output directory.")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["text", "json", "sarif"]),
    default="text",
    help="Output format (default: text).",
)
@click.option(
    "--output-file", "-o", default=None, metavar="PATH",
    help="Write output to file.",
)
@click.option("--force", is_flag=True, default=False, help="Overwrite existing output file.")
@click.option("--max-cost", default=5.00, metavar="USD", help="API cost budget.")
@click.option("--consent", "consent_flag", is_flag=True, help="Consent to API transmission.")
@click.option("--dry-run", is_flag=True, help="Preview what would be sent.")
@click.option("--verbose", is_flag=True, help="Verbose output.")
@click.option(
    "--ignore-suppressions", "ignore_suppressions", is_flag=True, default=False,
    help="Ignore .dcs-suppress.yaml and report all findings.",
)
def hunt_fuzz(
    path: str,
    language: tuple[str, ...],
    severity: str,
    max_findings: int,
    max_fuzz_targets: int,
    iterations: int,
    inputs_per_iter: int,
    timeout: int,
    model: str,
    output_dir: str,
    output_format: str,
    output_file: str | None,
    force: bool,
    max_cost: float,
    consent_flag: bool,
    dry_run: bool,
    verbose: bool,
    ignore_suppressions: bool,
) -> None:
    """Run SAST analysis then fuzz the identified vulnerable functions."""
    config = get_config()

    # Validate target path
    try:
        validated_path = validate_path(path, config.allowed_paths_str)
    except PathValidationError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    # Validate output directory (write-path protection)
    _validate_write_path(output_dir)

    # Validate max_fuzz_targets
    max_fuzz_targets = max(1, min(100, max_fuzz_targets))

    # Check formatter support
    formatter = get_formatter(output_format)
    if not supports_hybrid(formatter):
        click.echo(
            f"Error: Formatter '{output_format}' does not support hunt-fuzz output.",
            err=True,
        )
        sys.exit(1)

    # Phase 1: Hunt
    hunter = HunterOrchestrator(config=config)
    click.echo(f"[1/3] Scanning {validated_path}...", err=True)

    try:
        findings, hunt_stats, total_count, has_more = hunter.scan(
            target_path=validated_path,
            languages=list(language) if language else None,
            severity_threshold=severity,
            max_results=max_findings,
            offset=0,
            ignore_suppressions=ignore_suppressions,
        )
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    click.echo(
        f"  Found {total_count} findings in {hunt_stats.files_scanned} files",
        err=True,
    )

    from deep_code_security.shared.formatters.protocol import HuntResult

    # Build suppression summary from orchestrator result
    hf_suppression_result = hunter.last_suppression_result
    hf_suppression_summary: SuppressionSummary | None = None
    hf_suppressed_findings = []
    if isinstance(hf_suppression_result, SuppressionResult):
        hf_suppression_summary = SuppressionSummary(
            suppressed_count=len(hf_suppression_result.suppressed_findings),
            total_rules=hf_suppression_result.total_rules,
            expired_rules=hf_suppression_result.expired_rules,
            suppression_reasons=hf_suppression_result.suppression_reasons,
            suppression_file=hf_suppression_result.suppression_file_path,
        )
        hf_suppressed_findings = hf_suppression_result.suppressed_findings
        if hf_suppression_summary.suppressed_count > 0:
            _expired_note_hf = (
                f", {hf_suppression_summary.expired_rules} expired"
                if hf_suppression_summary.expired_rules
                else ""
            )
            click.echo(
                f"Suppressions: {hf_suppression_summary.suppressed_count} "
                f"finding(s) suppressed "
                f"({hf_suppression_summary.total_rules} rule(s){_expired_note_hf})",
                err=True,
            )

    _suppressed_ids_hf = (
        list(hf_suppression_result.suppression_reasons.keys())
        if isinstance(hf_suppression_result, SuppressionResult)
        else []
    )
    hunt_result = HuntResult(
        findings=findings,
        stats=hunt_stats,
        total_count=total_count,
        has_more=has_more,
        suppression_summary=hf_suppression_summary,
        suppressed_finding_ids=_suppressed_ids_hf,
        suppressed_findings=hf_suppressed_findings,
    )

    # Phase 2: Bridge
    click.echo("[2/3] Resolving fuzz targets from SAST findings...", err=True)

    from deep_code_security.bridge.models import BridgeConfig
    from deep_code_security.bridge.orchestrator import BridgeOrchestrator

    bridge_config = BridgeConfig(max_targets=max_fuzz_targets)
    bridge_orc = BridgeOrchestrator()
    bridge_result = bridge_orc.run_bridge(findings, config=bridge_config)

    fuzz_targets = bridge_result.fuzz_targets
    instance_targets = [t for t in fuzz_targets if t.requires_instance]

    click.echo(
        f"  {total_count} findings -> {len(fuzz_targets)} fuzz targets "
        f"({bridge_result.skipped_findings} skipped, "
        f"{bridge_result.not_directly_fuzzable} not directly fuzzable)",
        err=True,
    )

    if instance_targets:
        click.echo(
            f"  Warning: {len(instance_targets)} target(s) are instance methods and "
            "may require a manual harness for full coverage.",
            err=True,
        )

    if not fuzz_targets:
        click.echo(
            "  No fuzz targets found. "
            "Findings may be in route handlers that require framework harnesses.",
            err=True,
        )
        # Output bridge diagnostics only
        from deep_code_security.shared.formatters.protocol import HuntFuzzResult

        result_dto = HuntFuzzResult(
            hunt_result=hunt_result,
            bridge_result=bridge_result,
            fuzz_result=None,
            correlation=None,
        )
        output = formatter.format_hunt_fuzz(result_dto, target_path=validated_path)
        _write_output(output, output_file, force, config.allowed_paths_str)
        return

    # Phase 3: Fuzz
    click.echo(
        f"[3/3] Fuzzing {len(fuzz_targets)} function(s)...",
        err=True,
    )

    from deep_code_security.fuzzer.config import FuzzerConfig
    from deep_code_security.fuzzer.orchestrator import FuzzOrchestrator

    # Build sast_contexts mapping for prompt enrichment
    sast_contexts = {t.function_name: t.sast_context for t in fuzz_targets}
    target_functions = [t.function_name for t in fuzz_targets]
    # Use the file path of the first target for the fuzzer target path (may be multi-file)
    fuzz_target_path = fuzz_targets[0].file_path if fuzz_targets else validated_path

    fuzzer_config = FuzzerConfig.from_dcs_config(
        config,
        target_path=fuzz_target_path,
        target_functions=target_functions,
        max_iterations=iterations,
        inputs_per_iteration=inputs_per_iter,
        timeout_ms=timeout,
        model=model,
        output_dir=output_dir,
        max_cost_usd=max_cost,
        consent=consent_flag or config.fuzz_consent,
        dry_run=dry_run,
        verbose=verbose,
        plugin_name="python",
        report_format=output_format,
    )
    # Inject SAST contexts for iteration-1 prompt enrichment
    fuzzer_config.sast_contexts = sast_contexts  # type: ignore[assignment]

    orchestrator = FuzzOrchestrator(
        config=fuzzer_config,
        install_signal_handlers=True,
    )

    try:
        fuzz_report = orchestrator.run()
    except Exception as e:
        click.echo(f"Error during fuzzing: {e}", err=True)
        sys.exit(1)

    # Correlate
    correlation = bridge_orc.correlate(bridge_result, fuzz_report)

    # Build FuzzReportResult DTO
    fuzz_result_dto = _build_fuzz_report_result(fuzz_report, fuzzer_config)
    fuzz_result_dto.analysis_mode = "hybrid"

    from deep_code_security.shared.formatters.protocol import HuntFuzzResult

    result_dto = HuntFuzzResult(
        hunt_result=hunt_result,
        bridge_result=bridge_result,
        fuzz_result=fuzz_result_dto,
        correlation=correlation,
    )

    output = formatter.format_hunt_fuzz(result_dto, target_path=validated_path)
    _write_output(output, output_file, force, config.allowed_paths_str)


def _build_fuzz_report_result(
    report: FuzzReport, fuzzer_config: FuzzerConfig
) -> FuzzReportResult:
    """Build FuzzReportResult DTO from FuzzReport + FuzzerConfig."""
    from deep_code_security.shared.formatters.protocol import (
        FuzzConfigSummary,
        FuzzCrashSummary,
        FuzzReportResult,
        FuzzTargetInfo,
        UniqueCrashSummary,
    )

    config_summary = FuzzConfigSummary(
        target_path=fuzzer_config.target_path,
        plugin=fuzzer_config.plugin_name,
        model=fuzzer_config.model,
        max_iterations=fuzzer_config.max_iterations,
        inputs_per_iteration=fuzzer_config.inputs_per_iteration,
        timeout_ms=fuzzer_config.timeout_ms,
    )

    targets = [
        FuzzTargetInfo(
            qualified_name=t.qualified_name,
            signature=t.signature,
            module_path=t.module_path,
            complexity=t.complexity,
        )
        for t in report.targets
    ]

    crashes = [
        FuzzCrashSummary(
            target_function=c.input.target_function,
            exception=c.exception,
            args=list(c.input.args),
            kwargs=dict(c.input.kwargs),
            traceback=c.traceback,
            timed_out=c.timed_out,
        )
        for c in report.crashes
    ]

    unique_crashes = [
        UniqueCrashSummary(
            signature=uc.signature,
            exception_type=uc.exception_type,
            exception_message=uc.exception_message,
            location=uc.location,
            count=uc.count,
            target_functions=uc.target_functions,
            representative=FuzzCrashSummary(
                target_function=uc.representative.input.target_function,
                exception=uc.representative.exception,
                args=list(uc.representative.input.args),
                kwargs=dict(uc.representative.input.kwargs),
                traceback=uc.representative.traceback,
                timed_out=uc.representative.timed_out,
            ),
        )
        for uc in report.unique_crashes
    ]

    coverage_percent = None
    if report.final_coverage:
        coverage_percent = report.final_coverage.coverage_percent

    api_cost = None
    if report.api_usage:
        api_cost = report.api_usage.estimate_cost_usd(fuzzer_config.model)

    return FuzzReportResult(
        config_summary=config_summary,
        targets=targets,
        crashes=crashes,
        unique_crashes=unique_crashes,
        total_inputs=getattr(report, "total_inputs", 0),
        crash_count=getattr(report, "crash_count", 0),
        unique_crash_count=len(unique_crashes),
        timeout_count=getattr(report, "timeout_count", 0),
        total_iterations=getattr(report, "total_iterations", 0),
        coverage_percent=coverage_percent,
        api_cost_usd=api_cost,
        timestamp=getattr(report, "timestamp", 0.0),
    )


@cli.command()
def tui() -> None:
    """Launch the interactive TUI for deep-code-security."""
    try:
        from deep_code_security.tui.app import DCSApp
    except ImportError:
        click.echo(
            "Error: TUI requires the 'textual' package. "
            "Install with: pip install deep-code-security[tui]",
            err=True,
        )
        sys.exit(1)

    app = DCSApp()
    app.run()


if __name__ == "__main__":
    cli()
