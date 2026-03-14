"""CLI entry point for standalone deep-code-security usage."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from deep_code_security.architect.orchestrator import ArchitectOrchestrator
from deep_code_security.auditor.confidence import compute_confidence
from deep_code_security.auditor.models import VerifiedFinding
from deep_code_security.auditor.orchestrator import AuditorOrchestrator
from deep_code_security.hunter.orchestrator import HunterOrchestrator
from deep_code_security.mcp.path_validator import PathValidationError, validate_path
from deep_code_security.shared.config import get_config
from deep_code_security.shared.formatters import get_formatter
from deep_code_security.shared.formatters.protocol import FullScanResult, HuntResult


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
    """Write formatted output to stdout or file.

    When output_file is provided, validates path and writes with UTF-8 encoding.
    Refuses to overwrite existing files unless --force is set.
    """
    if output_file is None:
        click.echo(output)
        return

    # Validate output path through PathValidator
    try:
        validated_output = validate_path(output_file, config_allowed_paths)
    except PathValidationError as e:
        click.echo(f"Error: Output file path validation failed: {e}", err=True)
        sys.exit(1)

    output_path = Path(validated_output)

    # Refuse overwrite unless --force
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
) -> None:
    """Run the Hunter phase: discover vulnerabilities via AST analysis."""
    config = get_config()

    # Resolve format
    fmt_name = _resolve_format(output_format, json_output)

    # Validate path
    try:
        validated_path = validate_path(path, config.allowed_paths_str)
    except PathValidationError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    hunter = HunterOrchestrator(config=config)

    click.echo(f"Scanning {validated_path}...", err=True)

    findings, stats, total_count, has_more = hunter.scan(
        target_path=validated_path,
        languages=list(language) if language else None,
        severity_threshold=severity,
        max_results=max_results,
        offset=offset,
    )

    hunt_result = HuntResult(
        findings=findings,
        stats=stats,
        total_count=total_count,
        has_more=has_more,
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
) -> None:
    """Run all three phases: Hunt -> Verify -> Remediate."""
    config = get_config()

    # Resolve format
    fmt_name = _resolve_format(output_format, json_output)

    # Validate path
    try:
        validated_path = validate_path(path, config.allowed_paths_str)
    except PathValidationError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    hunter = HunterOrchestrator(config=config)
    auditor = AuditorOrchestrator(config=config)
    architect = ArchitectOrchestrator(config=config)

    click.echo(f"[1/3] Scanning {validated_path}...", err=True)

    findings, hunt_stats, total_count, has_more = hunter.scan(
        target_path=validated_path,
        languages=list(language) if language else None,
        severity_threshold=severity,
        max_results=max_results,
        offset=0,
    )

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

    full_scan_result = FullScanResult(
        findings=findings,
        verified=verified,
        guidance=guidance,
        hunt_stats=hunt_stats,
        verify_stats=verify_stats,
        remediate_stats=remediate_stats,
        total_count=total_count,
        has_more=has_more,
    )

    formatter = get_formatter(fmt_name)
    output = formatter.format_full_scan(full_scan_result, target_path=validated_path)

    _write_output(output, output_file, force, config.allowed_paths_str)


@cli.command()
def status() -> None:
    """Check sandbox health and registry info."""
    config = get_config()
    auditor = AuditorOrchestrator(config=config)

    sandbox_available = auditor.sandbox.is_available()
    runtime = auditor.sandbox._runtime_cmd or "none"

    registry_path = config.registry_path
    registries = []
    if registry_path.exists():
        registries = [f.stem for f in registry_path.glob("*.yaml") if f.is_file()]

    click.echo(f"Sandbox available: {sandbox_available}")
    click.echo(f"Container runtime: {runtime}")
    click.echo(f"Registries: {', '.join(sorted(registries)) or 'none'}")
    click.echo(f"Allowed paths: {', '.join(config.allowed_paths_str)}")


if __name__ == "__main__":
    cli()
