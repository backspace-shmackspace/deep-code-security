"""CLI entry point for standalone deep-code-security usage."""

from __future__ import annotations

import json
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
from deep_code_security.shared.json_output import serialize_model, serialize_models


@click.group()
@click.version_option(package_name="deep-code-security")
def cli() -> None:
    """deep-code-security — Multi-language SAST with agentic verification."""
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
@click.option("--json-output", is_flag=True, help="Output raw JSON to stdout.")
def hunt(
    path: str,
    language: tuple[str, ...],
    severity: str,
    max_results: int,
    offset: int,
    json_output: bool,
) -> None:
    """Run the Hunter phase: discover vulnerabilities via AST analysis."""
    config = get_config()

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

    if json_output:
        output = {
            "findings": serialize_models(findings),
            "stats": serialize_model(stats),
            "total_count": total_count,
            "has_more": has_more,
        }
        click.echo(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        click.echo(
            f"Scanned {stats.files_scanned} files, found {total_count} findings "
            f"({stats.scan_duration_ms}ms)",
            err=True,
        )
        for f in findings:
            click.echo(
                f"[{f.severity.upper()}] {f.vulnerability_class} "
                f"in {Path(f.source.file).name}:{f.source.line} -> "
                f"{Path(f.sink.file).name}:{f.sink.line}"
            )
        if has_more:
            click.echo(f"... and more (use --offset {offset + max_results})", err=True)


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
@click.option("--json-output", is_flag=True, help="Output raw JSON to stdout.")
def full_scan(
    path: str,
    language: tuple[str, ...],
    severity: str,
    skip_verify: bool,
    max_results: int,
    max_verifications: int,
    timeout: int,
    json_output: bool,
) -> None:
    """Run all three phases: Hunt -> Verify -> Remediate."""
    config = get_config()

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

    if json_output:
        output = {
            "findings": serialize_models(findings),
            "verified": serialize_models(verified),
            "guidance": serialize_models(guidance),
            "hunt_stats": serialize_model(hunt_stats),
            "verify_stats": serialize_model(verify_stats) if verify_stats else None,
            "remediate_stats": serialize_model(remediate_stats) if remediate_stats else None,
            "total_count": total_count,
            "has_more": has_more,
        }
        click.echo(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        click.echo("\n=== RESULTS ===", err=False)
        confirmed = [v for v in verified if v.verification_status == "confirmed"]
        likely = [v for v in verified if v.verification_status == "likely"]
        click.echo(f"Total findings: {total_count}", err=False)
        click.echo(f"Confirmed: {len(confirmed)}", err=False)
        click.echo(f"Likely: {len(likely)}", err=False)
        click.echo(f"Guidance items: {len(guidance)}", err=False)


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
