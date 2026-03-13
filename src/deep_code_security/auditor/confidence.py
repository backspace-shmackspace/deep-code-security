"""Confidence scoring model for vulnerability findings.

The confidence score (0-100) is a weighted composite:
- Taint path completeness: 45%
- Sanitizer absence: 25%
- CWE severity baseline: 20%
- Exploit verification: 10% BONUS ONLY (failed PoC does not penalize)

Formula:
    base = 0.45 * taint + 0.25 * sanitizer + 0.20 * cwe_baseline
    bonus = 0.10 * exploit_score  (only if exploit_score > 0)
    confidence = min(100, base + bonus)

Thresholds:
    >= 75: "confirmed"
    >= 45: "likely"
    >= 20: "unconfirmed"
    <  20: "false_positive"
"""

from __future__ import annotations

from deep_code_security.auditor.models import ExploitResult, VerificationStatus
from deep_code_security.hunter.models import RawFinding, TaintPath

__all__ = [
    "compute_confidence",
    "taint_completeness_score",
    "sanitizer_score",
    "cwe_baseline_score",
    "exploit_bonus_score",
    "confidence_to_status",
]

# CWE severity baseline scores
_CWE_BASELINE: dict[str, float] = {
    "CWE-78": 100.0,   # OS Command Injection — Critical
    "CWE-89": 100.0,   # SQL Injection — Critical
    "CWE-94": 100.0,   # Code Injection — Critical
    "CWE-22": 75.0,    # Path Traversal — High
    "CWE-120": 75.0,   # Buffer Copy without Size Check — High
    "CWE-134": 75.0,   # Uncontrolled Format String — High
    "CWE-79": 75.0,    # Cross-site Scripting — High
    "CWE-676": 50.0,   # Use of Potentially Dangerous Function — Medium
}

# Severity strings to baseline scores
_SEVERITY_BASELINE: dict[str, float] = {
    "critical": 100.0,
    "high": 75.0,
    "medium": 50.0,
    "low": 25.0,
}


def taint_completeness_score(taint_path: TaintPath) -> float:
    """Compute taint path completeness score (0-100).

    Args:
        taint_path: The taint path from source to sink.

    Returns:
        Score: 100 for full path (3+ steps), 50 for partial (2 steps),
               20 for heuristic (1 step / no steps).
    """
    step_count = len(taint_path.steps)
    if step_count >= 3:
        return 100.0
    elif step_count == 2:
        return 50.0
    elif step_count == 1:
        return 30.0
    else:
        # No steps recorded — source/sink in same statement (direct pattern)
        return 20.0


def sanitizer_score(taint_path: TaintPath) -> float:
    """Compute sanitizer absence score (0-100).

    Higher score = less sanitization = more likely to be exploitable.

    Args:
        taint_path: The taint path.

    Returns:
        100 if no sanitizer, 50 if partial sanitizer, 0 if full sanitizer.
    """
    if taint_path.sanitized:
        return 0.0  # Full sanitizer detected — low risk
    return 100.0   # No sanitizer detected — high risk


def cwe_baseline_score(finding: RawFinding) -> float:
    """Compute CWE severity baseline score (0-100).

    Args:
        finding: The raw finding with vulnerability_class and severity.

    Returns:
        Baseline score based on CWE and severity.
    """
    # Try to extract CWE from vulnerability_class (e.g., "CWE-78: OS Command Injection")
    vuln_class = finding.vulnerability_class
    for cwe, score in _CWE_BASELINE.items():
        if cwe in vuln_class:
            return score

    # Fall back to severity
    return _SEVERITY_BASELINE.get(finding.severity.lower(), 50.0)


def exploit_bonus_score(exploit_results: list[ExploitResult]) -> float:
    """Compute exploit verification bonus score (0-100).

    BONUS ONLY: A successful exploit adds up to 100 (scaled by 10% weight).
    A failed exploit adds 0 (no penalty).

    Args:
        exploit_results: Results from sandbox exploit attempts.

    Returns:
        100.0 if any exploit succeeded, 0.0 otherwise.
    """
    if not exploit_results:
        return 0.0

    # Any successful exploit adds the bonus
    if any(r.exploitable for r in exploit_results):
        return 100.0

    # All failed or timed out — no penalty, return 0
    return 0.0


def compute_confidence(
    finding: RawFinding,
    exploit_results: list[ExploitResult],
) -> tuple[int, VerificationStatus]:
    """Compute the final confidence score and verification status.

    Uses the bonus-only scoring model:
        base = 0.45 * taint + 0.25 * sanitizer + 0.20 * cwe_baseline
        bonus = 0.10 * exploit_score (only if > 0, never penalizes)
        confidence = min(100, int(base + bonus))

    Args:
        finding: The raw finding with taint path and metadata.
        exploit_results: Results from sandbox exploit attempts.

    Returns:
        Tuple of (confidence_score, verification_status).
    """
    # Component scores (0-100 each)
    taint = taint_completeness_score(finding.taint_path)
    sanitizer = sanitizer_score(finding.taint_path)
    cwe_baseline = cwe_baseline_score(finding)
    exploit = exploit_bonus_score(exploit_results)

    # Weighted base score
    base = (0.45 * taint) + (0.25 * sanitizer) + (0.20 * cwe_baseline)

    # Exploit is bonus-only: adds 10% if exploit succeeded, 0 otherwise
    bonus = 0.10 * exploit if exploit > 0 else 0.0

    raw_score = base + bonus
    confidence = min(100, int(round(raw_score)))

    status = confidence_to_status(confidence)
    return confidence, status


def confidence_to_status(score: int) -> VerificationStatus:
    """Convert a confidence score to a verification status string.

    Thresholds:
        >= 75: confirmed
        >= 45: likely
        >= 20: unconfirmed
        <  20: false_positive

    Args:
        score: Confidence score (0-100).

    Returns:
        VerificationStatus string.
    """
    if score >= 75:
        return "confirmed"
    elif score >= 45:
        return "likely"
    elif score >= 20:
        return "unconfirmed"
    else:
        return "false_positive"
