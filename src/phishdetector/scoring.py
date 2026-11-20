"""Weighted heuristic score aggregation."""

from phishdetector.models import Finding


def calculate_score(findings: list[Finding]) -> tuple[int, str]:
    """Sum positive finding weights, clamp to 0–100, and assign a score band."""
    score = min(100, sum(max(0, finding.weight) for finding in findings))
    if score <= 24:
        severity = "low"
    elif score <= 49:
        severity = "guarded"
    elif score <= 74:
        severity = "high"
    else:
        severity = "critical"
    return score, severity
