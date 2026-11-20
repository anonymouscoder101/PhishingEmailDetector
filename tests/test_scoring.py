"""Tests for bounded score aggregation and severity bands."""

import pytest

from phishdetector.models import Finding
from phishdetector.scoring import calculate_score


def finding(weight: int) -> Finding:
    return Finding("test", "low", weight, "test")


def test_empty_findings_have_zero_low_score() -> None:
    assert calculate_score([]) == (0, "low")


def test_positive_weights_are_additive() -> None:
    assert calculate_score([finding(10), finding(15)]) == (25, "guarded")


def test_scores_are_capped_at_100() -> None:
    assert calculate_score([finding(90), finding(30)]) == (100, "critical")


@pytest.mark.parametrize(
    ("points", "severity"),
    [(24, "low"), (25, "guarded"), (49, "guarded"), (50, "high"), (74, "high"), (75, "critical")],
)
def test_exact_severity_boundaries(points: int, severity: str) -> None:
    assert calculate_score([finding(points)]) == (points, severity)


def test_nonpositive_weights_do_not_reduce_the_score() -> None:
    assert calculate_score([finding(12), finding(-100), finding(0)]) == (12, "low")
