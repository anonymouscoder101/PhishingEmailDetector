"""End-to-end fixture outcomes: parse -> extract -> rules -> report.

These pin which rule IDs each fixture triggers. They check rule IDs as sets,
not exact scores or counts, so weight tuning and duplicate-finding changes do
not break them. The fixtures are behavior checks, not an accuracy benchmark.
"""

import json
from pathlib import Path

import pytest

from phishdetector.extractors import extract_urls
from phishdetector.models import AnalysisReport
from phishdetector.parser import parse_email
from phishdetector.reporting import build_report, render_json
from phishdetector.rules import RULE_WEIGHTS, evaluate_rules

FIXTURES = Path(__file__).parent / "fixtures"


def analyze(name: str) -> AnalysisReport:
    email = parse_email((FIXTURES / name).read_bytes())
    urls = extract_urls(email)
    return build_report(email, urls, evaluate_rules(email, urls))


def rule_ids(report: AnalysisReport) -> set[str]:
    return {finding.id for finding in report.findings}


@pytest.mark.parametrize(
    ("name", "expected_rules"),
    [
        ("simple.eml", set()),
        ("multipart.eml", set()),
        ("missing_headers.eml", set()),
        ("malformed_mime.eml", set()),
        ("repeated_headers.eml", {"auth.dkim_fail"}),
        ("suspicious.eml", set(RULE_WEIGHTS)),
    ],
)
def test_fixture_triggers_expected_rules(name: str, expected_rules: set[str]) -> None:
    assert rule_ids(analyze(name)) == expected_rules


def test_suspicious_fixture_scores_critical() -> None:
    report = analyze("suspicious.eml")

    assert report.severity == "critical"
    assert report.parse_warnings == []


def test_suspicious_fixture_evidence_points_at_the_right_values() -> None:
    evidence = {finding.id: finding.evidence for finding in analyze("suspicious.eml").findings}

    assert evidence["header.reply_to_mismatch"] == {
        "from_domain": "example-bank.test",
        "reply_to_domain": "collector.test",
    }
    assert evidence["url.ip_literal"] == {"host": "192.0.2.10"}
    assert evidence["url.visible_text_mismatch"] == {
        "visible_host": "www.example-bank.test",
        "destination_host": "192.0.2.10",
    }
    assert evidence["url.userinfo"]["url"] == "https://www.example-bank.test@login.collector.test/"
    assert evidence["url.punycode"] == {"host": "xn--xample-bank-9db.test"}
    assert evidence["url.excessive_subdomains"]["host"] == "secure.login.account.verify.collector.test"
    assert evidence["url.shortener"] == {"host": "bit.ly"}


def test_userinfo_host_is_the_real_destination() -> None:
    email = parse_email((FIXTURES / "suspicious.eml").read_bytes())
    hosts = {url.host for url in extract_urls(email)}

    assert "login.collector.test" in hosts
    assert "www.example-bank.test" not in hosts  # the user-info decoy is not reported as a host


@pytest.mark.parametrize("name", sorted(path.name for path in FIXTURES.glob("*.eml")))
def test_every_fixture_renders_valid_versioned_json(name: str) -> None:
    payload = json.loads(render_json(analyze(name)))

    assert payload["schema_version"] == "1"
    assert 0 <= payload["score"] <= 100
