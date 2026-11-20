"""Behavioral tests for explainable signal rules."""

from phishdetector.models import ExtractedUrl, ParsedEmail
from phishdetector.rules import evaluate_rules


def finding_ids(email: ParsedEmail, urls: list[ExtractedUrl]) -> set[str]:
    return {finding.id for finding in evaluate_rules(email, urls)}


def test_reply_to_domain_mismatch_is_reported() -> None:
    email = ParsedEmail(headers={"from": ["Billing <billing@example.com>"], "reply-to": ["help@attacker.test"]})

    findings = evaluate_rules(email, [])

    assert len(findings) == 1
    assert findings[0].id == "header.reply_to_mismatch"
    assert findings[0].evidence == {"from_domain": "example.com", "reply_to_domain": "attacker.test"}


def test_authentication_failures_are_reported_individually() -> None:
    email = ParsedEmail(headers={"authentication-results": ["mx.test; spf=fail smtp.mailfrom=x.test; dkim=pass; dmarc=fail header.from=x.test"]})

    assert finding_ids(email, []) == {"auth.spf_fail", "auth.dmarc_fail"}


def test_missing_authentication_results_are_unknown() -> None:
    assert evaluate_rules(ParsedEmail(), []) == []


def test_url_structure_rules_cover_ip_userinfo_punycode_subdomains_and_shorteners() -> None:
    urls = [
        ExtractedUrl("http://192.0.2.4/login", "http://192.0.2.4/login", "192.0.2.4", "text"),
        ExtractedUrl("http://name@safe.test/", "http://name@safe.test/", "safe.test", "text"),
        ExtractedUrl("https://xn--bcher-kva.test/", "https://xn--bcher-kva.test/", "xn--bcher-kva.test", "text"),
        ExtractedUrl("https://a.b.c.d.example.test/", "https://a.b.c.d.example.test/", "a.b.c.d.example.test", "text"),
        ExtractedUrl("https://sub.bit.ly/abc", "https://sub.bit.ly/abc", "sub.bit.ly", "text"),
    ]

    assert finding_ids(ParsedEmail(), urls) == {
        "url.ip_literal",
        "url.userinfo",
        "url.punycode",
        "url.excessive_subdomains",
        "url.shortener",
    }


def test_visible_domain_mismatch_is_reported_but_matching_label_is_not() -> None:
    urls = [
        ExtractedUrl("https://phish.test/login", "https://phish.test/login", "phish.test", "html_href", "https://bank.test/sign-in"),
        ExtractedUrl("https://bank.test/", "https://bank.test/", "bank.test", "html_href", "bank.test"),
    ]

    findings = evaluate_rules(ParsedEmail(), urls)

    assert [finding.id for finding in findings] == ["url.visible_text_mismatch"]
    assert findings[0].evidence == {"visible_host": "bank.test", "destination_host": "phish.test"}


def test_rule_evidence_is_bounded_and_contains_no_control_characters() -> None:
    hostile_url = "https://bad.test/" + ("x" * 2000) + "\x1b[2J"
    findings = evaluate_rules(
        ParsedEmail(),
        [ExtractedUrl(hostile_url, hostile_url, "192.0.2.10", "text")],
    )

    for finding in findings:
        for value in finding.evidence.values():
            assert len(value) <= 200
            assert not any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value)
