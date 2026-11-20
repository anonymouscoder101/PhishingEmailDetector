"""Tests for stable JSON and terminal-safe text output."""

import json

from phishdetector.models import AnalysisReport, Finding, ParsedEmail, ExtractedUrl
from phishdetector.reporting import build_report, render_json, render_text


def test_build_report_uses_shared_schema_and_preserves_warnings() -> None:
    email = ParsedEmail(parse_warnings=["limited extraction"])
    url = ExtractedUrl("https://example.test/", "https://example.test/", "example.test", "text")

    report = build_report(email, [url], [])

    assert report.schema_version == "1"
    assert report.score == 0
    assert report.severity == "low"
    assert report.urls == ["https://example.test/"]
    assert report.parse_warnings == ["limited extraction"]


def test_json_has_stable_fields_and_is_valid_json() -> None:
    report = AnalysisReport(
        "1", 25, "guarded",
        [Finding("header.reply_to_mismatch", "medium", 20, "Reply-To differs", {"reply_to_domain": "bad.test"})],
        ["https://bad.test/"],
        [],
    )

    rendered = render_json(report)
    parsed = json.loads(rendered)

    assert list(parsed) == ["schema_version", "score", "severity", "findings", "urls", "parse_warnings"]
    assert list(parsed["findings"][0]) == ["id", "severity", "weight", "message", "evidence"]
    assert parsed["schema_version"] == "1"
    assert rendered.endswith("\n")


def test_text_output_escapes_controls_truncates_values_and_disclaims_certainty() -> None:
    report = AnalysisReport(
        "1", 25, "guarded",
        [Finding("url.ip_literal", "high", 25, "IP literal host", {"url": "https://evil.test/\x1b[2J" + ("x" * 300)})],
        ["https://evil.test/\x1b[2J" + ("x" * 400)],
        ["parser warning\x1b[31m"],
    )

    rendered = render_text(report)

    assert "\x1b" not in rendered
    assert "\\x1b" in rendered
    assert "Heuristic triage score; not a probability." in rendered
    assert "A low score does not establish safety." in rendered
    assert len(rendered) < 1500
