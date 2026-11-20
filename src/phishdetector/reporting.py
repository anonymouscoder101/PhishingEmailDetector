"""Construct and render stable analysis reports."""

import json

from phishdetector.models import (
    SCHEMA_VERSION,
    AnalysisReport,
    ExtractedUrl,
    Finding,
    ParsedEmail,
)
from phishdetector.scoring import calculate_score

MAX_TEXT_VALUE_LENGTH = 240


def build_report(
    email: ParsedEmail,
    urls: list[ExtractedUrl],
    findings: list[Finding],
) -> AnalysisReport:
    """Build the stable report model from analysis results."""
    score, severity = calculate_score(findings)
    return AnalysisReport(
        schema_version=SCHEMA_VERSION,
        score=score,
        severity=severity,
        findings=list(findings),
        # The extractor keeps repeated links (needed for the visible-text rule);
        # list each distinct URL once in the report.
        urls=list(dict.fromkeys(url.original for url in urls)),
        parse_warnings=list(email.parse_warnings),
    )


def render_json(report: AnalysisReport) -> str:
    """Serialize a report with stable field order and JSON-safe strings."""
    payload = {
        "schema_version": report.schema_version,
        "score": report.score,
        "severity": report.severity,
        "findings": [
            {
                "id": finding.id,
                "severity": finding.severity,
                "weight": finding.weight,
                "message": finding.message,
                "evidence": {key: finding.evidence[key] for key in sorted(finding.evidence)},
            }
            for finding in report.findings
        ],
        "urls": report.urls,
        "parse_warnings": report.parse_warnings,
    }
    # ensure_ascii=True escapes every non-ASCII character, including invisible
    # C1 controls (such as \x9b) and bidi overrides, so printing the JSON to a
    # terminal cannot be manipulated by message content.
    return json.dumps(payload, ensure_ascii=True, indent=2) + "\n"


def render_text(report: AnalysisReport) -> str:
    """Render a terminal-safe summary; evidence never controls terminal output."""
    lines = [
        "Phishing email analysis (heuristic)",
        f"Risk score: {report.score}/100 ({_safe_text(report.severity)})",
        "Heuristic triage score; not a probability.",
        "A low score does not establish safety.",
        "",
        "Findings:",
    ]
    if report.findings:
        for finding in report.findings:
            lines.append(
                f"- [{_safe_text(finding.severity)}] {_safe_text(finding.message)} "
                f"(id: {_safe_text(finding.id)}, weight: {finding.weight})"
            )
            for key in sorted(finding.evidence):
                lines.append(f"    {_safe_text(key)}: {_safe_text(finding.evidence[key])}")
    else:
        lines.append("- No signals detected by these rules.")

    lines.extend(("", "Extracted URLs:"))
    if report.urls:
        lines.extend(f"- {_safe_text(url)}" for url in report.urls)
    else:
        lines.append("- None")

    lines.extend(("", "Parse warnings:"))
    if report.parse_warnings:
        lines.extend(f"- {_safe_text(warning)}" for warning in report.parse_warnings)
    else:
        lines.append("- None")
    return "\n".join(lines) + "\n"


def _safe_text(value: str) -> str:
    """Escape terminal controls and bound output from untrusted message data."""
    escaped = "".join(_escape_control(char) for char in str(value))
    if len(escaped) > MAX_TEXT_VALUE_LENGTH:
        return escaped[: MAX_TEXT_VALUE_LENGTH - 1] + "…"
    return escaped


def _escape_control(char: str) -> str:
    codepoint = ord(char)
    if char.isprintable():
        return char
    if codepoint <= 0xFF:
        return f"\\x{codepoint:02x}"
    return f"\\u{codepoint:04x}"
