"""Deterministic, explainable checks for common phishing indicators.

Weights are initial triage heuristics, not calibrated probabilities. The
reported Authentication-Results header is attacker-controlled and may not
have been added by a trusted receiving system.
"""

import ipaddress
import re
from email.utils import getaddresses
from urllib.parse import urlsplit

from phishdetector.models import ExtractedUrl, Finding, ParsedEmail

# Initial weights are deliberately moderate so a single weak signal does not
# dominate the report. Multiple independent findings are additive in scoring.
RULE_WEIGHTS = {
    "header.reply_to_mismatch": 20,
    "auth.spf_fail": 10,
    "auth.dkim_fail": 10,
    "auth.dmarc_fail": 15,
    "url.ip_literal": 25,
    "url.userinfo": 25,
    "url.punycode": 15,
    "url.excessive_subdomains": 10,
    "url.shortener": 8,
    "url.visible_text_mismatch": 20,
}

MAX_SUBDOMAINS = 3
MAX_EVIDENCE_LENGTH = 180
SHORTENER_DOMAINS = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly"}
)
_AUTH_FAILURE_RE = re.compile(r"(?<![a-z0-9_-])(spf|dkim|dmarc)\s*=\s*(fail)(?![a-z0-9_-])", re.IGNORECASE)


def evaluate_rules(email: ParsedEmail, urls: list[ExtractedUrl]) -> list[Finding]:
    """Return stable, ordered findings for header and URL signals."""
    findings: list[Finding] = []
    mismatch = _from_reply_to_mismatch(email)
    if mismatch:
        from_domain, reply_to_domain = mismatch
        findings.append(
            _finding(
                "header.reply_to_mismatch",
                "medium",
                "Reply-To domain differs from From domain",
                {"from_domain": from_domain, "reply_to_domain": reply_to_domain},
            )
        )

    findings.extend(_authentication_findings(email))
    for url in urls:
        findings.extend(_url_findings(url))
    return findings


def _from_reply_to_mismatch(email: ParsedEmail) -> tuple[str, str] | None:
    from_domain = _first_domain(email.headers.get("from", []))
    reply_to_domain = _first_domain(email.headers.get("reply-to", []))
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        return from_domain, reply_to_domain
    return None


def _first_domain(values: list[str]) -> str | None:
    if not values:
        return None
    addresses = getaddresses(values)
    for _, address in addresses:
        _, separator, domain = address.rpartition("@")
        domain = domain.strip().rstrip(".").casefold()
        if separator and domain and not any(char.isspace() or ord(char) < 32 for char in domain):
            return _safe_evidence(domain)
    return None


def _authentication_findings(email: ParsedEmail) -> list[Finding]:
    results: dict[str, str] = {}
    for value in email.headers.get("authentication-results", []):
        for match in _AUTH_FAILURE_RE.finditer(value):
            mechanism, result = match.group(1).lower(), match.group(2).lower()
            results.setdefault(mechanism, result)

    findings = []
    for mechanism in ("spf", "dkim", "dmarc"):
        if mechanism not in results:
            continue
        rule_id = f"auth.{mechanism}_fail"
        findings.append(
            _finding(
                rule_id,
                "medium",
                f"Authentication-Results reports {mechanism.upper()} failure (header is untrusted)",
                {"mechanism": mechanism.upper(), "reported_result": results[mechanism]},
            )
        )
    return findings


def _url_findings(url: ExtractedUrl) -> list[Finding]:
    host = (url.host or "").rstrip(".").casefold()
    if not host:
        return []

    findings: list[Finding] = []
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        findings.append(_finding("url.ip_literal", "high", "URL uses an IP-literal host", {"host": host}))

    if _has_userinfo(url.original):
        findings.append(_finding("url.userinfo", "high", "URL contains user-info before its host", {"url": url.original}))

    labels = host.split(".")
    if any(label.startswith("xn--") for label in labels) or any(not label.isascii() for label in labels):
        findings.append(_finding("url.punycode", "medium", "URL host contains a punycode or non-ASCII label", {"host": host}))

    subdomains = labels[:-2] if len(labels) > 2 else []
    if len(subdomains) > MAX_SUBDOMAINS:
        findings.append(
            _finding(
                "url.excessive_subdomains",
                "low",
                "URL host has more than three subdomain labels",
                {"host": host, "subdomain_count": str(len(subdomains))},
            )
        )

    if any(host == domain or host.endswith(f".{domain}") for domain in SHORTENER_DOMAINS):
        findings.append(_finding("url.shortener", "low", "URL uses a known shortening domain", {"host": host}))

    visible_host = _visible_host(url.visible_text) if url.source == "html_href" else None
    if visible_host and visible_host != host:
        findings.append(
            _finding(
                "url.visible_text_mismatch",
                "high",
                "Visible link text points to a different host than the destination",
                {"visible_host": visible_host, "destination_host": host},
            )
        )
    return findings


def _has_userinfo(url: str) -> bool:
    try:
        # Normalize backslashes as browsers do when interpreting special URLs.
        authority = urlsplit(url.replace("\\", "/")).netloc
    except ValueError:
        return False
    return "@" in authority


def _visible_host(text: str | None) -> str | None:
    if not text:
        return None
    candidate = text.strip()
    try:
        parsed = urlsplit(candidate if "://" in candidate else f"http://{candidate}")
        host = parsed.hostname
    except ValueError:
        return None
    if not host or "." not in host or any(char.isspace() or ord(char) < 32 for char in host):
        return None
    return host.rstrip(".").casefold()


def _finding(rule_id: str, severity: str, message: str, evidence: dict[str, str]) -> Finding:
    return Finding(
        id=rule_id,
        severity=severity,
        weight=RULE_WEIGHTS[rule_id],
        message=message,
        evidence={key: _safe_evidence(value) for key, value in evidence.items()},
    )


def _safe_evidence(value: str) -> str:
    """Escape controls and bound untrusted values before retaining evidence."""
    escaped = "".join(_escape_control(char) for char in str(value))
    if len(escaped) > MAX_EVIDENCE_LENGTH:
        return escaped[: MAX_EVIDENCE_LENGTH - 1] + "…"
    return escaped


def _escape_control(char: str) -> str:
    codepoint = ord(char)
    if char.isprintable():
        return char
    if codepoint <= 0xFF:
        return f"\\x{codepoint:02x}"
    return f"\\u{codepoint:04x}"
