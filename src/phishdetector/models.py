"""Shared data models for the phishdetector pipeline.

These dataclasses are the contract between parsing/extraction (Person A) and
rules/scoring/reporting (Person B). Change a field only with both partners'
agreement, and update both sides' tests in the same change.
"""

from dataclasses import dataclass, field

SCHEMA_VERSION = "1"
DEFAULT_MAX_BYTES = 10 * 1024 * 1024


class InputTooLargeError(ValueError):
    """Raised by ``parse_email`` when input exceeds ``max_bytes``.

    This is the only error ``parse_email`` raises. Malformed content is
    reported through ``ParsedEmail.parse_warnings`` instead.
    """

    def __init__(self, size: int, max_bytes: int) -> None:
        super().__init__(f"input is {size} bytes; limit is {max_bytes} bytes")
        self.size = size
        self.max_bytes = max_bytes


@dataclass
class ParsedEmail:
    """A normalized email message.

    ``headers`` keys are lowercase header names (for example ``"reply-to"``).
    Each value list holds that header's decoded values in file order, so
    repeated headers are preserved. Address parsing (such as From/Reply-To
    domains) is left to the rules, using ``email.utils.getaddresses``.
    """

    headers: dict[str, list[str]] = field(default_factory=dict)
    text_parts: list[str] = field(default_factory=list)
    html_parts: list[str] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)


@dataclass
class ExtractedUrl:
    """A URL found in the message body. It is never fetched or resolved.

    ``original`` is the URL exactly as found, kept for evidence. ``host`` is
    ``None`` when the URL cannot be parsed. ``source`` records where the URL
    was found. ``visible_text`` is the link label for HTML anchors, otherwise
    ``None``.
    """

    original: str
    normalized: str
    host: str | None
    source: str
    visible_text: str | None = None


@dataclass
class Finding:
    """One rule result, with the evidence behind it."""

    id: str
    severity: str
    weight: int
    message: str
    evidence: dict[str, str] = field(default_factory=dict)


@dataclass
class AnalysisReport:
    """The complete analysis result, independent of output format."""

    schema_version: str
    score: int
    severity: str
    findings: list[Finding] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)
