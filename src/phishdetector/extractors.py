"""Extract URLs from parsed email bodies.

URLs are only inspected as strings: nothing is fetched, resolved, or rendered.
Only http and https URLs are extracted.
"""

import re
import unicodedata
from html.parser import HTMLParser
from urllib.parse import urlsplit

from phishdetector.models import ExtractedUrl, ParsedEmail

MAX_URLS = 500
MAX_VISIBLE_TEXT = 1000

# Stop at whitespace, quotes, angle brackets, and control characters so a URL
# cannot swallow terminal escape sequences that follow it.
_TEXT_URL_RE = re.compile(r"https?://[^\s<>\"'\x00-\x1f\x7f-\x9f]+", re.IGNORECASE)
_HTTP_SCHEME_RE = re.compile(r"https?:", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,;:!?"
_CLOSING_BRACKETS = {")": "(", "]": "[", "}": "{"}
_EDGE_CHARS = "".join(chr(code) for code in range(0x21))  # C0 controls and space


def extract_urls(email: ParsedEmail) -> list[ExtractedUrl]:
    """Return http(s) URLs from text and HTML parts, deduplicated.

    Duplicates are removed on (normalized, source, visible_text), keeping the
    first occurrence. At most MAX_URLS URLs are returned.
    """
    results: list[ExtractedUrl] = []
    seen: set[tuple[str, str, str | None]] = set()

    def add(original: str, source: str, visible_text: str | None = None) -> None:
        if len(results) >= MAX_URLS:
            return
        url = _build_url(original, source, visible_text)
        key = (url.normalized, url.source, url.visible_text)
        if key not in seen:
            seen.add(key)
            results.append(url)

    for text in email.text_parts:
        for original in _find_text_urls(text):
            add(original, "text")

    for html in email.html_parts:
        links, visible_text = _parse_html(html)
        for href, label in links:
            if _HTTP_SCHEME_RE.match(_clean_href(href)):
                add(href, "html_href", label)
        for original in _find_text_urls(visible_text):
            add(original, "html_text")

    return results


def _find_text_urls(text: str) -> list[str]:
    urls = []
    for match in _TEXT_URL_RE.finditer(text):
        url = _trim_trailing(match.group())
        if url:
            urls.append(url)
    return urls


def _trim_trailing(url: str) -> str:
    """Drop sentence punctuation and unbalanced closing brackets at the end."""
    while url:
        last = url[-1]
        if last in _TRAILING_PUNCTUATION:
            url = url[:-1]
        elif last in _CLOSING_BRACKETS and url.count(_CLOSING_BRACKETS[last]) < url.count(last):
            url = url[:-1]
        else:
            break
    return url


def _clean_href(href: str) -> str:
    """Trim the way browsers do: strip edge controls/spaces, drop tabs and newlines."""
    cleaned = href.strip(_EDGE_CHARS)
    return cleaned.replace("\t", "").replace("\n", "").replace("\r", "")


def _build_url(original: str, source: str, visible_text: str | None) -> ExtractedUrl:
    cleaned = _clean_href(original)
    return ExtractedUrl(
        original=original,
        normalized=_normalize(cleaned),
        host=_host(cleaned),
        source=source,
        visible_text=visible_text,
    )


def _normalize(url: str) -> str:
    """Lowercase the scheme and host; leave everything else as written."""
    scheme, _, rest = url.partition(":")
    scheme = scheme.lower()
    if not rest.startswith("//"):
        return f"{scheme}:{rest}"

    after_slashes = rest[2:]
    end = len(after_slashes)
    for delimiter in "/\\?#":
        position = after_slashes.find(delimiter)
        if position != -1:
            end = min(end, position)
    authority, remainder = after_slashes[:end], after_slashes[end:]
    userinfo, at, host_port = authority.rpartition("@")
    return f"{scheme}://{userinfo}{at}{host_port.lower()}{remainder}"


def _host(url: str) -> str | None:
    """Return the lowercase host without port or user-info, or None if unparseable.

    Backslashes are treated as slashes, as browsers do for http(s) URLs, so
    ``http://evil.test\\@good.test`` reports ``evil.test``.
    """
    try:
        host = urlsplit(url.replace("\\", "/")).hostname
    except ValueError:
        return None
    if not host or any(char.isspace() or unicodedata.category(char) == "Cc" for char in host):
        return None
    return host


class _LinkParser(HTMLParser):
    """Collect anchor hrefs with their visible text, plus text outside anchors."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str | None]] = []
        self.text_chunks: list[str] = []
        self._href: str | None = None
        self._label: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._close_anchor()
            self._href = next((value for name, value in attrs if name == "href" and value is not None), None)
        elif tag in ("script", "style"):
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._close_anchor()
        elif tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._href is not None:
            self._label.append(data)
        else:
            self.text_chunks.append(data)

    def finish(self) -> None:
        self._close_anchor()

    def _close_anchor(self) -> None:
        if self._href is not None:
            label = " ".join("".join(self._label).split())[:MAX_VISIBLE_TEXT]
            self.links.append((self._href, label or None))
        self._href = None
        self._label = []


def _parse_html(html: str) -> tuple[list[tuple[str, str | None]], str]:
    parser = _LinkParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass  # keep whatever was collected before the markup broke the parser
    parser.finish()
    return parser.links, "\n".join(parser.text_chunks)
