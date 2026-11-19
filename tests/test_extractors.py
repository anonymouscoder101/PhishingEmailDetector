"""Tests for extract_urls: text and HTML links, normalization, and hostile input."""

from pathlib import Path

import pytest

from phishdetector.extractors import MAX_URLS, extract_urls
from phishdetector.models import ExtractedUrl, ParsedEmail
from phishdetector.parser import parse_email

FIXTURES = Path(__file__).parent / "fixtures"


def from_text(*parts: str) -> list[ExtractedUrl]:
    return extract_urls(ParsedEmail(text_parts=list(parts)))


def from_html(*parts: str) -> list[ExtractedUrl]:
    return extract_urls(ParsedEmail(html_parts=list(parts)))


def originals(urls: list[ExtractedUrl]) -> list[str]:
    return [url.original for url in urls]


# --- plain text ------------------------------------------------------------


def test_plain_text_url() -> None:
    [url] = from_text("Visit https://example.com/login now")

    assert url == ExtractedUrl(
        original="https://example.com/login",
        normalized="https://example.com/login",
        host="example.com",
        source="text",
        visible_text=None,
    )


def test_trailing_punctuation_is_trimmed() -> None:
    urls = from_text("See https://example.com/a. Or https://example.com/b, or https://example.com/c!")

    assert originals(urls) == ["https://example.com/a", "https://example.com/b", "https://example.com/c"]


def test_parentheses_are_balanced() -> None:
    urls = from_text("(see https://example.com/a) and https://wiki.example.com/Foo_(bar)")

    assert originals(urls) == ["https://example.com/a", "https://wiki.example.com/Foo_(bar)"]


def test_only_http_and_https_are_extracted() -> None:
    assert from_text("ftp://example.com mailto:a@example.com www.example.com") == []


def test_scheme_and_host_are_lowercased_only() -> None:
    [url] = from_text("HTTPS://Example.COM/Path?Q=Yes")

    assert url.original == "HTTPS://Example.COM/Path?Q=Yes"
    assert url.normalized == "https://example.com/Path?Q=Yes"
    assert url.host == "example.com"


def test_host_excludes_port_and_user_info() -> None:
    [url] = from_text("http://User:Secret@Evil.test:8080/x")

    assert url.host == "evil.test"
    assert url.normalized == "http://User:Secret@evil.test:8080/x"


def test_ip_literal_host() -> None:
    [url] = from_text("http://192.168.0.1/login")

    assert url.host == "192.168.0.1"


def test_punycode_and_unicode_hosts_are_kept_as_written() -> None:
    punycode, unicode_host = from_text("https://xn--pple-43d.com/ https://аpple.com/")

    assert punycode.host == "xn--pple-43d.com"
    assert unicode_host.host == "аpple.com"  # Cyrillic "а", not converted to xn--


def test_backslash_is_treated_like_a_slash() -> None:
    [url] = from_text("http://evil.test\\@good.example.com/")

    assert url.host == "evil.test"


# --- HTML ------------------------------------------------------------------


def test_html_href_with_visible_text() -> None:
    [url] = from_html('<a href="https://evil.test/login">https://bank.example.com</a>')

    assert url.source == "html_href"
    assert url.host == "evil.test"
    assert url.visible_text == "https://bank.example.com"


def test_html_entities_in_href_are_decoded() -> None:
    [url] = from_html('<a href="https://example.com/?a=1&amp;b=2">link</a>')

    assert url.original == "https://example.com/?a=1&b=2"


def test_visible_text_whitespace_is_collapsed() -> None:
    [url] = from_html('<a href="https://example.com/">\n  Click\n  <b>here</b>  </a>')

    assert url.visible_text == "Click here"


def test_image_only_link_has_no_visible_text() -> None:
    [url] = from_html('<a href="https://example.com/"><img src="logo.png"></a>')

    assert url.visible_text is None


def test_non_http_hrefs_are_ignored() -> None:
    html = (
        '<a href="mailto:a@example.com">mail</a>'
        '<a href="javascript:alert(1)">js</a>'
        '<a href="/relative">rel</a>'
        '<a href="#top">top</a>'
        "<a>no href</a>"
    )
    assert from_html(html) == []


def test_href_whitespace_and_case_are_cleaned() -> None:
    [url] = from_html('<a href="  HTTPS://Example.com/x\n">x</a>')

    assert url.normalized == "https://example.com/x"
    assert url.host == "example.com"


def test_bare_url_in_html_text() -> None:
    urls = from_html("<p>Go to https://example.com/page</p>")

    assert [(url.original, url.source) for url in urls] == [("https://example.com/page", "html_text")]


def test_url_used_as_link_text_is_not_also_reported_as_html_text() -> None:
    urls = from_html('<a href="https://evil.test/">https://bank.example.com/</a>')

    assert [url.source for url in urls] == ["html_href"]


def test_script_and_style_text_is_ignored() -> None:
    html = "<style>a { background: url(https://style.example.com/) }</style><script>x='https://js.example.com/'</script>"
    assert from_html(html) == []


def test_malformed_html_does_not_crash() -> None:
    urls = from_html("<a href='https://example.com/'>unclosed <div <<>> <a href=\"https://second.example.com/\">")

    assert [url.host for url in urls] == ["example.com", "second.example.com"]


def test_unclosed_anchor_keeps_its_text() -> None:
    [url] = from_html('<a href="https://example.com/">Sign in')

    assert url.visible_text == "Sign in"


# --- duplicates --------------------------------------------------------------


def test_duplicate_text_urls_are_reported_once() -> None:
    urls = from_text("https://example.com/a https://example.com/a HTTPS://EXAMPLE.com/a")

    assert originals(urls) == ["https://example.com/a"]


def test_same_href_with_different_text_is_kept() -> None:
    urls = from_html('<a href="https://example.com/">One</a> <a href="https://example.com/">Two</a>')

    assert [url.visible_text for url in urls] == ["One", "Two"]


def test_same_url_in_text_and_html_is_kept_per_source() -> None:
    urls = extract_urls(
        ParsedEmail(
            text_parts=["https://example.com/"],
            html_parts=['<a href="https://example.com/">here</a>'],
        )
    )
    assert [url.source for url in urls] == ["text", "html_href"]


def test_url_count_is_capped() -> None:
    text = " ".join(f"https://example.com/{number}" for number in range(MAX_URLS + 100))

    assert len(from_text(text)) == MAX_URLS


# --- malformed and hostile URLs ----------------------------------------------


@pytest.mark.parametrize("text", ["http://[::1", "https://?q=1", "http://:80/", "http://@/"])
def test_malformed_url_has_no_host(text: str) -> None:
    [url] = from_text(text)

    assert url.host is None


def test_text_url_stops_at_terminal_control_characters() -> None:
    [url] = from_text("https://example.com/\x1b[31mred\x07")

    assert url.original == "https://example.com/"


def test_control_character_in_href_host_gives_no_host() -> None:
    [url] = from_html('<a href="https://exa\x1bmple.com/">x</a>')

    assert url.original == "https://exa\x1bmple.com/"  # kept as evidence; reporting escapes it
    assert url.host is None


def test_empty_email_has_no_urls() -> None:
    assert extract_urls(ParsedEmail()) == []


# --- end to end with the parser -----------------------------------------------


def test_extracts_from_parsed_multipart_fixture() -> None:
    email = parse_email((FIXTURES / "multipart.eml").read_bytes())
    urls = extract_urls(email)

    assert [(url.source, url.original, url.visible_text) for url in urls] == [
        ("text", "https://billing.example.com/invoice/42", None),
        ("html_href", "https://billing.example.com/invoice/42", "ready"),
    ]
    assert not any("attachment.example.com" in url.original for url in urls)
