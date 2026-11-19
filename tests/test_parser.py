"""Tests for parse_email: headers, MIME bodies, malformed input, and size limits."""

from pathlib import Path

import pytest

from phishdetector.models import DEFAULT_MAX_BYTES, InputTooLargeError, ParsedEmail
from phishdetector.parser import MAX_WARNINGS, parse_email

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


# --- simple messages and headers -------------------------------------------


def test_simple_message() -> None:
    email = parse_email(load("simple.eml"))

    assert email.headers["from"] == ["Alice Example <alice@example.com>"]
    assert email.headers["subject"] == ["Lunch on Friday"]
    assert len(email.text_parts) == 1
    assert "lunch on Friday" in email.text_parts[0]
    assert email.html_parts == []
    assert email.parse_warnings == []


def test_header_keys_are_lowercase() -> None:
    email = parse_email(b"FROM: a@example.com\r\nReply-TO: b@other.test\r\n\r\nhi")

    assert email.headers["from"] == ["a@example.com"]
    assert email.headers["reply-to"] == ["b@other.test"]
    assert "FROM" not in email.headers


def test_encoded_header_is_decoded() -> None:
    email = parse_email(b"Subject: =?utf-8?q?Caf=C3=A9_menu?=\r\n\r\nhi")

    assert email.headers["subject"] == ["Café menu"]


def test_folded_header_is_unfolded() -> None:
    email = parse_email(b"Subject: first line\r\n second line\r\n\r\nhi")

    assert email.headers["subject"] == ["first line second line"]


def test_undecodable_header_bytes_do_not_crash() -> None:
    email = parse_email(b"Subject: caf\xe9\r\n\r\nhi")

    subject = email.headers["subject"][0]
    assert subject.startswith("caf")
    subject.encode("utf-8")  # no lone surrogates left behind


def test_repeated_headers_preserved_in_file_order() -> None:
    email = parse_email(load("repeated_headers.eml"))

    received = email.headers["received"]
    assert len(received) == 3
    assert received[0].startswith("from relay2.example.com")
    assert received[2].startswith("from sender.example.net")
    assert email.headers["authentication-results"] == [
        "mx.example.com; spf=pass smtp.mailfrom=example.net",
        "mx.example.com; dkim=fail header.d=example.net",
    ]


def test_missing_headers_are_absent() -> None:
    email = parse_email(load("missing_headers.eml"))

    assert list(email.headers) == ["subject"]
    assert "from" not in email.headers
    assert "reply-to" not in email.headers
    assert email.text_parts == ["This message has no From, To, Date, or Content-Type header.\n"]


# --- MIME bodies -----------------------------------------------------------


def test_multipart_text_and_html() -> None:
    email = parse_email(load("multipart.eml"))

    assert len(email.text_parts) == 1
    assert "https://billing.example.com/invoice/42" in email.text_parts[0]
    assert len(email.html_parts) == 1
    # Quoted-printable is decoded: =3D becomes "=" and the soft line break is joined.
    assert '<a href="https://billing.example.com/invoice/42">ready</a>.' in email.html_parts[0]
    assert email.parse_warnings == []


def test_attachments_are_skipped() -> None:
    email = parse_email(load("multipart.eml"))

    all_text = "".join(email.text_parts + email.html_parts)
    assert "ATTACHMENT-CONTENT-MARKER" not in all_text
    assert "JVBERi0" not in all_text


def test_base64_body_is_decoded() -> None:
    data = (
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"aGVsbG8gd29ybGQ=\r\n"
    )
    assert parse_email(data).text_parts == ["hello world"]


def test_declared_charset_is_used() -> None:
    data = b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\ncaf\xe9"
    email = parse_email(data)

    assert email.text_parts == ["café"]
    assert email.parse_warnings == []


# --- charset fallback ------------------------------------------------------


def test_unknown_charset_falls_back_to_utf8() -> None:
    data = b'Content-Type: text/plain; charset="x-not-a-charset"\r\n\r\nhello'
    email = parse_email(data)

    assert email.text_parts == ["hello"]
    assert any("unknown charset" in warning for warning in email.parse_warnings)


def test_invalid_bytes_for_declared_charset_are_replaced() -> None:
    data = b"Content-Type: text/plain; charset=utf-8\r\n\r\ncaf\xe9"
    email = parse_email(data)

    assert email.text_parts == ["caf�"]
    assert any("invalid for declared charset" in warning for warning in email.parse_warnings)


def test_no_charset_and_invalid_utf8_is_replaced() -> None:
    email = parse_email(b"Subject: x\r\n\r\ncaf\xe9")

    assert email.text_parts == ["caf�"]
    assert any("not valid UTF-8" in warning for warning in email.parse_warnings)


def test_non_text_codec_as_charset_does_not_crash() -> None:
    data = b"Content-Type: text/plain; charset=rot13\r\n\r\nhello"
    email = parse_email(data)

    assert email.text_parts == ["hello"]
    assert email.parse_warnings


# --- malformed input -------------------------------------------------------


def test_malformed_mime_reports_defects() -> None:
    email = parse_email(load("malformed_mime.eml"))

    assert email.headers["subject"] == ["Malformed MIME"]
    assert "defect: StartBoundaryNotFoundDefect" in email.parse_warnings


def test_missing_header_body_separator_reports_defect() -> None:
    email = parse_email(b"this line has no colon\r\nSubject: x\r\n\r\nbody")

    assert "defect: MissingHeaderBodySeparatorDefect" in email.parse_warnings


def test_bad_base64_padding_reports_defect() -> None:
    data = (
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"aGVsbG8\r\n"
    )
    email = parse_email(data)

    assert email.text_parts == ["hello"]
    assert "defect: InvalidBase64PaddingDefect" in email.parse_warnings


@pytest.mark.parametrize(
    "data",
    [
        b"",
        bytes(range(256)) * 4,
        b"\r\n\r\n\r\n",
        b"Content-Type: multipart/mixed\r\n\r\nno boundary parameter",
        b"Content-Type: text/html\r\n\r\n<a href='https://example.com'>unclosed <div <<>>",
    ],
)
def test_garbage_input_does_not_crash(data: bytes) -> None:
    assert isinstance(parse_email(data), ParsedEmail)


def test_deeply_nested_mime_is_bounded() -> None:
    depth = 60
    data = b"".join(
        b'Content-Type: multipart/mixed; boundary="b%d"\r\n\r\n--b%d\r\n' % (level, level)
        for level in range(depth)
    )
    data += b"Content-Type: text/plain\r\n\r\ninnermost\r\n"
    email = parse_email(data)

    assert "MIME nesting too deep; inner parts skipped" in email.parse_warnings
    assert email.text_parts == []


def test_warnings_never_contain_body_text() -> None:
    email = parse_email(load("malformed_mime.eml"))

    assert email.parse_warnings
    assert not any("SECRET-BODY-TOKEN" in warning for warning in email.parse_warnings)


def test_warnings_are_capped() -> None:
    parts = b"".join(
        b'--b\r\nContent-Type: text/plain; charset="x-bad-%d"\r\n\r\nhi\r\n' % number
        for number in range(30)
    )
    data = b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n' + parts + b"--b--\r\n"
    email = parse_email(data)

    assert len(email.parse_warnings) == MAX_WARNINGS
    assert email.parse_warnings[-1].endswith("more warnings omitted")
    assert len(email.text_parts) == 30


# --- size limit ------------------------------------------------------------


def test_input_at_limit_is_accepted() -> None:
    assert isinstance(parse_email(b"x" * 10, max_bytes=10), ParsedEmail)


def test_input_over_limit_raises() -> None:
    with pytest.raises(InputTooLargeError) as exc_info:
        parse_email(b"x" * 11, max_bytes=10)

    assert exc_info.value.size == 11
    assert exc_info.value.max_bytes == 10


def test_default_limit_is_10_mib() -> None:
    data = b"Subject: big\r\n\r\n" + b"a" * DEFAULT_MAX_BYTES

    with pytest.raises(InputTooLargeError):
        parse_email(data)
