"""Parse raw .eml bytes into a normalized ParsedEmail.

The parser only reads text: it never follows links, renders HTML, or opens
attachments. Malformed input produces parse warnings instead of exceptions.
The only error raised is InputTooLargeError for oversized input.
"""

from email import policy
from email.message import Message
from email.parser import BytesParser

from phishdetector.models import DEFAULT_MAX_BYTES, InputTooLargeError, ParsedEmail

MAX_WARNINGS = 20
MAX_PARTS = 1000
MAX_DEPTH = 20

_BODY_TYPES = {"text/plain", "text/html"}


def parse_email(data: bytes, max_bytes: int = DEFAULT_MAX_BYTES) -> ParsedEmail:
    """Parse one RFC 822 message.

    Header keys are lowercase; values are decoded and kept in file order.
    Only text/plain and text/html parts that are not attachments are decoded.
    Warnings are short fixed messages that never include message content.
    """
    if len(data) > max_bytes:
        raise InputTooLargeError(len(data), max_bytes)

    try:
        message = BytesParser(policy=policy.default).parsebytes(data)
    except Exception:
        return ParsedEmail(parse_warnings=["message could not be parsed"])

    warnings: list[str] = []
    headers = _read_headers(message, warnings)
    text_parts, html_parts = _read_bodies(message, warnings)
    return ParsedEmail(
        headers=headers,
        text_parts=text_parts,
        html_parts=html_parts,
        parse_warnings=_limit_warnings(warnings),
    )


def _read_headers(message: Message, warnings: list[str]) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    try:
        raw_items = list(message.raw_items())
    except Exception:
        warnings.append("headers could not be read")
        return headers

    for name, raw_value in raw_items:
        key = _clean_text(name).strip().lower()
        try:
            value = str(message.policy.header_fetch_parse(name, raw_value))
        except Exception:
            warnings.append("a header value could not be decoded; kept raw")
            value = "".join(str(raw_value).splitlines())
        headers.setdefault(key, []).append(_clean_text(value))
    return headers


def _read_bodies(message: Message, warnings: list[str]) -> tuple[list[str], list[str]]:
    """Walk MIME parts iteratively with depth and count limits."""
    text_parts: list[str] = []
    html_parts: list[str] = []
    defects: list[str] = []
    stack: list[tuple[Message, int]] = [(message, 0)]
    index = 0

    while stack:
        part, depth = stack.pop()
        index += 1
        if index > MAX_PARTS:
            warnings.append("too many MIME parts; remaining parts skipped")
            break

        try:
            if part.get_content_disposition() == "attachment":
                pass  # attachments are never decoded or descended into
            elif part.is_multipart():
                if depth >= MAX_DEPTH:
                    warnings.append("MIME nesting too deep; inner parts skipped")
                else:
                    children = part.get_payload()
                    if isinstance(children, list):
                        stack.extend((child, depth + 1) for child in reversed(children))
            else:
                content_type = part.get_content_type()
                if content_type in _BODY_TYPES:
                    text = _decode_part(part, index, warnings)
                    if text is not None:
                        target = text_parts if content_type == "text/plain" else html_parts
                        target.append(text)
        except Exception:
            warnings.append(f"part {index} could not be decoded; skipped")

        # Read defects last: decoding can add defects such as bad base64 padding.
        defects.extend(f"defect: {type(defect).__name__}" for defect in part.defects)

    warnings.extend(defects)
    return text_parts, html_parts


def _decode_part(part: Message, index: int, warnings: list[str]) -> str | None:
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return None

    charset = part.get_content_charset()
    if charset:
        try:
            return payload.decode(charset)
        except LookupError:
            warnings.append(f"part {index}: unknown charset; decoded as UTF-8 with replacement")
            return payload.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            warnings.append(f"part {index}: bytes invalid for declared charset; decoded with replacement")
            return payload.decode(charset, errors="replace")

    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        warnings.append(f"part {index}: no charset and not valid UTF-8; decoded with replacement")
        return payload.decode("utf-8", errors="replace")


def _clean_text(value: str) -> str:
    """Replace lone surrogates left by undecodable header bytes."""
    return value.encode("utf-8", errors="replace").decode("utf-8")


def _limit_warnings(warnings: list[str]) -> list[str]:
    unique = list(dict.fromkeys(warnings))
    if len(unique) <= MAX_WARNINGS:
        return unique
    omitted = len(unique) - (MAX_WARNINGS - 1)
    return unique[: MAX_WARNINGS - 1] + [f"{omitted} more warnings omitted"]
