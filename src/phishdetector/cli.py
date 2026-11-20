"""Command-line interface for local .eml analysis."""

import argparse
from pathlib import Path
import sys

from phishdetector.extractors import extract_urls
from phishdetector.models import DEFAULT_MAX_BYTES, InputTooLargeError
from phishdetector.parser import parse_email
from phishdetector.reporting import build_report, render_json, render_text
from phishdetector.rules import evaluate_rules


def main(argv: list[str] | None = None) -> int:
    """Analyze one bounded .eml file and print a text or JSON report."""
    parser = argparse.ArgumentParser(
        prog="phishdetector",
        description="Inspect an .eml message for explainable phishing signals.",
    )
    parser.add_argument("--json", action="store_true", help="emit the versioned JSON report")
    parser.add_argument("message", help="path to one RFC 822 .eml file")
    args = parser.parse_args(argv)

    try:
        data = _read_input(Path(args.message))
        email = parse_email(data)
        urls = extract_urls(email)
        findings = evaluate_rules(email, urls)
        report = build_report(email, urls, findings)
        output = render_json(report) if args.json else render_text(report)
    except InputTooLargeError:
        print(f"phishdetector: input exceeds the {DEFAULT_MAX_BYTES}-byte limit", file=sys.stderr)
        return 1
    except OSError:
        print("phishdetector: cannot read input file", file=sys.stderr)
        return 1
    except Exception:
        # Do not expose parser exceptions or attacker-controlled message data.
        print("phishdetector: could not analyze input file", file=sys.stderr)
        return 1

    sys.stdout.write(output)
    return 0


def _read_input(path: Path) -> bytes:
    """Read at most limit+1 bytes so oversized files do not consume unbounded memory."""
    with path.open("rb") as message_file:
        data = message_file.read(DEFAULT_MAX_BYTES + 1)
    if len(data) > DEFAULT_MAX_BYTES:
        raise InputTooLargeError(len(data), DEFAULT_MAX_BYTES)
    return data
