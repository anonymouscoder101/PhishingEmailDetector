"""Command-line integration tests for file analysis and safe errors."""

import json
from pathlib import Path

import pytest

from phishdetector import __version__
from phishdetector.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_package_has_version() -> None:
    assert __version__ == "0.1.0"


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    assert exc_info.value.code == 0
    assert "path to one RFC 822 .eml file" in capsys.readouterr().out


def test_file_input_renders_text_report(capsys: pytest.CaptureFixture[str]) -> None:
    result = main([str(FIXTURES / "simple.eml")])

    output = capsys.readouterr()
    assert result == 0
    assert "Phishing email analysis (heuristic)" in output.out
    assert "Risk score: 0/100 (low)" in output.out
    assert "https://cafe.example.com/menu" in output.out
    assert output.err == ""


def test_json_flag_renders_versioned_json(capsys: pytest.CaptureFixture[str]) -> None:
    result = main(["--json", str(FIXTURES / "simple.eml")])

    output = capsys.readouterr()
    report = json.loads(output.out)
    assert result == 0
    assert report["schema_version"] == "1"
    assert report["score"] == 0
    assert report["urls"] == ["https://cafe.example.com/menu"]
    assert output.err == ""


def test_suspicious_score_is_not_an_execution_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    message = tmp_path / "suspicious.eml"
    message.write_text(
        "From: Billing <billing@example.com>\n"
        "Reply-To: help@attacker.test\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "Please pay at http://192.0.2.9/login\n",
        encoding="utf-8",
    )

    result = main(["--json", str(message)])

    output = capsys.readouterr()
    report = json.loads(output.out)
    assert result == 0
    assert report["score"] > 0
    assert {item["id"] for item in report["findings"]} == {
        "header.reply_to_mismatch",
        "url.ip_literal",
    }
    assert output.err == ""


def test_unreadable_path_has_concise_error_without_message_contents(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "missing.eml"

    result = main([str(missing)])

    output = capsys.readouterr()
    assert result != 0
    assert output.out == ""
    assert "cannot read input file" in output.err
    assert "Traceback" not in output.err


def test_invalid_arguments_return_argparse_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--unknown"])

    output = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "usage:" in output.err


def test_oversized_file_is_rejected_without_printing_body(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "large.eml"
    path.write_bytes(b"SECRET-BODY-TOKEN" + b"x" * (10 * 1024 * 1024))

    result = main([str(path)])

    output = capsys.readouterr()
    assert result != 0
    assert output.out == ""
    assert "exceeds the 10485760-byte limit" in output.err
    assert "SECRET-BODY-TOKEN" not in output.err
