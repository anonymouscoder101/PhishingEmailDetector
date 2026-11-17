"""Smoke tests for the initial project scaffold."""

import pytest

from phishdetector import __version__
from phishdetector.cli import main


def test_package_has_version() -> None:
    assert __version__ == "0.1.0"


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    assert exc_info.value.code == 0
    assert "path to one RFC 822 .eml file" in capsys.readouterr().out
