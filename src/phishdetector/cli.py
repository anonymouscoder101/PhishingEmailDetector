"""Command-line entry point for phishdetector."""

import argparse


def main(argv: list[str] | None = None) -> int:
    """Parse the CLI arguments.

    Email analysis is added in the CLI integration phase. This initial entry
    point establishes the console command and its help interface.
    """
    parser = argparse.ArgumentParser(
        prog="phishdetector",
        description="Inspect an .eml message for explainable phishing signals.",
    )
    parser.add_argument("message", help="path to one RFC 822 .eml file")
    parser.parse_args(argv)
    return 0
