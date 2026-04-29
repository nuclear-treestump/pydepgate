"""The 'version' subcommand: print version info."""

from __future__ import annotations

import argparse
import sys


_VERSION = "0.2.0"


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "version",
        help="Print pydepgate version",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    sys.stdout.write(f"pydepgate {_VERSION}\n")
    return 0


def get_version() -> str:
    """Programmatic version access for the --version flag."""
    return _VERSION