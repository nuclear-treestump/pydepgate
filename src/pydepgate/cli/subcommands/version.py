"""pydepgate.cli.subcommands.version

The 'version' subcommand: print version info."""

from __future__ import annotations

import argparse
import sys

__version__ = "0.4.0"


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "version",
        help="Print pydepgate version",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    sys.stdout.write(f"pydepgate {__version__}\n")
    return 0


def get_version() -> str:
    """Programmatic version access for the --version flag."""
    return __version__
