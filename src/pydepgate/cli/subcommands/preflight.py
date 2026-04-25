"""Stub for the 'preflight' subcommand. Implementation planned for v0.2."""

from __future__ import annotations

import argparse
import sys

from pydepgate.cli import exit_codes


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "preflight",
        help="Walk an installed environment (under development)",
        description=(
            "Scan all installed packages in a Python environment for "
            "suspicious startup behavior. Currently under development; "
            "planned for v0.2."
        ),
    )
    parser.add_argument(
        "--python",
        help="Path to a Python interpreter whose environment to scan",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    sys.stderr.write(
        "The 'preflight' subcommand is part of pydepgate's environment "
        "auditing mode and is currently under development. It will "
        "scan every installed package in a Python environment for the "
        "same patterns 'pydepgate scan' looks for in individual "
        "artifacts.\n"
        "\n"
        "Planned for v0.2. Track progress in ROADMAP.md.\n"
        "\n"
        "For now, you can scan individual packages with "
        "'pydepgate scan <package-name>'.\n"
    )
    return exit_codes.TOOL_ERROR