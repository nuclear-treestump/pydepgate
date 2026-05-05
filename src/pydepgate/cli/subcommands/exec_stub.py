"""pydepgate.cli.subcommands.exec

Stub for the 'exec' subcommand. Implementation planned for v0.4."""

from __future__ import annotations

import argparse
import sys

from pydepgate.cli import exit_codes


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "exec",
        help="Run Python with runtime interdiction (under development)",
        description=(
            "Wrap a Python script with pydepgate's runtime engine, "
            "intercepting suspicious startup behavior before it executes. "
            "Currently under development; planned for v0.4."
        ),
    )
    parser.add_argument(
        "script",
        nargs="?",
        help="Python script to run (under development)",
    )
    parser.add_argument(
        "script_args",
        nargs=argparse.REMAINDER,
        help="Arguments to pass to the script (after --)",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    sys.stderr.write(
        "The 'exec' subcommand is part of pydepgate's runtime "
        "interdiction mode and is currently under development. It "
        "will let pydepgate run a Python script with audit hooks "
        "installed, blocking suspicious startup behavior before it "
        "executes.\n"
        "\n"
        "Planned for v0.4. Track progress in ROADMAP.md.\n"
        "\n"
        "For now, you can scan packages statically with "
        "'pydepgate scan'.\n"
    )
    return exit_codes.TOOL_ERROR