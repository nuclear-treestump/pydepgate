"""pydepgate.cli.main

pydepgate CLI entry point.

Sets up argparse with global flags, registers all subcommands,
handles environment-variable defaults, and dispatches to the
selected subcommand. Returns the subcommand's exit code.
"""

from __future__ import annotations

import argparse
import os
import sys

from pydepgate.cli import exit_codes
from pydepgate.cli.subcommands import (
    completion,
    exec_stub,
    preflight,
    scan,
    version,
    explain,
    cvedb,
)
from pydepgate.cli.subcommands.version import get_version

from pydepgate.cli.command_handlers.peek_args import (
    add_peek_arguments,
    build_peek_enricher,
    peek_chain_enabled,
    validate_peek_args,
)
from pydepgate.cli.command_handlers.decode_args import (
    add_decode_arguments,
    decode_enabled,
    validate_decode_args,
)

from pydepgate.cli.command_handlers.sarif_args import (
    add_sarif_arguments,
    validate_sarif_args,
)

# Color mode constants. Used as the values of args.color and as the
# argparse choices. Exposed at module level so tests and the reporter
# can refer to them without retyping string literals.
COLOR_AUTO = "auto"
COLOR_ALWAYS = "always"
COLOR_NEVER = "never"
COLOR_CHOICES = (COLOR_AUTO, COLOR_ALWAYS, COLOR_NEVER)


def _env_bool(name: str) -> bool:
    """Read a boolean environment variable.

    Truthy values: 1, true, yes, on (case-insensitive).
    Anything else (including unset) is False.
    """
    val = os.environ.get(name, "").lower()
    return val in ("1", "true", "yes", "on")


def _env_str(name: str, default: str | None = None) -> str | None:
    """Read a string environment variable, returning default if unset."""
    return os.environ.get(name, default)


def _color_default_from_env() -> str:
    """Compute the default value for --color from the environment.

    Precedence:
      1. PYDEPGATE_COLOR if set to one of auto/always/never.
      2. NO_COLOR or PYDEPGATE_NO_COLOR env vars (any value) map
         to "never" per the no-color.org convention.
      3. Otherwise "auto", which defers to TTY detection at render
         time.

    A bogus PYDEPGATE_COLOR value (e.g. "PYDEPGATE_COLOR=foo") is
    ignored and treated as if unset, falling through to the
    NO_COLOR check. We deliberately do not warn about this here
    because argparse runs before stderr-routing decisions are made;
    a typo'd env var falling back to a sane default is the least
    surprising behavior.
    """
    explicit = os.environ.get("PYDEPGATE_COLOR", "").strip().lower()
    if explicit in COLOR_CHOICES:
        return explicit

    if os.environ.get("NO_COLOR") or os.environ.get("PYDEPGATE_NO_COLOR"):
        return COLOR_NEVER

    return COLOR_AUTO


def _add_global_flags(
    parser: argparse.ArgumentParser,
    is_subparser: bool = False,
) -> None:
    """Add the pydepgate global flags to a parser.

    Called both on the top-level parser AND on each subcommand parser
    so flags work in either position. When called on a subparser, the
    defaults are SUPPRESS so that omitted flags do not clobber values
    captured by the top-level parser.
    """
    # Use argparse.SUPPRESS as default for subparsers so omitted flags
    # don't overwrite values set at the top level. For the top-level
    # parser, use the env-var-derived defaults normally.
    if is_subparser:
        ci_default = argparse.SUPPRESS
        format_default = argparse.SUPPRESS
        color_default = argparse.SUPPRESS
        min_severity_default = argparse.SUPPRESS
        strict_exit_default = argparse.SUPPRESS
    else:
        ci_default = _env_bool("PYDEPGATE_CI")
        format_default = _env_str("PYDEPGATE_FORMAT")
        color_default = _color_default_from_env()
        min_severity_default = _env_str("PYDEPGATE_MIN_SEVERITY")
        strict_exit_default = _env_bool("PYDEPGATE_STRICT_EXIT")

    parser.add_argument(
        "--ci",
        action="store_true",
        default=ci_default,
        help=(
            "CI mode: compact output, no color, JSON default format, "
            "diagnostics to stderr. Env: PYDEPGATE_CI"
        ),
    )
    parser.add_argument(
        "--format",
        choices=("human", "json", "sarif"),
        default=format_default,
        help=(
            "Output format. Default: human (json under --ci). " "Env: PYDEPGATE_FORMAT"
        ),
    )

    # --color is the canonical control. It takes one of three values:
    #   auto    Use color when stdout is a TTY and no NO_COLOR-style
    #           env var is set (the historical default behavior).
    #   always  Force color, even when stdout is not a TTY. Useful for
    #           piping to less -R or capturing colored output to a file
    #           that will later be rendered by a terminal-aware viewer.
    #   never   Disable color unconditionally.
    #
    # --no-color is kept as a backwards-compatible alias for
    # --color=never. Both write to args.color so the rest of the CLI
    # only has one attribute to consult. Old invocations and old CI
    # configs that pass --no-color continue to work without changes.
    parser.add_argument(
        "--color",
        choices=COLOR_CHOICES,
        default=color_default,
        metavar="WHEN",
        help=(
            "Control ANSI color output. 'auto' (default) emits color "
            "when stdout is a TTY; 'always' forces color even when "
            "piped or redirected; 'never' disables color entirely. "
            "Env: PYDEPGATE_COLOR. NO_COLOR and PYDEPGATE_NO_COLOR "
            "env vars (any value) imply --color=never."
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_const",
        const=COLOR_NEVER,
        dest="color",
        default=argparse.SUPPRESS,
        help=(
            "Alias for --color=never. Kept for backwards compatibility. "
            "Env: PYDEPGATE_NO_COLOR or NO_COLOR"
        ),
    )

    parser.add_argument(
        "--min-severity",
        choices=("info", "low", "medium", "high", "critical"),
        default=min_severity_default,
        help=("Suppress findings below this severity. " "Env: PYDEPGATE_MIN_SEVERITY"),
    )
    parser.add_argument(
        "--strict-exit",
        action="store_true",
        default=strict_exit_default,
        help=(
            "Apply --min-severity to display only; compute exit code "
            "from all findings. Env: PYDEPGATE_STRICT_EXIT"
        ),
    )

    parser.add_argument(
        "--rules-file",
        default=(
            argparse.SUPPRESS if is_subparser else _env_str("PYDEPGATE_RULES_FILE")
        ),
        help=(
            "Path to a .gate rules file. Default: discover "
            "pydepgate.gate in cwd or venv. Env: PYDEPGATE_RULES_FILE"
        ),
    )
    parser.add_argument(
        "--no-map",
        action="store_true",
        default=bool(os.environ.get("PYDEPGATE_NO_MAP")),
        help=(
            "Suppress the density map visualization in human output. "
            "Env: PYDEPGATE_NO_MAP"
        ),
    )
    add_peek_arguments(parser, is_subparser=is_subparser)  # Peek args (--peek*)
    add_decode_arguments(parser, is_subparser=is_subparser)  # Decode args (--decode*)
    add_sarif_arguments(parser, is_subparser=is_subparser)  # SARIF args (--sarif*)


def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser tree."""
    parser = argparse.ArgumentParser(
        prog="pydepgate",
        description=(
            "A lightweight Python runner that interdicts suspicious "
            "startup behavior. Statically analyzes packages for the "
            "patterns used in supply-chain attacks like LiteLLM 1.82.8."
        ),
        epilog=(
            "Use 'pydepgate <subcommand> --help' for subcommand-specific "
            "help, or 'pydepgate help' for an overview."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"pydepgate {get_version()}",
    )

    # Add global flags at the top level so 'pydepgate --format json scan pip' works.
    _add_global_flags(parser)

    # Subcommand registration.
    subparsers = parser.add_subparsers(
        dest="subcommand",
        title="subcommands",
        metavar="<subcommand>",
    )

    # Each subcommand registers its own arguments AND inherits the
    # global flags so 'pydepgate scan pip --format json' also works.
    scan.register(subparsers)
    preflight.register(subparsers)
    exec_stub.register(subparsers)
    version.register(subparsers)
    explain.register(subparsers)
    cvedb.register(subparsers)
    # Help subcommand.
    help_parser = subparsers.add_parser(
        "help",
        help="Show help for pydepgate or a specific subcommand",
    )
    help_parser.add_argument(
        "topic",
        nargs="?",
        help="Subcommand to show help for, or omit for top-level help",
    )
    help_parser.set_defaults(func=lambda args: _run_help(parser, args))

    # Add global flags to every subcommand parser.
    for subparser_name in subparsers.choices:
        _add_global_flags(subparsers.choices[subparser_name], is_subparser=True)

    # Completion subcommands. Registered after the global-flags loop
    # so the hidden _complete subcommand does not get the global
    # flags applied: its `words` REMAINDER positional must accept
    # tokens like `--format` as data, not interpret them as flags.
    completion.register(subparsers)

    return parser


def _run_help(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    """Implement the 'help' subcommand by routing to argparse's help."""
    if not args.topic:
        parser.print_help()
        return 0
    # Find the subparser for the given topic and print its help.
    subparsers_actions = [
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    ]
    for sp_action in subparsers_actions:
        if args.topic in sp_action.choices:
            sp_action.choices[args.topic].print_help()
            return 0
    sys.stderr.write(f"unknown subcommand: {args.topic}\n")
    return exit_codes.TOOL_ERROR


def _apply_ci_defaults(args: argparse.Namespace) -> None:
    """Apply --ci behavioral cluster: implies several other flags.

    CI mode forces JSON format (unless explicitly set) and disables
    color (unless the user explicitly opted in via --color=always).
    The latter is unusual but legitimate: a CI runner with a colored
    log viewer wants the escape codes preserved even under --ci.
    """
    if not args.ci:
        return
    if not args.format:
        args.format = "json"
    # Only auto-flip color to "never" when the user hasn't explicitly
    # asked for "always". An explicit --color=always paired with --ci
    # is a deliberate choice and we respect it.
    if args.color == COLOR_AUTO:
        args.color = COLOR_NEVER


def main(argv: list[str] | None = None) -> int:
    """Top-level entry point. Returns an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_peek_args(args)
    validate_decode_args(args)
    validate_sarif_args(args)

    if not args.subcommand:
        parser.print_help()
        return 0

    _apply_ci_defaults(args)

    # Default format if still unset.
    if not args.format:
        args.format = "human"

    if not hasattr(args, "func"):
        parser.print_help()
        return exit_codes.TOOL_ERROR

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
