"""
The 'completions' subcommand: emit shell completion scripts.

Also registers the hidden '_complete' subcommand, which is the
callback the shell invokes during tab completion. Users do not type
_complete directly; the shell glue inserted by `pydepgate completions
<shell>` does.

Both subcommands are thin argparse wrappers around the engine in
pydepgate.cli.completion; the actual logic lives there so it can
be unit-tested without argparse round-trips.
"""

from __future__ import annotations

import argparse
import sys

from pydepgate.cli import exit_codes
from pydepgate.cli.completion import (
    SUPPORTED_SHELLS,
    complete_words,
    script_for_shell,
)


def register(subparsers) -> None:
    """Register both the user-facing and hidden completion subcommands."""
    _register_completions(subparsers)
    _register_complete(subparsers)


def _register_completions(subparsers) -> None:
    """User-facing 'pydepgate completions <shell>' subcommand."""
    parser = subparsers.add_parser(
        "completions",
        help="Emit shell completion script for bash, zsh, or fish",
        description=(
            "Print a shell completion script to stdout. Running this "
            "command alone does NOT install completion; you have to "
            "do something with the output.\n"
            "\n"
            "Quickest install (bash, current shell only):\n"
            "  eval \"$(pydepgate completions bash)\"\n"
            "\n"
            "Persistent install (bash, all future shells):\n"
            "  pydepgate completions bash >> ~/.bashrc\n"
            "\n"
            "Persistent install (zsh):\n"
            "  pydepgate completions zsh >> ~/.zshrc\n"
            "\n"
            "Persistent install (fish):\n"
            "  pydepgate completions fish > "
            "~/.config/fish/completions/pydepgate.fish\n"
            "\n"
            "After installing, open a new shell or re-source your "
            "rc file, then test with:\n"
            "  pydepgate <TAB><TAB>\n"
            "\n"
            "When run interactively (output to a terminal rather "
            "than redirected), this command also prints install "
            "instructions to stderr."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "shell",
        choices=SUPPORTED_SHELLS,
        help="Target shell. Supported: bash, zsh, fish.",
    )
    parser.set_defaults(func=_run_completions)


def _register_complete(subparsers) -> None:
    """Hidden '_complete' subcommand for shell callbacks.

    The leading underscore signals that this is internal; argparse's
    `help=argparse.SUPPRESS` keeps it out of `--help` output. Users
    never type this directly. The shell glue from `completions <shell>`
    invokes it on every TAB press.
    """
    parser = subparsers.add_parser(
        "_complete",
        add_help=False,
    )
    parser.add_argument("--cur", default="", help=argparse.SUPPRESS)
    parser.add_argument("--prev", default="", help=argparse.SUPPRESS)
    parser.add_argument(
        "words",
        nargs=argparse.REMAINDER,
        help=argparse.SUPPRESS,
    )
    parser.set_defaults(func=_run_complete)


def _run_completions(args: argparse.Namespace) -> int:
    """Print the requested shell's completion script to stdout.

    Install instructions are written to stderr so they appear when
    the user runs the command interactively but do not pollute the
    output when the script is piped to a file or eval'd directly.
    Detecting interactive use via `sys.stdout.isatty()` lets us
    suppress the instructions in the redirect-to-file case where
    they would just be noise.
    """
    try:
        script = script_for_shell(args.shell)
    except ValueError as exc:
        # Should be unreachable because argparse validates `choices`,
        # but defensively report instead of trace.
        sys.stderr.write(f"error: {exc}\n")
        return exit_codes.TOOL_ERROR

    sys.stdout.write(script)
    if not script.endswith("\n"):
        sys.stdout.write("\n")

    # If stdout is a TTY, the user is running the command
    # interactively and is probably watching a wall of shell script
    # scroll past with no idea what to do next. Print install
    # instructions to stderr so they get useful guidance without
    # contaminating the stdout output. If stdout is being piped or
    # redirected (the install case), suppress the instructions
    # because they would just be confusing noise.
    if sys.stdout.isatty():
        _print_install_hints(args.shell)

    return exit_codes.CLEAN


def _print_install_hints(shell: str) -> None:
    """Write install instructions for `shell` to stderr.

    Three install options per shell, ordered by user effort:
      1. Eval directly (current shell only)
      2. Append to shell rc file (all future shells)
      3. Drop into the shell's completion directory (idiomatic)

    The hints are deliberately specific. Generic advice like 'put
    this somewhere your shell will source it' is exactly what the
    user is trying to avoid by reading these hints in the first
    place.
    """
    sys.stderr.write("\n")
    sys.stderr.write(
        "# That was the completion script. To actually install it, "
        "use one of:\n"
    )
    sys.stderr.write("\n")

    if shell == "bash":
        sys.stderr.write(
            "  # Current shell only (forgotten when you close it):\n"
            "  eval \"$(pydepgate completions bash)\"\n"
            "\n"
            "  # All future bash sessions (recommended):\n"
            "  pydepgate completions bash >> ~/.bashrc\n"
            "\n"
            "  # System-wide via bash-completion package "
            "(if installed):\n"
            "  pydepgate completions bash | sudo tee "
            "/etc/bash_completion.d/pydepgate > /dev/null\n"
        )
    elif shell == "zsh":
        sys.stderr.write(
            "  # Current shell only:\n"
            "  eval \"$(pydepgate completions zsh)\"\n"
            "\n"
            "  # All future zsh sessions (recommended):\n"
            "  pydepgate completions zsh >> ~/.zshrc\n"
            "\n"
            "  # Via the zsh fpath system "
            "(if you have one configured):\n"
            "  pydepgate completions zsh > "
            "\"${fpath[1]}/_pydepgate\"\n"
        )
    elif shell == "fish":
        sys.stderr.write(
            "  # Current shell only:\n"
            "  pydepgate completions fish | source\n"
            "\n"
            "  # All future fish sessions (recommended):\n"
            "  pydepgate completions fish > "
            "~/.config/fish/completions/pydepgate.fish\n"
        )

    sys.stderr.write(
        "\n"
        "# After installing, open a new shell or re-source your "
        "rc file. Test with:\n"
        "#   pydepgate <TAB><TAB>\n"
    )


def _run_complete(args: argparse.Namespace) -> int:
    """Emit completion candidates one per line.

    Called by the shell glue. Output goes to stdout. Errors in the
    engine are swallowed so the shell never sees a non-zero exit
    code from a tab press; a malformed completion state should
    silently produce no candidates rather than break the user's
    shell.
    """
    try:
        candidates = complete_words(
            cur=args.cur,
            prev=args.prev,
            words=list(args.words),
        )
    except Exception:
        # Tab completion must never crash the shell; on any
        # internal error we emit nothing and exit clean.
        return exit_codes.CLEAN

    for candidate in candidates:
        sys.stdout.write(candidate)
        sys.stdout.write("\n")
    return exit_codes.CLEAN