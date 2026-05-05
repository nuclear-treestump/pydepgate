"""pydepgate.cli.peek_args

Argparse helpers, environment-variable reading, validation, and
enricher construction for the payload_peek feature.

This module is the user-facing entry point for the enricher
subsystem. It exposes four functions intended to be called from
`pydepgate.cli.main` (or wherever the project's existing argparser
is built):

    add_peek_arguments(parser)
        Add the peek-related flags to an argparse parser.

    validate_peek_args(args, *, stderr)
        Emit warnings for tuning flags passed without `--peek`,
        and raise SystemExit on out-of-range values.

    build_peek_enricher(args) -> PayloadPeek | None
        Construct a configured PayloadPeek instance, or None if
        peek is disabled.

    peek_chain_enabled(args) -> bool
        Convenience for the reporter: is verbose chain rendering on?

Environment variables override built-in defaults but are themselves
overridden by explicit CLI flags. Order of precedence (highest
wins):

    explicit CLI flag  >  environment variable  >  built-in default

The builtin defaults match the values exposed as constants by
`pydepgate.enrichers.payload_peek` so this module and the enricher
agree on the meaning of "default."

Boolean environment variables accept any of {"1", "true", "yes",
"on"} (case-insensitive) as truthy. Anything else, including the
empty string and unset, is falsy. This matches the convention used
by other tools in the same niche.

Integer environment variables are parsed strictly: a non-integer
value falls back to the built-in default and emits a stderr
warning. We don't want a typo'd env var to silently produce
unexpected behavior.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import TextIO

from pydepgate.enrichers.payload_peek import (
    DEFAULT_MAX_BUDGET,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MIN_LENGTH,
    MIN_BUDGET_FLOOR,
    MIN_LENGTH_FLOOR,
    PayloadPeek,
)


# Hard ceiling on user-supplied depth. The unwrap loop's worst-case
# work is O(max_depth * max_budget) bytes processed; capping depth
# at 10 keeps a misconfigured run from churning indefinitely on a
# pathological chain. Most real chains terminate by depth 4.
PEEK_DEPTH_CEILING = 10

# Environment variable names. Exposed as constants so tests can
# reference them without retyping.
ENV_PEEK = "PYDEPGATE_PEEK"
ENV_PEEK_DEPTH = "PYDEPGATE_PEEK_DEPTH"
ENV_PEEK_BUDGET = "PYDEPGATE_PEEK_BUDGET"
ENV_PEEK_CHAIN = "PYDEPGATE_PEEK_CHAIN"
ENV_PEEK_MIN_LENGTH = "PYDEPGATE_PEEK_MIN_LENGTH"


# ---------------------------------------------------------------------------
# Environment-variable parsing
# ---------------------------------------------------------------------------

def _truthy_env(value: str | None) -> bool:
    """True iff `value` is a recognized truthy string."""
    if value is None:
        return False
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return _truthy_env(raw)


def _env_int(
    name: str,
    default: int,
    *,
    stderr: TextIO | None = None,
) -> int:
    """Read an integer environment variable.

    On parse failure, emit a stderr warning (if `stderr` is
    provided) and return the default. We don't want a typo to
    silently produce unexpected behavior, but we also don't want
    a typo to abort startup.
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        if stderr is not None:
            stderr.write(
                f"warning: environment variable {name}={raw!r} is not "
                f"an integer; using default {default}.\n"
            )
        return default


# ---------------------------------------------------------------------------
# Argparse wiring
# ---------------------------------------------------------------------------

def add_peek_arguments(
    parser: argparse.ArgumentParser,
    *,
    is_subparser: bool = False,
    stderr: TextIO | None = None,
) -> None:
    """Add the `--peek*` flags to `parser`.

    Defaults for each flag are computed from the corresponding
    environment variable, falling back to the built-in default.
    The caller's existing argparse setup is unchanged otherwise.

    Pass `stderr` to receive warnings about malformed env vars
    during parser construction; defaults to sys.stderr.
    """
    if stderr is None:
        stderr = sys.stderr

    if is_subparser:
        default_peek = argparse.SUPPRESS
        default_depth = argparse.SUPPRESS
        default_budget = argparse.SUPPRESS
        default_chain = argparse.SUPPRESS
        default_min_length = argparse.SUPPRESS
    else:
        default_peek = _env_bool(ENV_PEEK, False)
        default_depth = _env_int(ENV_PEEK_DEPTH, DEFAULT_MAX_DEPTH, stderr=stderr)
        default_budget = _env_int(ENV_PEEK_BUDGET, DEFAULT_MAX_BUDGET, stderr=stderr)
        default_chain = _env_bool(ENV_PEEK_CHAIN, False)
        default_min_length = _env_int(
            ENV_PEEK_MIN_LENGTH, DEFAULT_MIN_LENGTH, stderr=stderr,
        )

    group = parser.add_argument_group(
        "payload peek",
        "Safe partial decoding of large encoded literals. The "
        "unwrap loop never executes input; pickle data is "
        "detected and warned about but never deserialized.",
    )

    group.add_argument(
        "--peek",
        action="store_true",
        default=default_peek,
        help=(
            "Enable the payload_peek enricher. Attempts safe "
            "partial decoding of analyzer-flagged encoded "
            "literals (base64, hex, zlib, gzip, bzip2, lzma) "
            "and surfaces the inner payload kind plus indicator "
            "strings. Emits ENC002 when the chain reaches 2+ "
            "layers or exhausts the depth limit. "
            "(env: PYDEPGATE_PEEK)"
        ),
    )

    group.add_argument(
        "--peek-depth",
        type=int,
        default=default_depth,
        metavar="N",
        help=(
            f"Maximum number of unwrap transformations applied "
            f"to one literal. Default {DEFAULT_MAX_DEPTH}, "
            f"ceiling {PEEK_DEPTH_CEILING}, floor 1. "
            f"(env: PYDEPGATE_PEEK_DEPTH)"
        ),
    )

    group.add_argument(
        "--peek-budget",
        type=int,
        default=default_budget,
        metavar="BYTES",
        help=(
            f"Cumulative byte budget across all unwrap layers. "
            f"Defends against decompression bombs. Default "
            f"{DEFAULT_MAX_BUDGET} ({DEFAULT_MAX_BUDGET // 1024}KB), "
            f"floor {MIN_BUDGET_FLOOR}. "
            f"(env: PYDEPGATE_PEEK_BUDGET)"
        ),
    )

    group.add_argument(
        "--peek-min-length",
        type=int,
        default=default_min_length,
        metavar="BYTES",
        help=(
            f"Minimum literal size, in bytes, before the enricher "
            f"will attempt to unwrap. Smaller literals are skipped "
            f"because the cost of decoding tiny strings is rarely "
            f"worth the result, and many short high-entropy strings "
            f"are benign (UUIDs, hashes, color codes). "
            f"Default {DEFAULT_MIN_LENGTH}, floor {MIN_LENGTH_FLOOR}. "
            f"Lower this if you want to inspect smaller blobs; raise "
            f"it to skip more noise. (env: PYDEPGATE_PEEK_MIN_LENGTH)"
        ),
    )

    group.add_argument(
        "--peek-chain",
        action="store_true",
        default=default_chain,
        help=(
            "Render the unwrap chain layer-by-layer with hex "
            "dumps and indicator scans in human-format output. "
            "JSON output always includes the full chain "
            "regardless. (env: PYDEPGATE_PEEK_CHAIN)"
        ),
    )


# ---------------------------------------------------------------------------
# Post-parse validation
# ---------------------------------------------------------------------------

def validate_peek_args(
    args: argparse.Namespace,
    *,
    stderr: TextIO | None = None,
) -> None:
    """Validate parsed peek arguments.

    Soft warnings (written to stderr, return normally):
      - Tuning flags passed without `--peek` have no effect.

    Hard errors (raise SystemExit):
      - `--peek-depth` outside [1, PEEK_DEPTH_CEILING].
      - `--peek-budget` below MIN_BUDGET_FLOOR.
      - `--peek-min-length` below MIN_LENGTH_FLOOR.

    Hard errors only fire when `--peek` is enabled; if the flag
    is off, the values are ignored so out-of-range settings are
    irrelevant.
    """
    if stderr is None:
        stderr = sys.stderr

    # Soft warnings for ignored tuning flags.
    if not args.peek:
        ignored = []
        if args.peek_depth != DEFAULT_MAX_DEPTH:
            ignored.append("--peek-depth")
        if args.peek_budget != DEFAULT_MAX_BUDGET:
            ignored.append("--peek-budget")
        if args.peek_min_length != DEFAULT_MIN_LENGTH:
            ignored.append("--peek-min-length")
        if args.peek_chain:
            ignored.append("--peek-chain")
        if ignored:
            stderr.write(
                f"warning: {', '.join(ignored)} "
                f"{'has' if len(ignored) == 1 else 'have'} no effect "
                f"without --peek; ignored.\n"
            )
        return

    # Hard errors when peek is on.
    if args.peek_depth < 1:
        _exit_with_error(
            stderr,
            f"--peek-depth must be at least 1; got {args.peek_depth}",
        )
    if args.peek_depth > PEEK_DEPTH_CEILING:
        _exit_with_error(
            stderr,
            f"--peek-depth ceiling is {PEEK_DEPTH_CEILING}; "
            f"got {args.peek_depth}",
        )
    if args.peek_budget < MIN_BUDGET_FLOOR:
        _exit_with_error(
            stderr,
            f"--peek-budget floor is {MIN_BUDGET_FLOOR} bytes; "
            f"got {args.peek_budget}",
        )
    if args.peek_min_length < MIN_LENGTH_FLOOR:
        _exit_with_error(
            stderr,
            f"--peek-min-length floor is {MIN_LENGTH_FLOOR} bytes; "
            f"got {args.peek_min_length}",
        )


def _exit_with_error(stderr: TextIO, message: str) -> None:
    """Write an argparse-style error and exit with code 2."""
    prog = os.path.basename(sys.argv[0]) if sys.argv else "pydepgate"
    stderr.write(f"{prog}: error: {message}\n")
    raise SystemExit(2)


# ---------------------------------------------------------------------------
# Enricher construction
# ---------------------------------------------------------------------------

def build_peek_enricher(args: argparse.Namespace) -> PayloadPeek | None:
    """Construct a PayloadPeek configured per CLI args.

    Returns None when --peek is disabled. Caller appends to the
    engine's enricher list when not None.

    Assumes `validate_peek_args` was already called; this function
    does no validation of its own beyond what PayloadPeek's own
    __init__ enforces.
    """
    if not args.peek:
        return None
    return PayloadPeek(
        min_length=args.peek_min_length,
        max_depth=args.peek_depth,
        max_budget=args.peek_budget,
    )


def peek_chain_enabled(args: argparse.Namespace) -> bool:
    """True iff the reporter should render the verbose chain."""
    return bool(getattr(args, "peek", False)) and bool(
        getattr(args, "peek_chain", False)
    )