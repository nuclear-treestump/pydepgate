"""
Argparse helpers and validation for the --decode-payload-depth feature.

Adds three flags to the CLI:

    --decode-payload-depth N
        Recursion depth for the decoded-payload re-scan driver.
        Default 3. Floor 1, ceiling 8. Setting this requires --peek
        to also be enabled (the driver consumes the peek enricher's
        output to find payload-bearing findings).

    --decode-location PATH
        Output file path for the decoded-payload tree. When omitted,
        the path is auto-built as
            <cwd>/decoded/decoded_payloads_<targetname>.txt
        with .json substituted for .txt when --decode-format=json.

    --decode-format {text,json}
        Output format. Text is a tree-shaped report intended for
        human reading; JSON is structured for downstream tooling.
        Default text.

These flags follow the same env-var precedence pattern as the peek
flags (CLI > env > built-in default), and their argparse defaults
on subparsers use argparse.SUPPRESS so they don't clobber values
captured at the top-level parser when subcommands are dispatched.

Validation runs after parse_args via validate_decode_args. The
hard error is "depth set without --peek"; soft warnings cover the
"location/format set but depth is 0" case.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import TextIO


# Env var names for the three flags. Constants so tests can reference
# them without retyping.
ENV_DECODE_DEPTH = "PYDEPGATE_DECODE_PAYLOAD_DEPTH"
ENV_DECODE_LOCATION = "PYDEPGATE_DECODE_LOCATION"
ENV_DECODE_FORMAT = "PYDEPGATE_DECODE_FORMAT"


# Depth bounds. The ceiling exists for the same reason as peek's:
# a misconfigured run shouldn't be able to chase a recursive payload
# until the universe heat-deaths. Even depth 8 is well past the
# "any real attack we have observed" threshold; at depth 4+ the
# byte budget per layer has dropped low enough that subsequent
# layers fit fine inside whatever budget the user passed.
DEFAULT_DECODE_DEPTH = 3
MIN_DECODE_DEPTH = 1
MAX_DECODE_DEPTH = 8


# Format choices.
DECODE_FORMAT_TEXT = "text"
DECODE_FORMAT_JSON = "json"
DECODE_FORMAT_CHOICES = (DECODE_FORMAT_TEXT, DECODE_FORMAT_JSON)
DEFAULT_DECODE_FORMAT = DECODE_FORMAT_TEXT


# Sentinel for "not set" on the depth flag. We can't use 0 because 0 is a
# legitimate (if unusual) user value meaning "do not run the decode
# pass." Any negative value works as the sentinel because the validator
# rejects anything below MIN_DECODE_DEPTH; we use -1 for clarity.
_DECODE_DEPTH_UNSET = -1


def _env_int(name: str, default: int, *, stderr: TextIO | None = None) -> int:
    """Read an integer from the environment, returning default on miss/parse-fail."""
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


def _env_str(name: str, default: str | None) -> str | None:
    """Read a string env var, treating empty as unset."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw


def add_decode_arguments(
    parser: argparse.ArgumentParser,
    *,
    is_subparser: bool = False,
    stderr: TextIO | None = None,
) -> None:
    """Add the --decode-payload-* flags to `parser`.

    Mirrors add_peek_arguments' shape: env-derived defaults at the
    top level, argparse.SUPPRESS on subparsers so values set at the
    top level are not clobbered when a subcommand is dispatched.
    """
    if stderr is None:
        stderr = sys.stderr

    if is_subparser:
        default_depth = argparse.SUPPRESS
        default_location = argparse.SUPPRESS
        default_format = argparse.SUPPRESS
    else:
        default_depth = _env_int(
            ENV_DECODE_DEPTH, _DECODE_DEPTH_UNSET, stderr=stderr,
        )
        default_location = _env_str(ENV_DECODE_LOCATION, None)
        default_format = _env_str(ENV_DECODE_FORMAT, DEFAULT_DECODE_FORMAT)
        # If the env-var format is somehow garbage, fall back to the
        # built-in default. argparse would error on an invalid choice
        # if we passed it through, which would block the user from
        # running pydepgate at all just because of a typo'd env var.
        if default_format not in DECODE_FORMAT_CHOICES:
            default_format = DEFAULT_DECODE_FORMAT

    group = parser.add_argument_group(
        "decoded-payload inspection",
        "Recursive re-scan of payloads decoded by the peek enricher. "
        "Discovers attacks where one decoded layer contains another "
        "(LiteLLM 1.82.8 has at least two: an outer base64 payload "
        "whose decoded Python source contains a second base64 payload "
        "which decodes to the actual exfiltration code). Requires "
        "--peek; the decoded-payload driver consumes peek's output."
    )

    group.add_argument(
        "--decode-payload-depth",
        type=int,
        default=default_depth,
        metavar="N",
        help=(
            f"Recursion depth for the decoded-payload re-scan. "
            f"Default {DEFAULT_DECODE_DEPTH} (when set). At each "
            f"level, payload-bearing findings whose decoded form is "
            f"Python source are re-scanned; findings from that scan "
            f"are themselves candidates for further decoding. Floor "
            f"{MIN_DECODE_DEPTH}, ceiling {MAX_DECODE_DEPTH}. "
            f"Requires --peek. (env: {ENV_DECODE_DEPTH})"
        ),
    )

    group.add_argument(
        "--decode-location",
        type=str,
        default=default_location,
        metavar="PATH",
        help=(
            "Output path for the decoded-payload report. Default: "
            "<cwd>/decoded/decoded_payloads_<targetname>.<ext> where "
            "<ext> matches the chosen format. The 'decoded/' parent "
            "directory is created if it does not exist. "
            f"(env: {ENV_DECODE_LOCATION})"
        ),
    )

    group.add_argument(
        "--decode-format",
        choices=DECODE_FORMAT_CHOICES,
        default=default_format,
        help=(
            "Output format for the decoded-payload report. 'text' "
            "(default) is a tree-shaped report intended for human "
            "review; 'json' is a structured representation of the "
            "same tree intended for downstream tooling. "
            f"(env: {ENV_DECODE_FORMAT})"
        ),
    )

    group.add_argument(
        "--decode-iocs",
        action="store_true",
        help=(
            "Include IOC (Indicators of Compromise) section in the "
            "decoded-payload report. Adds SHA256/SHA512 hashes of "
            "all decoded blobs plus extracted source code for "
            "forensic analysis. Text format only; ignored in JSON mode."
        ),
    )


def decode_enabled(args: argparse.Namespace) -> bool:
    """True iff the user opted into the decode-payload pass.

    Treats the sentinel "depth not set" value (and depth <= 0) as
    disabled. The driver short-circuits when this returns False.
    """
    depth = getattr(args, "decode_payload_depth", _DECODE_DEPTH_UNSET)
    if depth is None:
        return False
    return depth >= MIN_DECODE_DEPTH


def validate_decode_args(
    args: argparse.Namespace,
    *,
    stderr: TextIO | None = None,
) -> None:
    """Validate parsed decode-payload arguments.

    Hard errors (raise SystemExit):
      - --decode-payload-depth set without --peek.
      - --decode-payload-depth out of [MIN_DECODE_DEPTH, MAX_DECODE_DEPTH].

    Soft warnings (write to stderr, return normally):
      - --decode-location set but --decode-payload-depth not enabled.
      - --decode-format set but --decode-payload-depth not enabled.
    """
    if stderr is None:
        stderr = sys.stderr

    enabled = decode_enabled(args)
    location = getattr(args, "decode_location", None)
    fmt = getattr(args, "decode_format", DEFAULT_DECODE_FORMAT)
    fmt_was_explicit = (
        location is not None or
        fmt != DEFAULT_DECODE_FORMAT
    )

    if enabled:
        depth = args.decode_payload_depth
        # Depth out of range.
        if depth < MIN_DECODE_DEPTH:
            _exit_with_error(
                stderr,
                f"--decode-payload-depth must be at least "
                f"{MIN_DECODE_DEPTH}; got {depth}",
            )
        if depth > MAX_DECODE_DEPTH:
            _exit_with_error(
                stderr,
                f"--decode-payload-depth ceiling is "
                f"{MAX_DECODE_DEPTH}; got {depth}. Beyond this, the "
                f"recursion is far past any real attack pattern; "
                f"use --peek-budget if you need to inspect a single "
                f"very large payload."
            )
        # Hard error: depth is set but peek is off.
        peek_on = bool(getattr(args, "peek", False))
        if not peek_on:
            _exit_with_error(
                stderr,
                "--decode-payload-depth requires --peek to be "
                "enabled. The decoded-payload driver consumes the "
                "peek enricher's output; without --peek there is "
                "nothing to decode."
            )
        return

    # Disabled path: warn about flags that have no effect.
    if location is not None or fmt_was_explicit:
        ignored = []
        if location is not None:
            ignored.append("--decode-location")
        if fmt != DEFAULT_DECODE_FORMAT:
            ignored.append("--decode-format")
        if ignored:
            stderr.write(
                f"warning: {', '.join(ignored)} "
                f"{'has' if len(ignored) == 1 else 'have'} no effect "
                f"without --decode-payload-depth; ignored.\n"
            )


def _exit_with_error(stderr: TextIO, message: str) -> None:
    """Write an argparse-style error and exit with code 2."""
    prog = os.path.basename(sys.argv[0]) if sys.argv else "pydepgate"
    stderr.write(f"{prog}: error: {message}\n")
    raise SystemExit(2)