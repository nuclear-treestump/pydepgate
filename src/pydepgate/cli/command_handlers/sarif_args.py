"""pydepgate.cli.command_handlers.sarif_args

Argparse helpers and validation for the SARIF output format.

Adds these flags to the CLI:

    --sarif-srcroot PATH
        Source root path used when emitting SARIF documents.
        When set, per-result artifactLocation entries on real
        on-disk paths are tagged with uriBaseId=PROJECTROOT, and
        the document's originalUriBaseIds.PROJECTROOT entry
        carries this value as its URI. GitHub code scanning
        consumers use this to resolve paths relative to the repo
        root.

The flag follows the same env-var precedence pattern as the peek
and decode flags (CLI > env > built-in default), and its argparse
default on subparsers uses argparse.SUPPRESS so it does not
clobber the value captured at the top-level parser when
subcommands are dispatched.

Validation runs after parse_args via validate_sarif_args. Soft
warnings cover the case of --sarif-srcroot being set when SARIF
is not the active format (--format != sarif).

Helpers for downstream dispatch:

    sarif_srcroot(args) -> str | None
        Returns the effective srcroot value, or None if unset.
        Treats empty string as unset, consistent with how
        decode_archive_password handles empty-string values.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import TextIO

# Env var name. Constant so tests can reference it without
# retyping the literal in multiple places.
ENV_SARIF_SRCROOT = "PYDEPGATE_SARIF_SRCROOT"


def _env_str(name: str, default: str | None) -> str | None:
    """Read a string env var, treating empty as unset.

    Mirrors the helper in decode_args.py so the unset semantics
    match across flag families.
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw


def add_sarif_arguments(
    parser: argparse.ArgumentParser,
    *,
    is_subparser: bool = False,
) -> None:
    """Add SARIF-specific arguments to a parser.

    Called both on the top-level parser AND on each subparser so
    the flag works in either position. When called on a subparser,
    the default is argparse.SUPPRESS so omitted flags do not
    clobber the value captured by the top-level parser. Mirrors
    the pattern used by add_decode_arguments and
    add_peek_arguments.

    Args:
        parser: the parser or subparser to augment.
        is_subparser: True when called on a subparser; controls
            the default value strategy.
    """
    if is_subparser:
        default_srcroot = argparse.SUPPRESS
    else:
        default_srcroot = _env_str(ENV_SARIF_SRCROOT, None)

    group = parser.add_argument_group(
        "SARIF output",
        "Flags affecting SARIF 2.1.0 output. Only meaningful "
        "when --format sarif is set; otherwise these flags are "
        "ignored with a warning.",
    )
    group.add_argument(
        "--sarif-srcroot",
        dest="sarif_srcroot",
        default=default_srcroot,
        metavar="PATH",
        help=(
            "Source root path for SARIF output. When set, the "
            "emitted SARIF document declares this as the "
            "PROJECTROOT URI base, and on-disk artifact "
            "locations are tagged so GitHub code scanning "
            "resolves paths relative to it. No path validation "
            "is performed; the value is passed through to the "
            "SARIF document. Only meaningful with --format "
            "sarif. Can also be set via the "
            f"{ENV_SARIF_SRCROOT} environment variable."
        ),
    )


def sarif_srcroot(args: argparse.Namespace) -> str | None:
    """Return the effective sarif_srcroot value, or None if unset.

    Treats empty string the same as unset, consistent with how
    decode_archive_password handles the empty-string case. The
    return value is suitable to pass directly to sarif.render()
    as the srcroot kwarg.
    """
    raw = getattr(args, "sarif_srcroot", None)
    if raw is None or raw == "":
        return None
    return raw


def validate_sarif_args(
    args: argparse.Namespace,
    *,
    stderr: TextIO | None = None,
) -> None:
    """Validate parsed SARIF arguments.

    Soft warnings (write to stderr, return normally):
      - --sarif-srcroot set when --format is not 'sarif'.
        The flag has no effect on other output formats; the
        warning catches user typos or stale CI scripts.

    No hard errors are raised. SARIF-flag validation is
    advisory because the flag is purely additive on SARIF runs
    and inert on others; failing the run because of a flag
    that would have been ignored is user-hostile.

    Args:
        args: the parsed argparse.Namespace.
        stderr: optional stream to write warnings to. Defaults
            to sys.stderr. Tests pass an io.StringIO to capture
            output.
    """
    if stderr is None:
        stderr = sys.stderr

    srcroot = sarif_srcroot(args)
    fmt = getattr(args, "format", None)

    if srcroot is not None and fmt != "sarif":
        stderr.write(
            "warning: --sarif-srcroot is set but --format is "
            "not 'sarif'; the value will be ignored.\n"
        )
