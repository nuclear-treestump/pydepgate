"""
Argparse helpers and validation for the --decode-payload-depth feature.

Adds these flags to the CLI:

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

    --decode-iocs[={off,hashes,full}]
        Tristate controlling IOC and source extraction. Default
        off. 'hashes' adds a sidecar with SHA256/SHA512 of every
        decoded payload, plaintext, no archive. 'full' produces an
        encrypted archive (default password 'infected') containing
        the tree, hash records, and per-layer source dumps, plus a
        plaintext hash sidecar.

        Bare --decode-iocs (no value) is accepted as a deprecated
        synonym for --decode-iocs=hashes; this preserves backward
        compatibility with the previous boolean spelling. A
        deprecation notice is written to stderr when the bare form
        is detected.

    --decode-archive-password PASSWORD
        Password for the encrypted archive produced by
        --decode-iocs=full. Defaults to 'infected'. The default is
        the malware-research convention; AV vendors recognize it
        as a do-not-scan marker. Override only when delivery
        constraints require it. Note that ZipCrypto is not a
        confidentiality control.

    --decode-archive-stored
        Use STORED compression for the encrypted archive instead
        of DEFLATE. Produces a slightly larger archive but bypasses
        zlib entirely. Useful when byte-verifiable archive contents
        matter.

These flags follow the same env-var precedence pattern as the peek
flags (CLI > env > built-in default), and their argparse defaults
on subparsers use argparse.SUPPRESS so they don't clobber values
captured at the top-level parser when subcommands are dispatched.

Validation runs after parse_args via validate_decode_args. Hard
errors include 'depth set without --peek' and 'iocs mode set
without --peek'. Soft warnings cover the case of location/format/
archive flags being set when the decode pass is disabled, and the
deprecated bare --decode-iocs spelling.

Helpers for downstream dispatch:

    decode_iocs_mode(args) -> str
        Returns 'off', 'hashes', or 'full'. Use this anywhere you
        need to branch on the IOC mode.

    decode_extract_iocs(args) -> bool
        Returns True iff IOC extraction is enabled (mode is
        'hashes' or 'full'). This is the right replacement for any
        existing 'if args.decode_iocs:' check that pre-dated the
        tristate.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import TextIO


# Env var names. Constants so tests can reference them without retyping.
ENV_DECODE_DEPTH = "PYDEPGATE_DECODE_PAYLOAD_DEPTH"
ENV_DECODE_LOCATION = "PYDEPGATE_DECODE_LOCATION"
ENV_DECODE_FORMAT = "PYDEPGATE_DECODE_FORMAT"
ENV_DECODE_IOCS = "PYDEPGATE_DECODE_IOCS"
ENV_DECODE_ARCHIVE_PASSWORD = "PYDEPGATE_DECODE_ARCHIVE_PASSWORD"


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


# IOC tristate choices.
DECODE_IOCS_OFF = "off"
DECODE_IOCS_HASHES = "hashes"
DECODE_IOCS_FULL = "full"
DECODE_IOCS_CHOICES = (DECODE_IOCS_OFF, DECODE_IOCS_HASHES, DECODE_IOCS_FULL)
DEFAULT_DECODE_IOCS = DECODE_IOCS_OFF


# Default archive password. The string "infected" is the malware-
# research convention; AV vendors and analysis tools recognize it
# as a "quarantined sample, do not scan inside" marker.
DEFAULT_ARCHIVE_PASSWORD = "infected"


# Sentinel for "not set" on the depth flag. We can't use 0 because 0 is a
# legitimate (if unusual) user value meaning "do not run the decode
# pass." Any negative value works as the sentinel because the validator
# rejects anything below MIN_DECODE_DEPTH; we use -1 for clarity.
_DECODE_DEPTH_UNSET = -1


# Sentinel for "bare --decode-iocs flag was used" (deprecated form).
# argparse's `nargs="?"` plus `const=...` makes both
# `--decode-iocs` and `--decode-iocs=hashes` produce the same value
# in args.decode_iocs, so we need a distinguishable sentinel as
# const. The custom action below replaces it with "hashes" but
# records that the bare form was used so validate_decode_args can
# emit the deprecation notice.
_BARE_IOCS_SENTINEL = object()


class _DecodeIocsAction(argparse.Action):
    """Custom argparse action for the tristate --decode-iocs flag.

    Argparse's built-in choices validation runs before the action
    is called, so we cannot use choices=[...] AND distinguish the
    bare form via a sentinel. We do our own validation here.

    State recorded:
      args.decode_iocs: one of 'off', 'hashes', 'full'.
      args._decode_iocs_was_bare: True iff the user wrote
        --decode-iocs without any value (the deprecated form).
        Internal; the underscore prefix marks it as a private
        attribute that validate_decode_args reads.
    """

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values,
        option_string: str | None = None,
    ) -> None:
        if values is None or values is _BARE_IOCS_SENTINEL:
            # Bare --decode-iocs: deprecated synonym for hashes.
            setattr(namespace, self.dest, DECODE_IOCS_HASHES)
            setattr(namespace, "_decode_iocs_was_bare", True)
        elif values in DECODE_IOCS_CHOICES:
            setattr(namespace, self.dest, values)
            setattr(namespace, "_decode_iocs_was_bare", False)
        else:
            valid = ", ".join(repr(c) for c in DECODE_IOCS_CHOICES)
            parser.error(
                f"argument --decode-iocs: invalid choice: {values!r} "
                f"(choose from {valid})"
            )


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


def _env_iocs(stderr: TextIO | None = None) -> str:
    """Read the IOC mode from the environment.

    Falls back to the built-in default on miss or invalid value;
    invalid values produce a stderr warning so the user knows.
    """
    raw = os.environ.get(ENV_DECODE_IOCS)
    if raw is None or raw == "":
        return DEFAULT_DECODE_IOCS
    if raw not in DECODE_IOCS_CHOICES:
        if stderr is not None:
            valid = ", ".join(DECODE_IOCS_CHOICES)
            stderr.write(
                f"warning: environment variable {ENV_DECODE_IOCS}={raw!r} "
                f"is not a valid mode; expected one of {valid}; using "
                f"default {DEFAULT_DECODE_IOCS!r}.\n"
            )
        return DEFAULT_DECODE_IOCS
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
        default_iocs = argparse.SUPPRESS
        default_archive_password = argparse.SUPPRESS
        default_archive_stored = argparse.SUPPRESS
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
        default_iocs = _env_iocs(stderr=stderr)
        default_archive_password = _env_str(
            ENV_DECODE_ARCHIVE_PASSWORD, DEFAULT_ARCHIVE_PASSWORD,
        )
        default_archive_stored = False

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
            "<cwd>/decoded/{STATUS}_{timestamp}_{target}{ext} where "
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
        nargs="?",
        const=_BARE_IOCS_SENTINEL,
        default=default_iocs,
        action=_DecodeIocsAction,
        metavar="MODE",
        help=(
            "IOC and source-extraction mode for the decoded-payload "
            "report. Default 'off' (tree only, no extracted source). "
            "'hashes' adds a sidecar with SHA256/SHA512 of every "
            "decoded payload, plaintext, no archive. 'full' produces "
            "an encrypted archive (default password 'infected') "
            "containing the tree, hash records, and per-layer source "
            "dumps, plus a plaintext hash sidecar. Bare --decode-iocs "
            "is accepted as a deprecated synonym for "
            "--decode-iocs=hashes; use the explicit form to avoid the "
            f"deprecation notice. (env: {ENV_DECODE_IOCS})"
        ),
    )

    group.add_argument(
        "--decode-archive-password",
        type=str,
        default=default_archive_password,
        metavar="PASSWORD",
        help=(
            "Password for the encrypted archive produced by "
            "--decode-iocs=full. Defaults to 'infected' (per the "
            "malware-research convention; AV vendors recognize this "
            "as a do-not-scan marker). Override only if you need to "
            "deliver the archive somewhere that cannot accept the "
            "default. ZipCrypto is cryptographically broken; this is "
            "not a confidentiality control. "
            f"(env: {ENV_DECODE_ARCHIVE_PASSWORD})"
        ),
    )

    group.add_argument(
        "--decode-archive-stored",
        action="store_true",
        default=default_archive_stored,
        help=(
            "Use STORED compression for the decoded-payload archive "
            "instead of DEFLATE. Produces a slightly larger archive "
            "but bypasses zlib entirely; useful when byte-verifiable "
            "archive contents matter."
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


def decode_iocs_mode(args: argparse.Namespace) -> str:
    """Return the IOC mode as one of 'off', 'hashes', 'full'.

    Use this anywhere you need to branch on the IOC mode (e.g.
    deciding whether to produce the hash sidecar, whether to wrap
    the report in an encrypted archive, etc).
    """
    mode = getattr(args, "decode_iocs", DEFAULT_DECODE_IOCS)
    if mode not in DECODE_IOCS_CHOICES:
        # Defensive: if downstream code mutates the namespace with
        # an invalid value, fall back to the default rather than
        # propagating it.
        return DEFAULT_DECODE_IOCS
    return mode


def decode_extract_iocs(args: argparse.Namespace) -> bool:
    """True iff IOC extraction (hashes and source) should run.

    This is the right replacement for any pre-tristate code that
    did `if args.decode_iocs:`. After the swap to the tristate,
    `args.decode_iocs` is always a non-empty string and is therefore
    always truthy; the bare-truthiness check would silently always
    be True. Callers that want a boolean should use this helper.
    """
    return decode_iocs_mode(args) != DECODE_IOCS_OFF


def decode_archive_password(args: argparse.Namespace) -> str:
    """Return the password to use for the encrypted archive.

    Defaults to DEFAULT_ARCHIVE_PASSWORD ('infected') when not set.
    """
    pw = getattr(args, "decode_archive_password", DEFAULT_ARCHIVE_PASSWORD)
    if pw is None or pw == "":
        return DEFAULT_ARCHIVE_PASSWORD
    return pw


def decode_archive_compression(args: argparse.Namespace) -> str:
    """Return the compression mode for the archive: 'deflate' or 'stored'."""
    if getattr(args, "decode_archive_stored", False):
        return "stored"
    return "deflate"


def validate_decode_args(
    args: argparse.Namespace,
    *,
    stderr: TextIO | None = None,
) -> None:
    """Validate parsed decode-payload arguments.

    Hard errors (raise SystemExit):
      - --decode-payload-depth set without --peek.
      - --decode-payload-depth out of [MIN_DECODE_DEPTH, MAX_DECODE_DEPTH].
      - --decode-iocs in {hashes, full} without --peek.

    Soft warnings (write to stderr, return normally):
      - --decode-location set but --decode-payload-depth not enabled.
      - --decode-format set but --decode-payload-depth not enabled.
      - --decode-iocs != off but --decode-payload-depth not enabled.
      - --decode-archive-password set but --decode-iocs != full.
      - --decode-archive-stored set but --decode-iocs != full.
      - Bare --decode-iocs (deprecated form).
    """
    if stderr is None:
        stderr = sys.stderr

    enabled = decode_enabled(args)
    location = getattr(args, "decode_location", None)
    fmt = getattr(args, "decode_format", DEFAULT_DECODE_FORMAT)
    iocs = decode_iocs_mode(args)
    archive_password = getattr(args, "decode_archive_password", DEFAULT_ARCHIVE_PASSWORD)
    archive_password_set = (
        archive_password is not None
        and archive_password != ""
        and archive_password != DEFAULT_ARCHIVE_PASSWORD
    )
    archive_stored = bool(getattr(args, "decode_archive_stored", False))

    fmt_was_explicit = (
        location is not None or
        fmt != DEFAULT_DECODE_FORMAT
    )

    # Deprecation notice for the bare --decode-iocs spelling. This
    # fires regardless of whether the decode pass is enabled, so the
    # user sees it on the same run they typed the bare form (rather
    # than only when their other flags happen to align).
    if getattr(args, "_decode_iocs_was_bare", False):
        stderr.write(
            "warning: bare --decode-iocs is deprecated; use "
            "--decode-iocs=hashes for the same behavior. The bare "
            "spelling will be removed in a future release.\n"
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

        # Soft warnings about archive flags that have no effect
        # outside --decode-iocs=full.
        if iocs != DECODE_IOCS_FULL:
            unused = []
            if archive_password_set:
                unused.append("--decode-archive-password")
            if archive_stored:
                unused.append("--decode-archive-stored")
            if unused:
                stderr.write(
                    f"warning: {', '.join(unused)} "
                    f"{'has' if len(unused) == 1 else 'have'} no "
                    f"effect when --decode-iocs is not 'full' "
                    f"(currently {iocs!r}); ignored.\n"
                )
        return

    # Disabled path: --decode-payload-depth was not set.
    # Hard error: --decode-iocs requires --peek (because the IOC
    # extraction depends on the peek-decoded bytes; without peek
    # there is nothing to hash). This applies regardless of whether
    # the user set --decode-payload-depth, because --decode-iocs is
    # documented to extract IOCs from decoded payloads.
    peek_on = bool(getattr(args, "peek", False))
    if iocs != DECODE_IOCS_OFF and not peek_on:
        _exit_with_error(
            stderr,
            f"--decode-iocs={iocs} requires --peek to be enabled. "
            f"IOC extraction operates on the peek enricher's "
            f"decoded output; without --peek there is nothing to "
            f"hash."
        )

    # Soft warning path: depth is disabled, but other decode flags
    # were set. Tell the user they had no effect.
    ignored = []
    if location is not None:
        ignored.append("--decode-location")
    if fmt != DEFAULT_DECODE_FORMAT:
        ignored.append("--decode-format")
    if iocs != DEFAULT_DECODE_IOCS:
        ignored.append(f"--decode-iocs={iocs}")
    if archive_password_set:
        ignored.append("--decode-archive-password")
    if archive_stored:
        ignored.append("--decode-archive-stored")
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
