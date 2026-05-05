"""pydepgate.enrichers._unwrap

The unwrap loop for the payload_peek enricher.

Given an initial value (the analyzer-stashed `_full_value`), this
module repeatedly transforms it through recognized text encodings
and binary compression formats until a terminal classification is
reached, the configured depth limit fires, or the cumulative
output budget is exceeded.

Public surface:

  `unwrap(initial, max_depth, max_budget) -> UnwrapResult`
  `Layer` (frozen dataclass describing one transformation step)
  `UnwrapResult` (frozen dataclass with the chain and terminal
                  classification)
  Status constants for `UnwrapResult.status`.

Safety invariants
-----------------
The loop never executes, imports, or compiles any input. Decompression
is bounded per-step using `decompressobj`-style streaming with a
`max_length` cap so a malicious 1KB input cannot decompress to a
gigabyte. Cumulative output is bounded by the budget across the whole
chain so three consecutive 64KB-cap layers can't pump 192KB through
when the user asked for a 64KB total budget.

Pickle data, when detected, is classified as terminal with
`pickle_warning=True`. The loop never calls `pickle.loads` because
that IS code execution by design.

Loop detection: if a transformation produces output equal to its
input (a degenerate case — shouldn't happen with well-formed
inputs but possible with weird edge cases), the loop breaks with
a `loop_detected` status rather than spinning.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import lzma
import re
import zlib
from dataclasses import dataclass

from pydepgate.enrichers._magic import (
    detect_format,
    scan_indicators,
)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydepgate.enrichers._asn1 import FormatContext


# Status constants for UnwrapResult.status.
STATUS_COMPLETED = "completed"
STATUS_EXHAUSTED_DEPTH = "exhausted_depth"
STATUS_EXHAUSTED_BUDGET = "exhausted_budget"
STATUS_DECODE_ERROR = "decode_error"
STATUS_LOOP_DETECTED = "loop_detected"


# Internal exceptions; these never escape `unwrap`. They exist so
# the per-step transforms can signal failure in a typed way.

class _DecodeError(Exception):
    """A transform failed to produce valid output from its input."""


class _BudgetExceeded(Exception):
    """A transform's output would exceed the remaining budget."""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Layer:
    """One transformation step in the unwrap chain.

    Attributes:
        kind: The transformation applied. One of "base64", "hex",
            "hex_0x_list", "zlib", "gzip", "bzip2", "lzma".
        input_size: Bytes (or chars, for str inputs) at this step's
            entry.
        output_size: Bytes produced by this step.
    """
    kind: str
    input_size: int
    output_size: int


@dataclass(frozen=True)
class UnwrapResult:
    """The outcome of the unwrap loop.

    Attributes:
        chain: Tuple of Layer instances, one per successful
            transformation. Empty if the input was already terminal.
        final_bytes: The bytes after the last transformation (or
            the original input encoded as bytes if no transforms
            ran).
        final_kind: Terminal classification of `final_bytes`. One
            of "python_source", "ascii_text", "binary_unknown",
            "pickle_data", "pe_executable", "elf_executable",
            "png_image", "zip_archive". When `status` is one of
            the exhaustion or error statuses, `final_kind` carries
            whatever the last classification produced.
        status: Why the loop stopped. One of the STATUS_*
            constants.
        indicators: For `python_source` and `ascii_text` terminals,
            a tuple of indicator strings found in `final_bytes`.
            Empty otherwise.
        pickle_warning: True iff `final_kind == "pickle_data"`.
            Surfaced separately so renderers can highlight it
            without parsing `final_kind`.
        continues_as: When `status == "exhausted_depth"`, the kind
            of the next would-be layer (e.g. "base64", "zlib") so
            the renderer can say "depth limit reached; payload
            continues as base64." None otherwise.
        details: Structured per-format detail object propagated
            from the terminal FormatDetection. Currently
            populated when the terminal is binary_unknown and
            looks_like_der was true, in which case it carries a
            DERClassification. None otherwise.
    """
    chain: tuple[Layer, ...]
    final_bytes: bytes
    final_kind: str
    status: str
    indicators: tuple[str, ...]
    pickle_warning: bool
    continues_as: str | None = None
    details: FormatContext | None = None


# ---------------------------------------------------------------------------
# Per-format transforms
# ---------------------------------------------------------------------------

# Whitespace-only chars stripped from text-encoded inputs before
# decoding. Real-world payloads are sometimes line-wrapped or
# split across whitespace.
_WHITESPACE_RE = re.compile(r"\s+")


def _decode_base64(data: str | bytes, max_output: int) -> bytes:
    """Decode standard or URL-safe base64. Bounded by max_output."""
    if isinstance(data, bytes):
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError as e:
            raise _DecodeError(f"base64 input not ASCII: {e}") from e
    else:
        text = data
    stripped = _WHITESPACE_RE.sub("", text)
    # Try standard then URL-safe; both share most of the alphabet.
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        if decoder is base64.urlsafe_b64decode:
            try:               
                # Standard base64 allows some non-alphabet chars as
                # noise; URL-safe does not. If we see those chars, no
                # need to try URL-safe.
                # Also 'validate' doesn't exist for urlsafe_b64decode, so we have to pre-check. 
                result = decoder(stripped)
            except (binascii.Error, ValueError):
                continue
        else:
            try:
               result = decoder(stripped, validate=True)
            except (binascii.Error, ValueError):
                continue
        if len(result) > max_output:
            raise _BudgetExceeded(
                f"base64 output {len(result)} exceeds budget {max_output}"
            )
        return result
    raise _DecodeError("base64 input did not validate")

def _decode_pem(data: str | bytes, max_output: int) -> bytes:
    """Strip PEM armor and base64-decode the body.

    Reuses the same regex (_PEM_FULL_RE) that is_pem matched on
    so the body extraction is consistent with detection. The body
    is whitespace-stripped before base64 decoding to handle the
    standard line-wrapped form. Output is bounded by max_output.
    """
    # Late import to avoid a circular module-level dependency:
    # _magic.py imports from us indirectly via detect_format
    # callers; importing it at top-level inside this module
    # would create a circular module-load chain in some test
    # configurations. Local import is cheap (cached after first
    # call).
    from pydepgate.enrichers._magic import _PEM_FULL_RE

    if isinstance(data, bytes):
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError as e:
            raise _DecodeError(f"PEM input not ASCII: {e}") from e
    else:
        text = data

    match = _PEM_FULL_RE.search(text)
    if match is None:
        raise _DecodeError(
            "PEM markers expected (BEGIN/END pair) but not found"
        )

    body = match.group(2)
    body_no_ws = _WHITESPACE_RE.sub("", body)

    try:
        result = base64.b64decode(body_no_ws, validate=True)
    except binascii.Error as e:
        raise _DecodeError(
            f"PEM body base64 decode failed: {e}"
        ) from e

    if len(result) > max_output:
        raise _BudgetExceeded(
            f"PEM decoded body {len(result)} bytes exceeds budget {max_output}"
        )
    return result


def _decode_pure_hex(data: str | bytes, max_output: int) -> bytes:
    """Decode a pure-hex string."""
    if isinstance(data, bytes):
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError as e:
            raise _DecodeError(f"hex input not ASCII: {e}") from e
    else:
        text = data
    stripped = _WHITESPACE_RE.sub("", text)
    try:
        result = bytes.fromhex(stripped)
    except ValueError as e:
        raise _DecodeError(f"hex decode failed: {e}") from e
    if len(result) > max_output:
        raise _BudgetExceeded(
            f"hex output {len(result)} exceeds budget {max_output}"
        )
    return result


def _decode_hex_0x_list(data: str | bytes, max_output: int) -> bytes:
    """Decode a 0x-prefixed comma-or-space-separated list of bytes."""
    if isinstance(data, bytes):
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError as e:
            raise _DecodeError(f"hex-list input not ASCII: {e}") from e
    else:
        text = data
    tokens = [t for t in re.split(r"[,\s]+", text.strip()) if t]
    try:
        ints = [int(t.removeprefix("0x"), 16) for t in tokens]
    except ValueError as e:
        raise _DecodeError(f"hex-list parse failed: {e}") from e
    for v in ints:
        if v < 0 or v > 0xFF:
            raise _DecodeError(f"hex-list value {v:#x} out of byte range")
    if len(ints) > max_output:
        raise _BudgetExceeded(
            f"hex-list output {len(ints)} exceeds budget {max_output}"
        )
    return bytes(ints)


def _decompress_with_object(decomp_obj, data: bytes, max_output: int) -> bytes:
    """Common path for stream-based decompression objects.

    Uses the `max_length` parameter to `decompress` so we never
    materialize more than the budget allows. If the object reports
    itself as not done after producing max_output bytes, we treat
    that as budget exhaustion.
    """
    try:
        result = decomp_obj.decompress(data, max_length=max_output)
    except (zlib.error, OSError, ValueError) as e:
        raise _DecodeError(f"decompression failed: {e}") from e
    # `eof` attribute is on bz2.BZ2Decompressor and lzma.LZMADecompressor;
    # zlib decompressobj has `eof` only via unused_data check.
    finished = getattr(decomp_obj, "eof", None)
    if finished is False and len(result) >= max_output:
        raise _BudgetExceeded(
            f"decompression output >= budget {max_output} but stream not done"
        )
    if finished is None:
        # zlib path: check unconsumed_tail or unused_data heuristically.
        unused = getattr(decomp_obj, "unconsumed_tail", b"")
        if unused and len(result) >= max_output:
            raise _BudgetExceeded(
                f"zlib decompression hit budget {max_output} with input remaining"
            )
    return result


def _decompress_zlib(data: bytes, max_output: int) -> bytes:
    return _decompress_with_object(zlib.decompressobj(), data, max_output)


def _decompress_gzip(data: bytes, max_output: int) -> bytes:
    # wbits = 16 + 15 selects the gzip wrapper.
    return _decompress_with_object(
        zlib.decompressobj(wbits=16 + 15), data, max_output,
    )


def _decompress_bzip2(data: bytes, max_output: int) -> bytes:
    return _decompress_with_object(bz2.BZ2Decompressor(), data, max_output)


def _decompress_lzma(data: bytes, max_output: int) -> bytes:
    return _decompress_with_object(lzma.LZMADecompressor(), data, max_output)


# Dispatch table: kind -> transform function. Used by the unwrap loop.
_TRANSFORMS = {
    "base64": _decode_base64,
    "hex": _decode_pure_hex,
    "hex_0x_list": _decode_hex_0x_list,
    "pem": _decode_pem,
    "zlib": _decompress_zlib,
    "gzip": _decompress_gzip,
    "bzip2": _decompress_bzip2,
    "lzma": _decompress_lzma,
}

def _apply_transform(kind: str, data, max_output: int) -> bytes:
    transform = _TRANSFORMS.get(kind)
    if transform is None:
        raise _DecodeError(f"no transform for kind {kind!r}")
    return transform(data, max_output)


# ---------------------------------------------------------------------------
# Pre-loop input normalization
# ---------------------------------------------------------------------------

def _to_bytes_for_loop(initial) -> bytes:
    """Convert the initial input to bytes for the loop body.

    The unwrap loop's working type is bytes after the first
    transformation. Before any transformation, we normalize the
    input to bytes so the detect-then-transform machinery has a
    consistent shape. Strings encode as UTF-8 with replacement.
    """
    if isinstance(initial, bytes):
        return initial
    if isinstance(initial, str):
        return initial.encode("utf-8", errors="replace")
    raise TypeError(
        f"unwrap input must be str or bytes, got {type(initial).__name__}"
    )


# ---------------------------------------------------------------------------
# The unwrap loop
# ---------------------------------------------------------------------------

def unwrap(
    initial: str | bytes,
    *,
    max_depth: int,
    max_budget: int,
) -> UnwrapResult:
    """Repeatedly transform `initial` through recognized formats.

    Args:
        initial: The input value, str or bytes. Typically the
            analyzer-stashed `_full_value` from a Signal context.
        max_depth: Maximum number of transformations to apply.
            Depth 3 is recommended; the project ships that as
            the default but the value is configurable.
        max_budget: Cumulative cap on bytes produced across all
            layers. 524288 (512KB) is recommended.

    Returns:
        An UnwrapResult describing the chain and terminal state.
        See the dataclass docstring for field semantics.

    The loop never raises; all error paths produce an UnwrapResult
    with an appropriate status.
    """
    if max_depth < 1:
        raise ValueError(f"max_depth must be >= 1, got {max_depth}")
    if max_budget < 16:
        raise ValueError(f"max_budget must be >= 16, got {max_budget}")

    try:
        current = _to_bytes_for_loop(initial)
    except TypeError as e:
        return UnwrapResult(
            chain=(),
            final_bytes=b"",
            final_kind="binary_unknown",
            status=STATUS_DECODE_ERROR,
            indicators=(),
            pickle_warning=False,
            continues_as=None,
        )

    chain: list[Layer] = []
    budget_remaining = max_budget

    # The detection function takes str or bytes. After the first
    # iteration we always have bytes; for the FIRST iteration we
    # let detect_format see the original type (so a str input
    # gets text-encoding detection on its native form).
    detection_input: str | bytes
    detection_input = initial if isinstance(initial, (str, bytes)) else current

    for _ in range(max_depth):
        det = detect_format(detection_input)
        if det.is_terminal:
            return _terminal_result(chain, current, det.kind, det.details)
        try:
            new_bytes = _apply_transform(
                det.kind, detection_input, budget_remaining,
            )
        except _BudgetExceeded:
            return UnwrapResult(
                chain=tuple(chain),
                final_bytes=current,
                final_kind="binary_unknown",
                status=STATUS_EXHAUSTED_BUDGET,
                indicators=(),
                pickle_warning=False,
                continues_as=det.kind,
            )
        except _DecodeError:
            return UnwrapResult(
                chain=tuple(chain),
                final_bytes=current,
                final_kind="binary_unknown",
                status=STATUS_DECODE_ERROR,
                indicators=(),
                pickle_warning=False,
                continues_as=None,
            )

        # Loop detection: a transform that returns its input unchanged
        # (or its byte-equivalent) would spin forever. Compare against
        # the bytes form of the current input.
        current_as_bytes = (
            detection_input.encode("utf-8", errors="replace")
            if isinstance(detection_input, str)
            else detection_input
        )
        if new_bytes == current_as_bytes:
            return UnwrapResult(
                chain=tuple(chain),
                final_bytes=current,
                final_kind="binary_unknown",
                status=STATUS_LOOP_DETECTED,
                indicators=(),
                pickle_warning=False,
                continues_as=None,
            )

        chain.append(Layer(
            kind=det.kind,
            input_size=len(current_as_bytes),
            output_size=len(new_bytes),
        ))
        budget_remaining -= len(new_bytes)
        current = new_bytes
        detection_input = new_bytes

        if budget_remaining <= 0:
            # We just consumed the rest of the budget. If the next
            # detection would be terminal anyway, fall through to
            # the loop's natural exit; if it would be another
            # transformation, we can't run it.
            next_det = detect_format(current)
            if next_det.is_terminal:
                return _terminal_result(
                    chain, current, next_det.kind, next_det.details,
                )
            return UnwrapResult(
                chain=tuple(chain),
                final_bytes=current,
                final_kind="binary_unknown",
                status=STATUS_EXHAUSTED_BUDGET,
                indicators=(),
                pickle_warning=False,
                continues_as=next_det.kind,
            )

    # Loop ran max_depth times without a terminal classification.
    # Check if there's still more to unwrap.
    next_det = detect_format(current)
    if next_det.is_terminal:
        return _terminal_result(
            chain, current, next_det.kind, next_det.details,
        )
    return UnwrapResult(
        chain=tuple(chain),
        final_bytes=current,
        final_kind="binary_unknown",
        status=STATUS_EXHAUSTED_DEPTH,
        indicators=(),
        pickle_warning=False,
        continues_as=next_det.kind,
    )


def _terminal_result(
    chain: list[Layer],
    final_bytes: bytes,
    terminal_kind: str,
    terminal_details: "FormatContext | None" = None,
) -> UnwrapResult:
    """Build the UnwrapResult for a successful terminal classification.

    The terminal_details argument carries any FormatContext that
    detect_format produced for the terminal classification (currently
    a DERClassification when binary_unknown matched looks_like_der).
    """
    indicators: tuple[str, ...] = ()
    if terminal_kind in ("python_source", "ascii_text"):
        indicators = scan_indicators(final_bytes)
    return UnwrapResult(
        chain=tuple(chain),
        final_bytes=final_bytes,
        final_kind=terminal_kind,
        status=STATUS_COMPLETED,
        indicators=indicators,
        pickle_warning=(terminal_kind == "pickle_data"),
        continues_as=None,
        details=terminal_details,
    )