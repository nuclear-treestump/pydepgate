"""
Helpers for analyzers that produce signals carrying enrichment hints.

Enrichers (in `pydepgate.enrichers`) consume signals via the
`enrichment_hints` field on `Signal`. When an analyzer flags a
signal for enrichment, it typically also stashes the raw literal
value under the context key `_full_value` so the enricher can
consume the data without re-extracting it from the source bytes.

This module centralizes the stash logic, including a hard cap on
the amount of data retained per signal. The cap protects against
pathological inputs (multi-megabyte embedded blobs in a single
literal) that would otherwise inflate per-finding memory.

The leading underscore on the `_full_value` context key marks it as
pipeline-internal; the JSON reporter omits underscore-prefixed keys
from serialized output, so this data does not bloat the wire format.
"""

from __future__ import annotations


# Maximum bytes retained in `context['_full_value']` per signal.
# Above this size, the value is truncated and
# `context['_full_value_truncated']` is set to True.
#
# Sized so that the enricher's 512KB total budget can accommodate
# the full stashed value plus expansion across three decompression
# layers without overflow. Most real-world payloads land far below
# this cap (the LiteLLM 1.82.8 attack was 34KB); the cap exists for
# defense against pathological inputs, not for shaping normal use.
MAX_STASHED_VALUE_BYTES = 256 * 1024


def stash_value(value: str | bytes) -> tuple[str | bytes, bool]:
    """Truncate the value if it exceeds the per-signal stash cap.

    Args:
        value: The literal value (str or bytes) to stash.

    Returns:
        A tuple `(stashed_value, truncated)`. The stashed_value is
        the (possibly truncated) original; truncated is True if
        truncation occurred.

    The function preserves the input type: a str input returns a
    str output, a bytes input returns bytes. The cap is applied on
    byte length: for str inputs the value is encoded as UTF-8 to
    measure size, and truncation is by character count (an
    over-estimate that keeps the value as str and may retain a few
    extra bytes past the strict cap; acceptable since the cap is a
    safety floor, not a precise limit).

    In practice, payloads of interest are pure ASCII (base64, hex,
    or `0x`-prefixed lists), so byte length and character count
    coincide.
    """
    if isinstance(value, str):
        encoded = value.encode("utf-8", errors="replace")
        if len(encoded) > MAX_STASHED_VALUE_BYTES:
            return value[:MAX_STASHED_VALUE_BYTES], True
        return value, False
    if len(value) > MAX_STASHED_VALUE_BYTES:
        return value[:MAX_STASHED_VALUE_BYTES], True
    return value, False