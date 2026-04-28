"""
The payload_peek enricher.

Consumes signals flagged with the `payload_peek` enrichment hint by
upstream analyzers (`density_analyzer`, `encoding_abuse`), runs the
unwrap loop on the analyzer-stashed `_full_value`, augments the
signal with a `decoded` block, and emits an `ENC002` signal when
the unwrap chain reaches depth 2 or beyond (the user's "deeply
nested = signal of fuckery" threshold).

The enricher is configurable on three axes:

  - `min_length`: only signals whose `context['length']` is at or
    above this size will be peeked. Default 1024 bytes; floor 16.
    Below 16, the unwrap loop cannot reliably detect any magic.
  - `max_depth`: depth limit for the unwrap loop. Default 3.
  - `max_budget`: cumulative byte budget across the unwrap chain.
    Default 524288 (512KB).

All three are configurable per-instance. PR 3 will wire CLI flags
to construct an instance with user-chosen values.

The enricher is stateless across calls (statelessness contract from
`pydepgate.enrichers.base`). All per-call state lives in the local
variables of `enrich`. Picklability follows from the constructor
holding only `int` values.

ENC002 emission
---------------
When the unwrap chain has 2+ layers (regardless of completion vs
exhaustion), the enricher emits an `ENC002` signal at the same
location as the originating signal. Confidence calibration:

  - depth 2, completed:    AMBIGUOUS  (legitimate b64+gzip patterns
                                       exist for embedded assets)
  - depth 3, completed:    MEDIUM
  - exhausted_depth:       HIGH       (chain wanted to keep going;
                                       we stopped it)

The new signal carries the same `decoded` context block as the
originating signal so downstream rules and reporters can match on
either signal_id and find the same data. ENC002 itself is NOT
flagged for further enrichment (no `enrichment_hints`); we don't
want an enrichment of an enrichment.
"""

from __future__ import annotations

import dataclasses
from typing import Iterable

from pydepgate.analyzers.base import Confidence, Signal
from pydepgate.engines.base import ScanContext
from pydepgate.enrichers.base import Enricher
from pydepgate.enrichers._unwrap import (
    Layer,
    STATUS_COMPLETED,
    STATUS_DECODE_ERROR,
    STATUS_EXHAUSTED_BUDGET,
    STATUS_EXHAUSTED_DEPTH,
    STATUS_LOOP_DETECTED,
    UnwrapResult,
    unwrap,
)


# Public constants. Exposed so CLI argument parsing in PR 3 can
# import the same values for help text and validation.
DEFAULT_MIN_LENGTH = 1024
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_BUDGET = 512 * 1024
MIN_LENGTH_FLOOR = 16
MIN_BUDGET_FLOOR = 1024
MIN_DEPTH = 1

# How many bytes of the final layer to retain in the decoded block.
# Long enough to make a magic header obvious; short enough that the
# JSON output stays compact. Hex preview is 2x this size in chars
# (each byte renders as two hex chars), so 256 bytes -> 512 chars.
PREVIEW_BYTES = 256


class PayloadPeek(Enricher):
    """Consumer for `payload_peek`-tagged signals.

    See the module docstring for behavior. Constructed once per
    scan, picklable, stateless across calls.
    """

    def __init__(
        self,
        min_length: int = DEFAULT_MIN_LENGTH,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_budget: int = DEFAULT_MAX_BUDGET,
    ):
        if min_length < MIN_LENGTH_FLOOR:
            raise ValueError(
                f"min_length must be >= {MIN_LENGTH_FLOOR} "
                f"(got {min_length}); below this the unwrap loop "
                f"cannot reliably match magic-byte signatures"
            )
        if max_depth < MIN_DEPTH:
            raise ValueError(
                f"max_depth must be >= {MIN_DEPTH}, got {max_depth}"
            )
        if max_budget < MIN_BUDGET_FLOOR:
            raise ValueError(
                f"max_budget must be >= {MIN_BUDGET_FLOOR}, got {max_budget}"
            )
        self._min_length = min_length
        self._max_depth = max_depth
        self._max_budget = max_budget

    @property
    def name(self) -> str:
        return "payload_peek"

    @property
    def min_length(self) -> int:
        return self._min_length

    @property
    def max_depth(self) -> int:
        return self._max_depth

    @property
    def max_budget(self) -> int:
        return self._max_budget

    # -- core dispatch -------------------------------------------------

    def enrich(
        self,
        signals: tuple[Signal, ...],
        content: bytes,
        context: ScanContext,
    ) -> Iterable[Signal]:
        out: list[Signal] = []
        for sig in signals:
            if self.name not in sig.enrichment_hints:
                out.append(sig)
                continue

            decision = self._consider(sig)
            if decision is None:
                # Skipped (length below threshold, no full_value, or
                # unwrap could not produce useful output). Pass the
                # original signal through unchanged.
                out.append(sig)
                continue

            enriched_sig, derivative = decision
            out.append(enriched_sig)
            if derivative is not None:
                out.append(derivative)
        return tuple(out)

    # -- per-signal logic ----------------------------------------------

    def _consider(
        self,
        sig: Signal,
    ) -> tuple[Signal, Signal | None] | None:
        """Decide what to do with one hint-bearing signal.

        Returns:
          - None if the signal should be passed through unchanged.
          - (enriched_sig, None) if the signal should be replaced with
            an enriched version, with no derivative signal.
          - (enriched_sig, enc002_sig) if the signal should be replaced
            and accompanied by an ENC002 derivative.
        """
        length = sig.context.get("length", 0)
        if length < self._min_length:
            return None

        full_value = sig.context.get("_full_value")
        if full_value is None:
            return None
        if not isinstance(full_value, (str, bytes)):
            return None

        result = unwrap(
            full_value,
            max_depth=self._max_depth,
            max_budget=self._max_budget,
        )

        # If unwrap couldn't even produce a useful chain (no transforms,
        # input was already terminal), there's nothing to add. Skip.
        if not result.chain and result.status == STATUS_COMPLETED:
            return None

        decoded_block = self._build_decoded_block(result)
        new_context = {**sig.context, "decoded": decoded_block}
        enriched = dataclasses.replace(sig, context=new_context)

        derivative = self._maybe_emit_enc002(sig, result, decoded_block)
        return enriched, derivative

    # -- decoded-block construction ------------------------------------

    def _build_decoded_block(self, result: UnwrapResult) -> dict:
        """Produce the JSON-serializable `decoded` context block."""
        chain_dicts = [
            {
                "kind": layer.kind,
                "input_size": layer.input_size,
                "output_size": layer.output_size,
            }
            for layer in result.chain
        ]
        preview_bytes_actual = result.final_bytes[:PREVIEW_BYTES]
        block: dict = {
            "chain": chain_dicts,
            "layers_count": len(result.chain),
            "final_kind": result.final_kind,
            "final_bytes_size": len(result.final_bytes),
            "unwrap_status": result.status,
            "preview_hex": preview_bytes_actual.hex(),
            "preview_text": _bytes_as_text_preview(preview_bytes_actual),
            "preview_truncated": len(result.final_bytes) > PREVIEW_BYTES,
            "indicators": list(result.indicators),
            "pickle_warning": result.pickle_warning,
        }
        if result.continues_as is not None:
            block["continues_as"] = result.continues_as
        return block

    # -- ENC002 derivative ---------------------------------------------

    def _maybe_emit_enc002(
        self,
        original: Signal,
        result: UnwrapResult,
        decoded_block: dict,
    ) -> Signal | None:
        """Return an ENC002 signal if the chain warrants one, else None."""
        depth = len(result.chain)
        is_exhausted = result.status == STATUS_EXHAUSTED_DEPTH

        if depth < 2 and not is_exhausted:
            return None

        if is_exhausted:
            confidence = Confidence.HIGH
        elif depth >= 3:
            confidence = Confidence.MEDIUM
        else:
            # depth == 2, completed
            confidence = Confidence.AMBIGUOUS

        chain_summary = " -> ".join(layer.kind for layer in result.chain)
        if is_exhausted and result.continues_as:
            chain_summary += f" -> {result.continues_as} [DEPTH LIMIT REACHED]"

        # ENC002 carries its own context block (with the decoded data
        # plus a depth-summary string). It does NOT carry an
        # enrichment_hints set; no further enrichment.
        enc002_context = {
            "originating_signal_id": original.signal_id,
            "originating_analyzer": original.analyzer,
            "chain_summary": chain_summary,
            "layers_count": depth,
            "unwrap_status": result.status,
            "final_kind": result.final_kind,
            "decoded": decoded_block,
        }

        return Signal(
            analyzer="encoding_abuse",
            signal_id="ENC002",
            confidence=confidence,
            scope=original.scope,
            location=original.location,
            description=(
                f"deeply-nested encoded payload at line {original.location.line}: "
                f"{chain_summary} ({depth} transforms, "
                f"final form {result.final_kind})"
            ),
            context=enc002_context,
            # No enrichment_hints: ENC002 is itself a derivative; we
            # do not enrich enrichments.
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bytes_as_text_preview(data: bytes) -> str:
    """Render bytes as a human-readable preview.

    Each byte renders as itself if printable ASCII, '.' otherwise.
    Used for the right-hand gutter of an xxd-style hex dump in PR 3's
    human renderer; also useful as a quick eyeballable indicator in
    JSON output.
    """
    return "".join(
        chr(b) if 0x20 <= b <= 0x7E else "."
        for b in data
    )