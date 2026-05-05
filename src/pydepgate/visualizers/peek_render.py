"""
pydepgate.visualizers.peek_render

Human-format renderer for the `decoded` context block produced by
the payload_peek enricher.

Two modes:

  - Summary (default): one or two lines suitable for the per-finding
    body in standard human output. Shows the chain shape, layer
    count, terminal kind, and any indicator strings.

  - Verbose (--peek-chain): multi-line block with per-layer sizes,
    full indicator list, xxd-style hex dump of the first 256 bytes
    of the final form, and a prominent pickle warning when present.

Both modes are pure: same input always produces same output, no
I/O, no side effects. The reporter writes the returned string to
its stream.

Color handling
--------------
A `color` argument controls escape-sequence emission. When None,
output is plain text (suitable for files, pipes, non-TTY). When a
ColorScheme is provided, certain elements get highlighted:

  - The pickle warning, when present, renders in red+bold.
  - Layer kind names and indicator keywords get a dim treatment.
  - Section headers ("decoded chain:") get bold.

The ColorScheme dataclass is structurally compatible with whatever
ANSI scheme the existing reporter already uses; the caller passes
its own scheme and this module just inserts the pre/post strings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


# ---------------------------------------------------------------------------
# Color scheme
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ColorScheme:
    """Pre/post escape sequences for highlighted text spans.

    Each pair is two strings (pre, post) wrapped around content.
    Defaults to empty (plain text).
    """
    bold_pre: str = ""
    bold_post: str = ""
    dim_pre: str = ""
    dim_post: str = ""
    red_pre: str = ""
    red_post: str = ""
    yellow_pre: str = ""
    yellow_post: str = ""


PLAIN = ColorScheme()


# Standard ANSI scheme. Reporter callers can substitute their own.
ANSI = ColorScheme(
    bold_pre="\033[1m",
    bold_post="\033[0m",
    dim_pre="\033[2m",
    dim_post="\033[0m",
    red_pre="\033[31;1m",   # red + bold for the pickle warning
    red_post="\033[0m",
    yellow_pre="\033[33m",
    yellow_post="\033[0m",
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_decoded_block(
    decoded: Mapping,
    *,
    verbose: bool,
    color: ColorScheme | None = None,
    indent: str = "  ",
) -> str:
    """Render the decoded block as text.

    Args:
        decoded: The `decoded` context block produced by the
            PayloadPeek enricher. See payload_peek.py for the
            schema; the keys this function reads are listed
            below.
        verbose: True iff --peek-chain was passed; selects the
            multi-line verbose mode.
        color: Optional color scheme. None means plain text.
        indent: String prefixed to every output line. Lets the
            reporter nest the block under its parent finding.

    Returns:
        A multi-line string ending in a newline. May be empty if
        the decoded block is malformed.

    Keys read from `decoded`:
        chain (list of {kind, input_size, output_size})
        layers_count (int)
        final_kind (str)
        final_bytes_size (int)
        unwrap_status (str)
        preview_hex (str)
        preview_text (str)
        preview_truncated (bool)
        indicators (list of str)
        pickle_warning (bool)
        continues_as (str, optional)
    """
    if color is None:
        color = PLAIN
    if not isinstance(decoded, Mapping):
        return ""
    if verbose:
        return _render_verbose(decoded, color, indent)
    return _render_summary(decoded, color, indent)


# ---------------------------------------------------------------------------
# Summary renderer
# ---------------------------------------------------------------------------

def _render_summary(
    decoded: Mapping,
    color: ColorScheme,
    indent: str,
) -> str:
    chain = decoded.get("chain") or []
    layers_count = decoded.get("layers_count", 0)
    final_kind = decoded.get("final_kind", "unknown")
    status = decoded.get("unwrap_status", "")
    indicators = decoded.get("indicators") or []
    pickle_warn = decoded.get("pickle_warning", False)
    continues_as = decoded.get("continues_as")

    # Build the chain summary string.
    # When the loop exhausted depth, we want to clearly separate
    # "what we actually unwrapped" from "what the chain would have
    # done next" rather than concatenating them with a misleading
    # arrow.
    chain_kinds = [layer.get("kind", "?") for layer in chain]
    chain_str = " -> ".join(chain_kinds) if chain_kinds else "(no chain)"

    label = f"{color.bold_pre}decoded chain:{color.bold_post}"
    suffix_bits = [
        f"{layers_count} layer{'s' if layers_count != 1 else ''}",
    ]
    if status and status != "completed":
        suffix_bits.append(
            f"{color.yellow_pre}{status}{color.yellow_post}"
        )
    if continues_as:
        suffix_bits.append(
            f"would continue as {color.yellow_pre}"
            f"{continues_as}{color.yellow_post}"
        )
    suffix = "(" + "; ".join(suffix_bits) + ")"

    # Show the terminal kind separately when we actually reached
    # one (status completed). Skip it on exhausted/error since
    # final_kind in those cases is just "binary_unknown" and adds
    # noise.
    if status == "completed":
        chain_display = f"{chain_str} -> {final_kind}"
    else:
        chain_display = chain_str

    lines = [
        f"{indent}{label} {chain_display} {suffix}",
    ]

    if indicators:
        ind_str = ", ".join(
            f"{color.dim_pre}{ind}{color.dim_post}" for ind in indicators
        )
        lines.append(f"{indent}  indicators: {ind_str}")

    if pickle_warn:
        lines.append(
            f"{indent}  {color.red_pre}WARNING: payload is a Python "
            f"pickle stream (NOT deserialized){color.red_post}"
        )

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Verbose renderer
# ---------------------------------------------------------------------------

def _render_verbose(
    decoded: Mapping,
    color: ColorScheme,
    indent: str,
) -> str:
    chain = decoded.get("chain") or []
    layers_count = decoded.get("layers_count", 0)
    final_kind = decoded.get("final_kind", "unknown")
    final_size = decoded.get("final_bytes_size", 0)
    status = decoded.get("unwrap_status", "")
    indicators = decoded.get("indicators") or []
    preview_hex = decoded.get("preview_hex", "")
    preview_text = decoded.get("preview_text", "")
    preview_truncated = decoded.get("preview_truncated", False)
    pickle_warn = decoded.get("pickle_warning", False)
    continues_as = decoded.get("continues_as")

    lines = []

    # Header line.
    status_label = ""
    if status and status != "completed":
        status_label = f", {color.yellow_pre}{status}{color.yellow_post}"
    lines.append(
        f"{indent}{color.bold_pre}decoded chain "
        f"({layers_count} layer{'s' if layers_count != 1 else ''}"
        f"{status_label}):{color.bold_post}"
    )

    # Per-layer breakdown. Aligned columns.
    if chain:
        kind_width = max(len(layer.get("kind", "")) for layer in chain)
        for n, layer in enumerate(chain, start=1):
            kind = layer.get("kind", "?")
            in_sz = layer.get("input_size", 0)
            out_sz = layer.get("output_size", 0)
            lines.append(
                f"{indent}  layer {n}: "
                f"{color.dim_pre}{kind:<{kind_width}}{color.dim_post}  "
                f"{in_sz} -> {out_sz} bytes"
            )
    else:
        lines.append(f"{indent}  (no transformations applied)")

    if continues_as:
        lines.append(
            f"{indent}  {color.yellow_pre}[chain continues as: "
            f"{continues_as}; depth limit reached]{color.yellow_post}"
        )

    # Final form summary.
    truncation_note = ""
    if preview_truncated:
        truncation_note = ", preview truncated"
    lines.append("")
    lines.append(
        f"{indent}final form: {color.bold_pre}{final_kind}{color.bold_post} "
        f"({final_size} bytes{truncation_note})"
    )

    # Indicators.
    if indicators:
        lines.append(f"{indent}indicators:")
        for ind in indicators:
            lines.append(
                f"{indent}  - {color.dim_pre}{ind}{color.dim_post}"
            )

    # Hex dump.
    if preview_hex:
        lines.append("")
        lines.append(f"{indent}hex preview:")
        lines.extend(_format_hex_dump(preview_hex, preview_text, indent))

    # Pickle warning at the bottom in red.
    if pickle_warn:
        lines.append("")
        lines.append(
            f"{indent}{color.red_pre}!!! WARNING: payload is a Python "
            f"pickle stream. NOT deserialized by pydepgate. Inspect "
            f"in an isolated environment only.{color.red_post}"
        )

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Hex dump
# ---------------------------------------------------------------------------

def _format_hex_dump(
    hex_str: str,
    text_str: str,
    indent: str,
) -> list[str]:
    """Format a hex string and matching text preview as xxd-style rows."""
    if not hex_str:
        return []
    if len(hex_str) % 2 != 0:
        return [f"{indent}  (malformed hex preview)"]

    n_bytes = len(hex_str) // 2
    if len(text_str) < n_bytes:
        text_str = text_str + "." * (n_bytes - len(text_str))

    lines = []
    for offset in range(0, n_bytes, 16):
        row_bytes_hex = hex_str[offset * 2 : (offset + 16) * 2]
        row_text = text_str[offset : offset + 16]

        hex_parts = []
        for i in range(0, len(row_bytes_hex), 2):
            hex_parts.append(row_bytes_hex[i : i + 2])
        while len(hex_parts) < 16:
            hex_parts.append("  ")

        first_half = " ".join(hex_parts[:8])
        second_half = " ".join(hex_parts[8:])
        gutter = row_text + " " * (16 - len(row_text))

        lines.append(
            f"{indent}  {offset:08x}  {first_half}  {second_half}  |{gutter}|"
        )

    return lines