"""
Density map renderer for pydepgate's human-readable output.

Produces a compact, SSH-randomart-inspired block diagram showing
where in a file findings are concentrated. Rendered only in human
format, only for files that have at least one finding, and only
when color output is enabled (the visualization is not meaningful
in monochrome, the color is load-bearing).

The map is purely aesthetic. It conveys no information not already
present in the finding list; it merely presents spatial distribution
at a glance. Think of it as a sparkline for the scan results.

Output example (64-column inner width, 6-row height):

    +-------------------- setup.py -----------------------------+
    |                                                          |
    |                                   #                      |
    |                                  ###                     |
    |                      .           #####    .              |
    |          ..          ##       #######   ##               |
    |    .  .. ..  .  ..  ###  ... ######### ###  ..  ..       |
    |....................MM.HH.......CCCCCCCCC.HHH.............|
    +---------------------- 4 findings -------------------------+

The legend row uses severity labels: C=CRITICAL H=HIGH M=MEDIUM
L=LOW '.' = no finding. Bar color matches the worst severity in
each column.
"""

from __future__ import annotations

import math
import shutil
from dataclasses import dataclass
from typing import Sequence

from pydepgate.engines.base import Finding, Severity


# ---------------------------------------------------------------------------
# Block characters
# ---------------------------------------------------------------------------
# Nine levels: index 0 is a space (empty), indices 1-8 are the Unicode
# lower-block characters. The index is the "fill level" of a cell.
_BLOCKS = " \u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"
_N_LEVELS = len(_BLOCKS)  # 9 (0-8)


# ---------------------------------------------------------------------------
# ANSI color codes
# ---------------------------------------------------------------------------
# Using raw codes consistent with reporter.py, no third-party dep.
_RESET   = "\033[0m"
_BOLD    = "\033[1m"
_DIM     = "\033[2m"

_SEVERITY_FG: dict[Severity, str] = {
    Severity.CRITICAL: "\033[91m",   # bright red
    Severity.HIGH:     "\033[31m",   # red
    Severity.MEDIUM:   "\033[33m",   # yellow
    Severity.LOW:      "\033[34m",   # blue
    Severity.INFO:     "\033[2m",    # dim
}

# One-character label for the legend row.
_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "C",
    Severity.HIGH:     "H",
    Severity.MEDIUM:   "M",
    Severity.LOW:      "L",
    Severity.INFO:     "i",
}

# Numeric rank for "worst in bucket" comparisons.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO:     0,
    Severity.LOW:      1,
    Severity.MEDIUM:   2,
    Severity.HIGH:     3,
    Severity.CRITICAL: 4,
}


# ---------------------------------------------------------------------------
# Geometry constants
# ---------------------------------------------------------------------------
_MIN_WIDTH   = 40    # never render narrower than this
_MAX_WIDTH   = 80    # cap so the map doesn't sprawl on huge terminals
_DEFAULT_HEIGHT = 6  # bar rows (not counting legend or borders)


# ---------------------------------------------------------------------------
# Internal data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Bucket:
    """One column of the density map."""
    count: int       # number of findings whose line falls in this bucket
    worst: Severity  # worst severity among those findings


def _build_buckets(
    findings: Sequence[Finding],
    total_lines: int,
    n_buckets: int,
) -> list[_Bucket]:
    """
    Partition findings into n_buckets columns by line number.

    total_lines is used to normalize line positions. If the caller
    does not know the actual line count, passing the maximum finding
    line number (possibly with a small multiplier) is a reasonable
    approximation.
    """
    if total_lines < 1:
        total_lines = 1

    counts: list[int]                = [0] * n_buckets
    worsts: list[Severity | None]    = [None] * n_buckets

    for finding in findings:
        line = finding.signal.location.line
        # Map 1-based line number to 0-based bucket index.
        raw_idx = int((line - 1) / total_lines * n_buckets)
        idx     = min(raw_idx, n_buckets - 1)
        counts[idx] += 1
        sev = finding.severity
        if worsts[idx] is None or _SEVERITY_RANK[sev] > _SEVERITY_RANK[worsts[idx]]:
            worsts[idx] = sev

    return [
        _Bucket(
            count=counts[i],
            worst=worsts[i] if worsts[i] is not None else Severity.INFO,
        )
        for i in range(n_buckets)
    ]


# ---------------------------------------------------------------------------
# Bar-chart rendering
# ---------------------------------------------------------------------------

def _finding_count_to_fill(count: int, max_count: int, n_rows: int) -> int:
    """
    Map a finding count to a fill level in [0, n_rows * (_N_LEVELS-1)].

    Uses a log scale so that a bucket with a single finding still
    produces a visible bar even when another bucket has dozens. The
    minimum non-zero return value is 1 (at least one block is shown).
    """
    if count == 0 or max_count == 0:
        return 0
    ratio = math.log1p(count) / math.log1p(max_count)
    return max(1, round(ratio * n_rows * (_N_LEVELS - 1)))


def _render_bar_rows(
    buckets: list[_Bucket],
    n_rows: int,
    color: bool,
) -> list[str]:
    """
    Return n_rows strings, each len(buckets) chars wide (before escapes),
    representing the bar chart from top to bottom.

    Each character is one of the _BLOCKS characters, colored (if enabled)
    by the worst severity in that column.
    """
    max_count = max((b.count for b in buckets), default=0)
    fills     = [_finding_count_to_fill(b.count, max_count, n_rows) for b in buckets]

    rows: list[str] = []

    for row_idx in range(n_rows):
        # row_idx 0 is the top row; row_idx (n_rows-1) is the bottom row.
        # The bottom row represents fill levels [0, _N_LEVELS-1].
        # The next row up represents [_N_LEVELS-1, 2*(_N_LEVELS-1)]. Etc.
        row_floor = (n_rows - 1 - row_idx) * (_N_LEVELS - 1)
        row_ceil  = row_floor + (_N_LEVELS - 1)

        parts: list[str] = []
        for fill, bucket in zip(fills, buckets):
            if fill <= row_floor:
                # Bar doesn't reach this row.
                char = " "
                sev  = None
            elif fill >= row_ceil:
                # Bar completely fills this row.
                char = _BLOCKS[-1]
                sev  = bucket.worst
            else:
                # Partial fill.
                char = _BLOCKS[fill - row_floor]
                sev  = bucket.worst

            if color and sev is not None:
                fg   = _SEVERITY_FG.get(sev, "")
                parts.append(f"{fg}{char}{_RESET}")
            else:
                parts.append(char)

        rows.append("".join(parts))

    return rows


def _render_legend_row(buckets: list[_Bucket], color: bool) -> str:
    """
    One row of single-character severity labels below the bar chart.

    Columns with no findings show a dim middle dot. Columns with
    findings show the severity label letter, colored to match.
    """
    parts: list[str] = []
    for bucket in buckets:
        if bucket.count == 0:
            parts.append(f"{_DIM}\u00b7{_RESET}" if color else "\u00b7")
        else:
            label = _SEVERITY_LABEL[bucket.worst]
            if color:
                fg = _SEVERITY_FG.get(bucket.worst, "")
                parts.append(f"{fg}{label}{_RESET}")
            else:
                parts.append(label)
    return "".join(parts)


# ---------------------------------------------------------------------------
# Border helpers
# ---------------------------------------------------------------------------

def _centered_border(left: str, right: str, label: str, inner_width: int) -> str:
    """
    Build a border line like:  +---- label ----+
    where inner_width is the width of the content area (between the
    vertical bars). The label is placed as close to center as possible.
    """
    # Available dash space is inner_width minus the label length.
    label_with_spaces = f" {label} "
    dash_total  = inner_width - len(label_with_spaces)
    dash_total  = max(dash_total, 0)
    left_dashes = dash_total // 2
    right_dashes = dash_total - left_dashes
    return (
        f"{left}"
        f"{'\u2500' * left_dashes}"
        f"{label_with_spaces}"
        f"{'\u2500' * right_dashes}"
        f"{right}"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_density_map(
    filename: str,
    findings: Sequence[Finding],
    total_lines: int | None = None,
    color: bool = True,
    n_rows: int = _DEFAULT_HEIGHT,
) -> str:
    """
    Render a density map as a multi-line string and return it.

    Parameters
    ----------
    filename:
        The display name to show in the top border (e.g. 'setup.py'
        or 'litellm/__init__.py').
    findings:
        All findings for this specific file. Must be non-empty.
    total_lines:
        The actual line count of the file, used to normalize positions.
        If None, the maximum finding line number is used as a proxy.
        This is acceptable for an aesthetic visualization.
    color:
        Whether to emit ANSI color codes. If False, returns an empty
        string (the monochrome map is not meaningful).
    n_rows:
        Height of the bar chart in character rows, not counting the
        legend row or borders.

    Returns
    -------
    str
        The complete map, including borders and a trailing newline.
        Empty string if conditions are not met.
    """
    if not findings or not color:
        return ""

    # Determine inner width from terminal size.
    term_width = shutil.get_terminal_size(fallback=(80, 24)).columns
    # Subtract 2 for the border pipes, then clamp.
    inner_width = max(_MIN_WIDTH, min(_MAX_WIDTH, term_width - 2))

    # Total lines: use provided value or fall back to max finding line.
    if total_lines is None or total_lines < 1:
        total_lines = max(f.signal.location.line for f in findings)
        # Small multiplier so findings aren't all crammed at the right edge
        # when the last finding is at the last line of the file.
        total_lines = int(total_lines * 1.1) or 1

    buckets    = _build_buckets(findings, total_lines, inner_width)
    bar_rows   = _render_bar_rows(buckets, n_rows, color)
    legend_row = _render_legend_row(buckets, color)

    # Truncate filename for the border if it's very long.
    max_label_len = inner_width - 6   # leave room for dashes on each side
    display_name  = filename
    if len(display_name) > max_label_len:
        display_name = f"\u2026{filename[-(max_label_len - 1):]}"

    n = len(findings)
    finding_label = f"{n} finding{'s' if n != 1 else ''}"

    top_border    = _centered_border("\u250c", "\u2510", display_name, inner_width)
    bottom_border = _centered_border("\u2514", "\u2518", finding_label, inner_width)

    lines = [top_border]
    for row in bar_rows:
        lines.append(f"\u2502{row}\u2502")
    lines.append(f"\u2502{legend_row}\u2502")
    lines.append(bottom_border)

    return "\n".join(lines) + "\n"