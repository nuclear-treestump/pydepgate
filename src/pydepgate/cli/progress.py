"""pydepgate.cli.progress

Progress bar for artifact scans.

Renders a single-line, terminal-style progress indicator to stderr
during multi-file scans. The bar updates as files are scanned and is
suppressed automatically when stderr is not a TTY (CI runs, piped
output, redirected logs) or when the user passes --no-bar.

Design constraints:
  - No third-party dependencies. The pydepgate philosophy is zero
    runtime deps and that includes "no progress library."
  - Cheap. Rendering is throttled to ~10 Hz so a 5000-file scan
    doesn't spend measurable time writing to the terminal.
  - Robust. The bar always renders its first update (so the user
    sees activity immediately) and its final update (so 100% is
    always visible), even when those updates would otherwise be
    suppressed by the throttle.
  - Inert when disabled. A disabled bar's update() is a method call
    that does nothing, so callers don't need to branch on enabled
    state at every call site.

Public API:
  - ProgressBar(label, stream, force_enabled): the renderer.
  - make_progress_callback(no_bar, stream): factory that returns
    (update, finish) tuple. Returns no-op callbacks when the bar
    should be suppressed; returns real callbacks otherwise.

The factory is the recommended entry point for the CLI. The class
is exposed for tests and for callers that want direct control.
"""

from __future__ import annotations

import shutil
import sys
import time
from typing import Callable, IO


# Type alias for the per-file progress callback. Receives
# (completed, total). Engine calls this once per file in Phase 2.
ProgressCallback = Callable[[int, int], None]


# Throttle interval. With files averaging ~10 ms each (the LiteLLM
# 1.82.8 measurement: 1709 files in 17.8 s), this means the bar
# refreshes roughly every 10 files during a typical scan. Slow
# enough to not noticeably load the terminal; fast enough to feel
# live.
_THROTTLE_SECONDS = 0.1


class ProgressBar:
    """Single-line, ASCII-only progress bar.

    Construct with the stream you want to render to (default
    sys.stderr). The bar self-disables if the stream is not a TTY,
    unless `force_enabled` is set explicitly (used by tests).

    Calling update(completed, total) renders if either:
      - This is the first call (so the bar appears immediately).
      - completed >= total (so the final state is always shown).
      - Or the throttle has elapsed since the last render.

    Calling finish() writes a newline so subsequent stderr output
    doesn't sit on top of the bar.

    The bar is intentionally stateful but does not own any
    long-lived resources. It does no I/O after finish() unless
    update() is called again.
    """

    def __init__(
        self,
        label: str = "Scanning",
        stream: IO[str] | None = None,
        force_enabled: bool | None = None,
    ) -> None:
        self._label = label
        self._stream: IO[str] = stream if stream is not None else sys.stderr
        if force_enabled is None:
            # Only render if we're attached to an interactive terminal.
            # IOBase.isatty() returns False for StringIO / BytesIO /
            # piped output, which is exactly what we want.
            self._enabled = self._stream_is_tty()
        else:
            self._enabled = force_enabled
        self._started_at: float | None = None
        self._last_render_at: float = 0.0
        self._prev_line_length: int = 0
        self._has_rendered: bool = False
        self._finished: bool = False

    @property
    def enabled(self) -> bool:
        """Whether this bar will render anything. Useful for tests."""
        return self._enabled

    # ------------------------------------------------------------------
    # Public API: matches ProgressCallback signature
    # ------------------------------------------------------------------

    def update(self, completed: int, total: int) -> None:
        """Update the bar's state and render if appropriate.

        Signature matches `ProgressCallback`. Safe to pass directly
        to the engine as the per-file callback.
        """
        if not self._enabled:
            return
        if self._finished:
            # Defensive: don't render after finish(). Avoids the
            # case where a callback is held past scan completion
            # and overwrites a subsequent line of output.
            return
        if total <= 0:
            # Zero-file scans aren't worth a bar.
            return

        if self._started_at is None:
            self._started_at = time.monotonic()

        now = time.monotonic()
        is_first = not self._has_rendered
        is_final = completed >= total
        throttle_ok = (now - self._last_render_at) >= _THROTTLE_SECONDS

        if not (is_first or is_final or throttle_ok):
            return

        self._render(completed, total, now)
        self._last_render_at = now
        self._has_rendered = True

    def finish(self) -> None:
        """Terminate the bar with a newline.

        Idempotent: calling more than once is harmless. Safe to call
        even if no update() ever happened (e.g. zero-file scans).
        """
        if not self._enabled or self._finished:
            return
        if self._has_rendered:
            self._stream.write("\n")
            self._stream.flush()
        self._finished = True

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _stream_is_tty(self) -> bool:
        """Best-effort TTY check that doesn't crash on weird streams."""
        isatty = getattr(self._stream, "isatty", None)
        if isatty is None:
            return False
        try:
            return bool(isatty())
        except (ValueError, OSError):
            # Closed stream, or a stream wrapper that raises on isatty.
            return False

    def _render(self, completed: int, total: int, now: float) -> None:
        line = self._build_line(completed, total, now)
        # Pad with spaces to clear any leftover characters from a
        # previous longer render. \r returns to column 0; the spaces
        # erase whatever was there beyond `len(line)`.
        pad = max(0, self._prev_line_length - len(line))
        self._stream.write("\r" + line + (" " * pad))
        self._stream.flush()
        self._prev_line_length = len(line)

    def _build_line(self, completed: int, total: int, now: float) -> str:
        """Compose the bar line, capped to the terminal width."""
        elapsed = (
            (now - self._started_at) if self._started_at is not None else 0.0
        )
        percent = int(100 * completed / total) if total > 0 else 0
        # Cap completed at total for display (engine shouldn't ever
        # send completed > total, but defensive).
        shown_completed = min(completed, total)

        terminal_width = self._terminal_width()
        # Reserve space for label, percent, counts, elapsed, plus
        # punctuation. Anything left over goes to the bar itself.
        # Format target:
        #   "Scanning  47% [==========>          ] 1234/2598  8.2s"
        prefix = f"{self._label} {percent:3d}% ["
        suffix = f"] {shown_completed}/{total}  {elapsed:.1f}s"
        overhead = len(prefix) + len(suffix)
        bar_width = max(8, terminal_width - 1 - overhead)
        # Cap bar width so very wide terminals don't get an absurdly
        # long bar.
        bar_width = min(bar_width, 50)

        bar_chars = self._bar_chars(shown_completed, total, bar_width)
        line = prefix + bar_chars + suffix

        # If we somehow exceeded the terminal width (small terminal),
        # truncate to keep from wrapping.
        if len(line) > terminal_width - 1:
            line = line[: max(0, terminal_width - 1)]
        return line

    @staticmethod
    def _bar_chars(completed: int, total: int, width: int) -> str:
        """Render the inner bar characters: '====>    ' shape.

        At completion, every cell is '='. Below completion, the
        leading edge gets a '>' and the rest is spaces.
        """
        if total <= 0 or width <= 0:
            return ""
        ratio = completed / total
        filled = int(ratio * width)
        if filled >= width:
            return "█" * width
        return "█" * filled + "▒" + "░" * (width - filled - 1)

    def _terminal_width(self) -> int:
        """Best-effort terminal width with sensible fallback."""
        try:
            size = shutil.get_terminal_size((80, 24))
            return size.columns
        except (OSError, ValueError):
            return 80


# ---------------------------------------------------------------------------
# Factory: the recommended way for the CLI to wire up progress
# ---------------------------------------------------------------------------


def _noop_update(completed: int, total: int) -> None:
    """No-op replacement for an active progress callback."""
    return None


def _noop_finish() -> None:
    """No-op replacement for an active progress finish."""
    return None


def make_progress_callback(
    *,
    no_bar: bool = False,
    stream: IO[str] | None = None,
    label: str = "Scanning",
) -> tuple[ProgressCallback, Callable[[], None]]:
    """Build (update, finish) callbacks suitable for the CLI's scan path.

    Returns a tuple of two callables:
      - update(completed, total): pass to the engine as
        progress_callback. Renders the bar (or does nothing if
        the bar is suppressed).
      - finish(): call once after the scan returns, to terminate
        the bar with a newline.

    The bar is suppressed (both callbacks are no-ops) when:
      - `no_bar` is True (user passed --no-bar), or
      - `stream` is not a TTY (CI run, piped output, redirected
        stderr).

    These two cases collapse to "do nothing" deliberately: callers
    can wire the callbacks unconditionally and the right behavior
    happens.

    Args:
        no_bar: When True, force suppression regardless of TTY state.
        stream: Output stream. Defaults to sys.stderr.
        label: Label shown at the start of the bar line.

    Returns:
        (update_callback, finish_callback).
    """
    target_stream: IO[str] = stream if stream is not None else sys.stderr

    if no_bar:
        return (_noop_update, _noop_finish)

    bar = ProgressBar(label=label, stream=target_stream)
    if not bar.enabled:
        # Stream isn't a TTY. ProgressBar is already inert, but
        # returning the no-ops makes the suppression explicit and
        # avoids holding a reference to an unused bar.
        return (_noop_update, _noop_finish)

    return (bar.update, bar.finish)