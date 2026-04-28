"""
Tests for pydepgate.cli.progress.

Three focus areas:
  - ProgressBar rendering: format, throttling, first-call always
    renders, final-call always renders, disabled bar is silent.
  - make_progress_callback factory: returns no-ops for --no-bar,
    returns no-ops for non-TTY streams, returns active callbacks
    for TTY-attached streams.
  - Robustness: zero total, weird streams, double-finish are all
    handled without crashing.
"""

from __future__ import annotations

import io
import time
import unittest

from pydepgate.cli.progress import (
    ProgressBar,
    _noop_finish,
    _noop_update,
    make_progress_callback,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class _FakeTTYStream:
    """A stream that wraps a StringIO and reports as a TTY.

    Used to test the "TTY detected, render normally" path of the
    factory without needing to actually attach to a terminal.
    """

    def __init__(self) -> None:
        self._buf = io.StringIO()

    def write(self, s: str) -> int:
        return self._buf.write(s)

    def flush(self) -> None:
        self._buf.flush()

    def isatty(self) -> bool:
        return True

    def getvalue(self) -> str:
        return self._buf.getvalue()


class _BrokenIsattyStream:
    """A stream whose isatty() raises. ProgressBar should treat it
    as non-TTY and render nothing, instead of crashing."""

    def __init__(self) -> None:
        self._buf = io.StringIO()

    def write(self, s: str) -> int:
        return self._buf.write(s)

    def flush(self) -> None:
        self._buf.flush()

    def isatty(self) -> bool:
        raise OSError("stream closed or otherwise unhappy")

    def getvalue(self) -> str:
        return self._buf.getvalue()


# ===========================================================================
# ProgressBar rendering
# ===========================================================================


class TestProgressBarRendering(unittest.TestCase):
    """Verify the bar renders the expected format."""

    def test_renders_on_first_update(self):
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=True)
        bar.update(50, 100)
        output = buf.getvalue()
        # Starts with carriage return (line overwrite)
        self.assertTrue(output.startswith("\r"))
        # Contains label, percentage, counts, and a bar
        self.assertIn("Scanning", output)
        self.assertIn("50%", output)
        self.assertIn("50/100", output)
        self.assertIn("[", output)
        self.assertIn("]", output)

    def test_uses_custom_label(self):
        buf = io.StringIO()
        bar = ProgressBar(label="Analyzing", stream=buf, force_enabled=True)
        bar.update(1, 10)
        self.assertIn("Analyzing", buf.getvalue())
        self.assertNotIn("Scanning", buf.getvalue())

    def test_final_state_is_all_equals(self):
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=True)
        bar.update(100, 100)
        output = buf.getvalue()
        self.assertIn("100%", output)
        self.assertIn("100/100", output)
        # No '>' in the bar at completion (all '=')
        # Find the bar segment between '[' and ']'
        bar_start = output.index("[") + 1
        bar_end = output.index("]")
        bar_chars = output[bar_start:bar_end]
        self.assertNotIn(">", bar_chars)
        # And all equals
        self.assertEqual(set(bar_chars), {"█"})

    def test_intermediate_state_has_progress_marker(self):
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=True)
        bar.update(50, 100)
        output = buf.getvalue()
        bar_start = output.index("[") + 1
        bar_end = output.index("]")
        bar_chars = output[bar_start:bar_end]
        # Half-progress: should have both '█' (filled) and '▒' (head)
        # and '░' (unfilled).
        self.assertIn("█", bar_chars)
        self.assertIn("▒", bar_chars)
        self.assertIn("░", bar_chars)

    def test_pads_to_clear_previous_longer_line(self):
        # Render once with a long-numbered total, then with a short
        # one; the second render must pad to erase leftover characters.
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=True)
        bar.update(99, 99999)  # long counts
        first = buf.getvalue()
        first_len_after_cr = len(first.rsplit("\r", 1)[-1])

        # Force the throttle to elapse so the second update renders.
        bar._last_render_at = 0.0  # type: ignore[attr-defined]
        bar.update(2, 5)  # short counts
        full = buf.getvalue()
        # After the second render, the trailing segment includes
        # the new line plus padding spaces. The padded line must be
        # at least as long as the previous one.
        last_render = full.rsplit("\r", 1)[-1]
        self.assertGreaterEqual(len(last_render), first_len_after_cr)


class TestProgressBarThrottling(unittest.TestCase):
    """Verify rapid updates don't all produce renders."""

    def test_throttle_suppresses_rapid_intermediate_updates(self):
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=True)
        bar.update(1, 100)
        first_len = len(buf.getvalue())
        # Subsequent updates immediately after should be suppressed
        # by throttle.
        bar.update(2, 100)
        bar.update(3, 100)
        bar.update(4, 100)
        self.assertEqual(
            len(buf.getvalue()), first_len,
            "throttle did not suppress rapid intermediate updates",
        )

    def test_throttle_does_not_suppress_first_update(self):
        # First update always renders, even though _last_render_at
        # is initially 0 (which would make the throttle calculation
        # look like "elapsed = now" >= 0.1, but we don't rely on
        # that math: we explicitly bypass throttle for the first
        # call).
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=True)
        bar.update(1, 1000)
        self.assertGreater(len(buf.getvalue()), 0)

    def test_throttle_does_not_suppress_final_update(self):
        # Final update (completed >= total) bypasses the throttle,
        # so the user always sees 100%.
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=True)
        bar.update(1, 100)  # first render
        len_after_first = len(buf.getvalue())
        # Immediately fire the final update. Throttle would normally
        # suppress this.
        bar.update(100, 100)
        self.assertGreater(
            len(buf.getvalue()), len_after_first,
            "final update was suppressed by throttle",
        )
        self.assertIn("100/100", buf.getvalue())

    def test_throttle_lets_through_after_interval(self):
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=True)
        bar.update(1, 100)
        len_after_first = len(buf.getvalue())
        # Sleep past the throttle interval.
        time.sleep(0.12)
        bar.update(2, 100)
        self.assertGreater(len(buf.getvalue()), len_after_first)


class TestProgressBarDisabled(unittest.TestCase):
    """A disabled bar produces no output and consumes no resources."""

    def test_force_disabled_writes_nothing(self):
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=False)
        bar.update(50, 100)
        bar.update(100, 100)
        bar.finish()
        self.assertEqual(buf.getvalue(), "")

    def test_non_tty_stream_auto_disables(self):
        buf = io.StringIO()  # isatty() returns False
        bar = ProgressBar(stream=buf)  # auto-detect
        self.assertFalse(bar.enabled)
        bar.update(50, 100)
        self.assertEqual(buf.getvalue(), "")

    def test_tty_stream_auto_enables(self):
        stream = _FakeTTYStream()
        bar = ProgressBar(stream=stream)
        self.assertTrue(bar.enabled)
        bar.update(50, 100)
        self.assertGreater(len(stream.getvalue()), 0)


class TestProgressBarEdgeCases(unittest.TestCase):
    """Defensive: weird inputs don't crash."""

    def test_zero_total_does_not_render(self):
        # A zero-file scan shouldn't show a bar at all.
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=True)
        bar.update(0, 0)
        self.assertEqual(buf.getvalue(), "")

    def test_zero_total_does_not_divide_by_zero(self):
        bar = ProgressBar(force_enabled=True, stream=io.StringIO())
        # The point is just "this doesn't raise".
        try:
            bar.update(0, 0)
        except ZeroDivisionError:
            self.fail("update(0, 0) raised ZeroDivisionError")

    def test_completed_greater_than_total_does_not_overflow_bar(self):
        # If the engine somehow over-reports, the bar should clamp
        # rather than render absurd output.
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=True)
        bar.update(150, 100)
        # Bar should show 100% / 100/100 (clamped), not "150/100".
        self.assertIn("100/100", buf.getvalue())

    def test_double_finish_is_safe(self):
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=True)
        bar.update(100, 100)
        bar.finish()
        first = buf.getvalue()
        bar.finish()  # idempotent
        self.assertEqual(buf.getvalue(), first)

    def test_finish_without_render_is_safe(self):
        # A bar that was constructed but never updated (e.g.
        # zero-file scan) should finish cleanly without writing
        # a stray newline.
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=True)
        bar.finish()
        self.assertEqual(buf.getvalue(), "")

    def test_update_after_finish_is_silent(self):
        # Defensive: holding a callback past scan completion shouldn't
        # produce stray output if the callback fires once more.
        buf = io.StringIO()
        bar = ProgressBar(stream=buf, force_enabled=True)
        bar.update(100, 100)
        bar.finish()
        before = buf.getvalue()
        bar.update(50, 100)  # late call after finish
        self.assertEqual(buf.getvalue(), before)

    def test_broken_isatty_does_not_crash(self):
        # If a stream's isatty() raises, the bar treats it as
        # non-TTY rather than letting the exception propagate.
        stream = _BrokenIsattyStream()
        bar = ProgressBar(stream=stream)
        self.assertFalse(bar.enabled)
        bar.update(50, 100)
        self.assertEqual(stream.getvalue(), "")


# ===========================================================================
# make_progress_callback factory
# ===========================================================================


class TestMakeProgressCallbackFactory(unittest.TestCase):
    """The factory's job is to encapsulate the suppression decision."""

    def test_no_bar_true_returns_noops(self):
        update, finish = make_progress_callback(no_bar=True)
        # The two well-known no-op functions are returned.
        self.assertIs(update, _noop_update)
        self.assertIs(finish, _noop_finish)

    def test_non_tty_stream_returns_noops(self):
        # StringIO.isatty() returns False, so the factory should
        # return no-ops even with no_bar=False.
        buf = io.StringIO()
        update, finish = make_progress_callback(no_bar=False, stream=buf)
        self.assertIs(update, _noop_update)
        self.assertIs(finish, _noop_finish)

    def test_tty_stream_returns_active_callbacks(self):
        stream = _FakeTTYStream()
        update, finish = make_progress_callback(no_bar=False, stream=stream)
        self.assertIsNot(update, _noop_update)
        self.assertIsNot(finish, _noop_finish)
        # Drive them and verify rendering happens.
        update(50, 100)
        self.assertGreater(len(stream.getvalue()), 0)
        finish()
        self.assertTrue(stream.getvalue().endswith("\n"))

    def test_no_bar_overrides_tty_detection(self):
        # Even on a TTY, no_bar=True should suppress.
        stream = _FakeTTYStream()
        update, finish = make_progress_callback(no_bar=True, stream=stream)
        update(50, 100)
        finish()
        self.assertEqual(stream.getvalue(), "")

    def test_noops_accept_correct_signature(self):
        # The no-op functions must accept the same args as the real
        # callbacks, so the engine doesn't need to branch.
        _noop_update(50, 100)  # should not raise
        _noop_finish()         # should not raise

    def test_custom_label_propagates(self):
        stream = _FakeTTYStream()
        update, finish = make_progress_callback(
            no_bar=False, stream=stream, label="Indexing",
        )
        update(50, 100)
        self.assertIn("Indexing", stream.getvalue())


if __name__ == "__main__":
    unittest.main()