"""
Tests for analyzer-emitted enrichment hints.

After PR 2 slice 1, analyzers that produce enrichment-eligible
signals should populate `Signal.enrichment_hints` with the name of
the enricher meant to consume them. The current set of hint-emitting
signals is DENS010, DENS011, and ENC001, all of which request the
`payload_peek` enricher.

This module verifies:

  - the relevant analyzers set the hint when their signal fires
  - the relevant analyzers stash the raw literal value under
    `_full_value` (and set `_full_value_truncated` for oversize
    literals)
  - analyzers that should NOT request enrichment do not set hints
    (negative coverage so we notice if a signal accidentally grows
    a hint by accident)
  - the enrichment_hints field round-trips through pickle, alongside
    the existing Signal contract

The tests are deliberately analyzer-focused: they exercise each
analyzer in isolation against synthetic source so any change to the
emission code is caught at the per-analyzer layer rather than only
at the engine-integration layer.
"""

import pickle
import unittest

from pydepgate.analyzers._enrichment import (
    MAX_STASHED_VALUE_BYTES,
    stash_value,
)
from pydepgate.analyzers.base import Confidence, Scope, Signal
from pydepgate.analyzers.density_analyzer import CodeDensityAnalyzer
from pydepgate.analyzers.dynamic_execution import DynamicExecutionAnalyzer
from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.analyzers.string_ops import StringOpsAnalyzer
from pydepgate.analyzers.suspicious_stdlib import SuspiciousStdlibAnalyzer
from pydepgate.parsers.pysource import SourceLocation, parse_python_source


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _analyze(analyzer, source: bytes) -> list[Signal]:
    parsed = parse_python_source(source, "<test>")
    return list(analyzer.analyze_python(parsed))


# A high-entropy base64 literal (200 chars of pseudo-random b64 alphabet),
# long enough to fire DENS010 at the higher-confidence tier.
_LONG_B64_LITERAL = (
    "QWxsIHRoZSB3b3JsZHMgYSBzdGFnZSBhbmQgYWxsIHRoZSBtZW4gYW5kIHdvbWVu"
    "IGFyZSBtZXJlbHkgcGxheWVycyB0aGV5IGhhdmUgdGhlaXIgZXhpdHMgYW5kIHRo"
    "ZWlyIGVudHJhbmNlcyBldmVyeSBtYW4gaW4gaGlzIHRpbWUgcGxheXMgbWFueSBw"
    "YXJ0cw=="
)

_DENSITY_SOURCE = (
    f'_x = "{_LONG_B64_LITERAL}"\n'
).encode("utf-8")

_ENC_SOURCE = (
    f"import base64\n"
    f"exec(base64.b64decode('{_LONG_B64_LITERAL}'))\n"
).encode("utf-8")


# ===========================================================================
# stash_value helper
# ===========================================================================

class StashValueHelperTests(unittest.TestCase):

    def test_short_str_passes_through_unchanged(self):
        v = "hello"
        out, truncated = stash_value(v)
        self.assertEqual(out, v)
        self.assertFalse(truncated)

    def test_short_bytes_passes_through_unchanged(self):
        v = b"\x78\x9c\x05\x00"
        out, truncated = stash_value(v)
        self.assertEqual(out, v)
        self.assertFalse(truncated)

    def test_oversize_str_is_truncated(self):
        v = "A" * (MAX_STASHED_VALUE_BYTES + 1024)
        out, truncated = stash_value(v)
        self.assertTrue(truncated)
        # Returned value preserved as str.
        self.assertIsInstance(out, str)
        # Length is at most the cap (in chars; for ASCII this equals bytes).
        self.assertLessEqual(len(out), MAX_STASHED_VALUE_BYTES)

    def test_oversize_bytes_is_truncated(self):
        v = b"B" * (MAX_STASHED_VALUE_BYTES + 1024)
        out, truncated = stash_value(v)
        self.assertTrue(truncated)
        self.assertIsInstance(out, bytes)
        self.assertEqual(len(out), MAX_STASHED_VALUE_BYTES)

    def test_at_cap_exactly_does_not_truncate(self):
        v = b"C" * MAX_STASHED_VALUE_BYTES
        out, truncated = stash_value(v)
        self.assertFalse(truncated)
        self.assertEqual(out, v)


# ===========================================================================
# DENS010 emits the payload_peek hint
# ===========================================================================

class Dens010EnrichmentHintTests(unittest.TestCase):

    def setUp(self):
        self.signals = _analyze(CodeDensityAnalyzer(), _DENSITY_SOURCE)
        self.dens010 = [s for s in self.signals if s.signal_id == "DENS010"]

    def test_dens010_fires_on_fixture(self):
        self.assertGreater(
            len(self.dens010), 0,
            msg="fixture failed to produce DENS010; test is meaningless",
        )

    def test_dens010_carries_payload_peek_hint(self):
        for sig in self.dens010:
            self.assertIn(
                "payload_peek", sig.enrichment_hints,
                msg=(
                    f"DENS010 signal at {sig.location} did not carry "
                    f"the payload_peek hint; analyzer is not flagging "
                    f"the signal for enrichment"
                ),
            )

    def test_dens010_stashes_full_value(self):
        for sig in self.dens010:
            self.assertIn(
                "_full_value", sig.context,
                msg=(
                    "DENS010 signal does not have _full_value in "
                    "context; the enricher will have nothing to peek at"
                ),
            )
            stashed = sig.context["_full_value"]
            self.assertIsInstance(stashed, (str, bytes))

    def test_dens010_does_not_set_truncated_for_short_input(self):
        for sig in self.dens010:
            # The fixture is 200 chars; far below the cap.
            self.assertNotIn("_full_value_truncated", sig.context)


# ===========================================================================
# DENS011 emits the payload_peek hint
# ===========================================================================

class Dens011EnrichmentHintTests(unittest.TestCase):

    def setUp(self):
        self.signals = _analyze(CodeDensityAnalyzer(), _DENSITY_SOURCE)
        self.dens011 = [s for s in self.signals if s.signal_id == "DENS011"]

    def test_dens011_fires_on_fixture(self):
        self.assertGreater(
            len(self.dens011), 0,
            msg="fixture failed to produce DENS011; test is meaningless",
        )

    def test_dens011_carries_payload_peek_hint(self):
        for sig in self.dens011:
            self.assertIn(
                "payload_peek", sig.enrichment_hints,
            )

    def test_dens011_stashes_full_value(self):
        for sig in self.dens011:
            self.assertIn("_full_value", sig.context)


# ===========================================================================
# ENC001 emits the payload_peek hint
# ===========================================================================

class Enc001EnrichmentHintTests(unittest.TestCase):

    def setUp(self):
        self.signals = _analyze(EncodingAbuseAnalyzer(), _ENC_SOURCE)
        self.enc001 = [s for s in self.signals if s.signal_id == "ENC001"]

    def test_enc001_fires_on_fixture(self):
        self.assertGreater(
            len(self.enc001), 0,
            msg="fixture failed to produce ENC001; test is meaningless",
        )

    def test_enc001_carries_payload_peek_hint(self):
        for sig in self.enc001:
            self.assertIn(
                "payload_peek", sig.enrichment_hints,
            )

    def test_enc001_stashes_full_value_when_literal_present(self):
        # The fixture passes a literal to b64decode; the analyzer
        # should be able to grab it and stash.
        for sig in self.enc001:
            self.assertIn(
                "_full_value", sig.context,
                msg=(
                    "ENC001 with a literal payload should stash the "
                    "literal in context['_full_value'] for the enricher"
                ),
            )


# ===========================================================================
# Negative coverage: other analyzers do NOT emit hints
# ===========================================================================

class NoUnexpectedHintsTests(unittest.TestCase):
    """If a non-DENS/ENC signal grows a hint by accident, we want to
    notice. Each analyzer is exercised on a fixture that fires a
    signal, and we assert no payload_peek hint is set."""

    def test_dynamic_execution_signals_have_no_hint(self):
        source = b"exec(some_payload)\n"
        signals = _analyze(DynamicExecutionAnalyzer(), source)
        self.assertGreater(
            len(signals), 0,
            msg="fixture failed to fire DynamicExecutionAnalyzer",
        )
        for sig in signals:
            self.assertEqual(
                sig.enrichment_hints, frozenset(),
                msg=(
                    f"{sig.signal_id} unexpectedly carries hints "
                    f"{sig.enrichment_hints}; only DENS010, DENS011, "
                    f"ENC001 should request enrichment in this slice"
                ),
            )

    def test_string_ops_signals_have_no_hint(self):
        source = (
            b"fn = getattr(__builtins__, 'ev' + 'al')\n"
            b"fn('1+1')\n"
        )
        signals = _analyze(StringOpsAnalyzer(), source)
        for sig in signals:
            self.assertEqual(sig.enrichment_hints, frozenset())

    def test_suspicious_stdlib_signals_have_no_hint(self):
        source = (
            b"import subprocess\n"
            b"subprocess.run(['echo', 'hi'])\n"
        )
        signals = _analyze(SuspiciousStdlibAnalyzer(), source)
        for sig in signals:
            self.assertEqual(sig.enrichment_hints, frozenset())

    def test_other_density_signals_have_no_hint(self):
        # DENS001 (single-line token compression) should not request
        # enrichment; only DENS010 and DENS011 do, in this slice.
        source = (
            b"import os; import sys; import json; x=1; y=2; z=3; "
            b"a=4; b=5; c=6; d=7; e=8; f=9; g=10; h=11\n"
        )
        signals = _analyze(CodeDensityAnalyzer(), source)
        for sig in signals:
            if sig.signal_id in ("DENS010", "DENS011"):
                continue
            self.assertEqual(
                sig.enrichment_hints, frozenset(),
                msg=(
                    f"density signal {sig.signal_id} unexpectedly "
                    f"carries hints {sig.enrichment_hints}; only "
                    f"DENS010 and DENS011 should request enrichment "
                    f"in this slice"
                ),
            )


# ===========================================================================
# Signal field plumbing: pickle round-trip
# ===========================================================================

class SignalEnrichmentHintsPickleTests(unittest.TestCase):

    def test_default_empty_hints_pickles(self):
        sig = Signal(
            analyzer="test",
            signal_id="TEST001",
            confidence=Confidence.MEDIUM,
            scope=Scope.MODULE,
            location=SourceLocation(line=1, column=0),
            description="test",
        )
        round_tripped = pickle.loads(pickle.dumps(sig))
        self.assertEqual(round_tripped, sig)
        self.assertEqual(round_tripped.enrichment_hints, frozenset())

    def test_populated_hints_pickle(self):
        sig = Signal(
            analyzer="test",
            signal_id="TEST001",
            confidence=Confidence.MEDIUM,
            scope=Scope.MODULE,
            location=SourceLocation(line=1, column=0),
            description="test",
            enrichment_hints=frozenset({"payload_peek", "future_enricher"}),
        )
        round_tripped = pickle.loads(pickle.dumps(sig))
        self.assertEqual(round_tripped, sig)
        self.assertEqual(
            round_tripped.enrichment_hints,
            frozenset({"payload_peek", "future_enricher"}),
        )

    def test_full_value_in_context_pickles(self):
        # The stashed _full_value can be either str or bytes; both
        # need to round-trip cleanly.
        sig = Signal(
            analyzer="density_analyzer",
            signal_id="DENS010",
            confidence=Confidence.HIGH,
            scope=Scope.MODULE,
            location=SourceLocation(line=1, column=0),
            description="test",
            context={
                "length": 200,
                "_full_value": "A" * 200,
            },
            enrichment_hints=frozenset({"payload_peek"}),
        )
        round_tripped = pickle.loads(pickle.dumps(sig))
        self.assertEqual(round_tripped, sig)
        self.assertEqual(round_tripped.context["_full_value"], "A" * 200)


# ===========================================================================
# JSON reporter: underscore keys are omitted
# ===========================================================================

class ReporterOmitsUnderscoreKeysTests(unittest.TestCase):
    """The reporter must not emit `_full_value` or other underscore-
    prefixed context keys to JSON output. They are pipeline-internal."""

    def test_underscore_keys_omitted(self):
        from pydepgate.cli.reporter import _serialize_context
        out = _serialize_context({
            "length": 200,
            "_full_value": "A" * 200,
            "_full_value_truncated": True,
            "scope_name": "module",
        })
        self.assertIn("length", out)
        self.assertIn("scope_name", out)
        self.assertNotIn("_full_value", out)
        self.assertNotIn("_full_value_truncated", out)


if __name__ == "__main__":
    unittest.main()