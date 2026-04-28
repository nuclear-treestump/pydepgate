"""
Integration tests for `pydepgate.enrichers.payload_peek`.

These tests exercise the enricher end-to-end through the engine
pipeline: real analyzers produce signals, the engine runs the
enricher between analyzer and rule passes, and we assert on the
findings that come out.

The tests are organized by feature:

  - Construction: validation of min_length floor, depth floor,
    budget floor.
  - Threshold filtering: signals below min_length are skipped.
  - Hint filtering: signals without the payload_peek hint are
    untouched.
  - Decoded block contents: chain, final_kind, indicators,
    preview fields.
  - ENC002 emission: at depth 2 (AMBIGUOUS), depth 3 (MEDIUM),
    exhausted_depth (HIGH); not emitted for depth 1.
  - Pickle warning surfacing.
  - Picklability of the enricher and its post-enrichment output.
"""

import base64
import dataclasses
import pickle
import unittest
import zlib

from pydepgate.analyzers.base import Confidence, Scope, Signal
from pydepgate.analyzers.density_analyzer import CodeDensityAnalyzer
from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.engines.base import (
    ArtifactKind,
    FileScanInput,
    ScanContext,
)
from pydepgate.engines.static import StaticEngine
from pydepgate.enrichers.payload_peek import (
    DEFAULT_MAX_BUDGET,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MIN_LENGTH,
    MIN_BUDGET_FLOOR,
    MIN_LENGTH_FLOOR,
    PayloadPeek,
)
from pydepgate.parsers.pysource import SourceLocation


# ---------------------------------------------------------------------------
# Inert source used to build forward-chained payloads.
# ---------------------------------------------------------------------------

_INERT_SOURCE = (
    b"import os\n"
    b"import subprocess\n"
    b"def main():\n"
    b"    subprocess.run(['echo', 'inert'])\n"
    b"main()\n"
) * 5  # repetition pushes well past every default threshold


def _build_setup_py_with_chain(*encodings: str) -> bytes:
    """Build a setup.py whose payload literal is INERT_SOURCE wrapped
    in the named encodings, applied innermost-first.

    Example:
        _build_setup_py_with_chain('zlib', 'base64')
        # produces: payload = "<b64(zlib(INERT))>"
    """
    payload = _INERT_SOURCE
    for encoding in encodings:
        if encoding == "zlib":
            payload = zlib.compress(payload)
        elif encoding == "base64":
            payload = base64.b64encode(payload)
        else:
            raise ValueError(f"unknown encoding: {encoding}")
    if isinstance(payload, bytes):
        payload_str = payload.decode("ascii")
    else:
        payload_str = payload
    return (
        b"# Synthetic fixture; payload below is inert.\n"
        b"_PAYLOAD = '" + payload_str.encode("ascii") + b"'\n"
        b"# real attacks would: exec(base64.b64decode(_PAYLOAD))\n"
    )


def _scan_one(content: bytes, peek: PayloadPeek):
    engine = StaticEngine(
        analyzers=[CodeDensityAnalyzer(), EncodingAbuseAnalyzer()],
        enrichers=[peek],
        rules=[],
    )
    inp = FileScanInput(
        content=content,
        internal_path="setup.py",
        artifact_kind=ArtifactKind.LOOSE_FILE,
        artifact_identity="setup.py",
    )
    return engine._scan_one_file(inp)


# ===========================================================================
# Constructor validation
# ===========================================================================

class ConstructorValidationTests(unittest.TestCase):

    def test_default_construction_works(self):
        peek = PayloadPeek()
        self.assertEqual(peek.min_length, DEFAULT_MIN_LENGTH)
        self.assertEqual(peek.max_depth, DEFAULT_MAX_DEPTH)
        self.assertEqual(peek.max_budget, DEFAULT_MAX_BUDGET)

    def test_min_length_below_floor_raises(self):
        with self.assertRaises(ValueError) as ctx:
            PayloadPeek(min_length=15)
        self.assertIn(str(MIN_LENGTH_FLOOR), str(ctx.exception))

    def test_min_length_at_floor_works(self):
        peek = PayloadPeek(min_length=MIN_LENGTH_FLOOR)
        self.assertEqual(peek.min_length, MIN_LENGTH_FLOOR)

    def test_max_depth_zero_raises(self):
        with self.assertRaises(ValueError):
            PayloadPeek(max_depth=0)

    def test_max_depth_negative_raises(self):
        with self.assertRaises(ValueError):
            PayloadPeek(max_depth=-1)

    def test_budget_below_floor_raises(self):
        with self.assertRaises(ValueError):
            PayloadPeek(max_budget=512)


# ===========================================================================
# Threshold filtering
# ===========================================================================

class ThresholdFilteringTests(unittest.TestCase):
    """Signals below min_length are not enriched."""

    def test_below_threshold_signal_passes_through(self):
        # Build a signal with length=100 (below default 1024). Since
        # we control the signal directly, we can bypass the analyzer.
        peek = PayloadPeek()
        sig = Signal(
            analyzer="density_analyzer",
            signal_id="DENS010",
            confidence=Confidence.MEDIUM,
            scope=Scope.MODULE,
            location=SourceLocation(line=1, column=0),
            description="test",
            context={
                "length": 100,
                "_full_value": "AAAA" * 25,  # 100 chars
            },
            enrichment_hints=frozenset({"payload_peek"}),
        )
        ctx = ScanContext(
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="setup.py",
            internal_path="setup.py",
            file_kind=None,
            triage_reason="test",
        )
        out = list(peek.enrich((sig,), b"", ctx))
        self.assertEqual(len(out), 1)
        # No 'decoded' block was added.
        self.assertNotIn("decoded", out[0].context)

    def test_at_threshold_signal_attempts_enrichment(self):
        # Signal at exactly min_length should attempt enrichment.
        peek = PayloadPeek(min_length=MIN_LENGTH_FLOOR)
        chain_payload = base64.b64encode(_INERT_SOURCE).decode("ascii")
        sig = Signal(
            analyzer="density_analyzer",
            signal_id="DENS010",
            confidence=Confidence.MEDIUM,
            scope=Scope.MODULE,
            location=SourceLocation(line=1, column=0),
            description="test",
            context={
                "length": len(chain_payload),
                "_full_value": chain_payload,
            },
            enrichment_hints=frozenset({"payload_peek"}),
        )
        ctx = ScanContext(
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="setup.py",
            internal_path="setup.py",
            file_kind=None,
            triage_reason="test",
        )
        out = list(peek.enrich((sig,), b"", ctx))
        # Got at least the original (possibly enriched).
        enriched = [s for s in out if s.signal_id == "DENS010"]
        self.assertEqual(len(enriched), 1)
        self.assertIn("decoded", enriched[0].context)


# ===========================================================================
# Hint filtering
# ===========================================================================

class HintFilteringTests(unittest.TestCase):

    def test_signal_without_payload_peek_hint_passes_through(self):
        peek = PayloadPeek()
        sig = Signal(
            analyzer="other",
            signal_id="DYN001",
            confidence=Confidence.MEDIUM,
            scope=Scope.MODULE,
            location=SourceLocation(line=1, column=0),
            description="test",
            context={"length": 5000, "_full_value": "x" * 5000},
            enrichment_hints=frozenset(),  # no hints
        )
        ctx = ScanContext(
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="setup.py",
            internal_path="setup.py",
            file_kind=None,
            triage_reason="test",
        )
        out = list(peek.enrich((sig,), b"", ctx))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0], sig)
        self.assertNotIn("decoded", out[0].context)

    def test_signal_with_other_hint_passes_through(self):
        peek = PayloadPeek()
        sig = Signal(
            analyzer="other",
            signal_id="OTHER",
            confidence=Confidence.MEDIUM,
            scope=Scope.MODULE,
            location=SourceLocation(line=1, column=0),
            description="test",
            context={"length": 5000, "_full_value": "x" * 5000},
            enrichment_hints=frozenset({"some_other_enricher"}),
        )
        ctx = ScanContext(
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="setup.py",
            internal_path="setup.py",
            file_kind=None,
            triage_reason="test",
        )
        out = list(peek.enrich((sig,), b"", ctx))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0], sig)


# ===========================================================================
# Decoded-block contents (single-layer)
# ===========================================================================

class DecodedBlockSingleLayerTests(unittest.TestCase):

    def test_single_b64_layer_chain_recorded(self):
        content = _build_setup_py_with_chain("base64")
        out = _scan_one(content, PayloadPeek(min_length=MIN_LENGTH_FLOOR))

        # Find a finding with the decoded block.
        with_decoded = [
            f for f in out.findings
            if "decoded" in f.signal.context
        ]
        self.assertGreater(len(with_decoded), 0)

        decoded = with_decoded[0].signal.context["decoded"]
        self.assertEqual(decoded["layers_count"], 1)
        self.assertEqual(decoded["chain"][0]["kind"], "base64")
        self.assertEqual(decoded["final_kind"], "python_source")
        self.assertEqual(decoded["unwrap_status"], "completed")
        self.assertIn("subprocess", decoded["indicators"])
        self.assertFalse(decoded["pickle_warning"])

    def test_preview_hex_and_text_present(self):
        content = _build_setup_py_with_chain("base64")
        out = _scan_one(content, PayloadPeek(min_length=MIN_LENGTH_FLOOR))
        with_decoded = [
            f for f in out.findings if "decoded" in f.signal.context
        ]
        decoded = with_decoded[0].signal.context["decoded"]
        self.assertIn("preview_hex", decoded)
        self.assertIn("preview_text", decoded)
        # preview_hex should be a hex string (even length, hex chars).
        self.assertEqual(len(decoded["preview_hex"]) % 2, 0)
        self.assertTrue(all(
            c in "0123456789abcdef" for c in decoded["preview_hex"]
        ))


# ===========================================================================
# ENC002 emission
# ===========================================================================

class Enc002EmissionTests(unittest.TestCase):

    def test_depth_1_does_not_emit_enc002(self):
        content = _build_setup_py_with_chain("base64")
        out = _scan_one(content, PayloadPeek(min_length=MIN_LENGTH_FLOOR))
        enc002 = [f for f in out.findings if f.signal.signal_id == "ENC002"]
        self.assertEqual(len(enc002), 0)

    def test_depth_2_emits_ambiguous_enc002(self):
        # zlib then base64 = 2 layers when unwrapped.
        content = _build_setup_py_with_chain("zlib", "base64")
        out = _scan_one(content, PayloadPeek(min_length=MIN_LENGTH_FLOOR))
        enc002 = [f for f in out.findings if f.signal.signal_id == "ENC002"]
        self.assertGreater(len(enc002), 0)
        self.assertEqual(enc002[0].signal.confidence, Confidence.AMBIGUOUS)
        self.assertEqual(enc002[0].signal.context["layers_count"], 2)

    def test_depth_3_emits_medium_enc002(self):
        # b64 -> zlib -> b64 unwrap chain = 3 layers.
        content = _build_setup_py_with_chain(
            "base64", "zlib", "base64",
        )
        out = _scan_one(content, PayloadPeek(min_length=MIN_LENGTH_FLOOR))
        enc002 = [f for f in out.findings if f.signal.signal_id == "ENC002"]
        self.assertGreater(len(enc002), 0)
        self.assertEqual(enc002[0].signal.confidence, Confidence.MEDIUM)
        self.assertEqual(enc002[0].signal.context["layers_count"], 3)

    def test_exhausted_depth_emits_high_enc002(self):
        # 4-layer chain with default depth=3 forces exhaustion.
        content = _build_setup_py_with_chain(
            "zlib", "base64", "zlib", "base64",
        )
        out = _scan_one(content, PayloadPeek(min_length=MIN_LENGTH_FLOOR))
        enc002 = [f for f in out.findings if f.signal.signal_id == "ENC002"]
        self.assertGreater(len(enc002), 0)
        self.assertEqual(enc002[0].signal.confidence, Confidence.HIGH)
        self.assertEqual(
            enc002[0].signal.context["unwrap_status"], "exhausted_depth",
        )

    def test_enc002_does_not_request_further_enrichment(self):
        # An ENC002 signal must not carry enrichment_hints; we don't
        # want to enrich an enrichment.
        content = _build_setup_py_with_chain("zlib", "base64")
        out = _scan_one(content, PayloadPeek(min_length=MIN_LENGTH_FLOOR))
        for finding in out.findings:
            if finding.signal.signal_id == "ENC002":
                self.assertEqual(
                    finding.signal.enrichment_hints, frozenset(),
                    msg=(
                        "ENC002 should not carry enrichment_hints; "
                        "we don't want recursive enrichment"
                    ),
                )

    def test_enc002_carries_decoded_block(self):
        content = _build_setup_py_with_chain("zlib", "base64")
        out = _scan_one(content, PayloadPeek(min_length=MIN_LENGTH_FLOOR))
        enc002 = [f for f in out.findings if f.signal.signal_id == "ENC002"]
        self.assertGreater(len(enc002), 0)
        self.assertIn("decoded", enc002[0].signal.context)
        self.assertIn("chain_summary", enc002[0].signal.context)


# ===========================================================================
# Pickle warning surfacing
# ===========================================================================

class PickleWarningTests(unittest.TestCase):

    def test_pickle_inside_b64_sets_warning(self):
        # Note: this test exercises the unwrap loop's pickle terminal
        # via direct enricher invocation, since the analyzer may not
        # fire on a pickle-shaped fixture.
        peek = PayloadPeek(min_length=MIN_LENGTH_FLOOR)
        pickled = pickle.dumps([1, 2, 3, 4, 5] * 100, protocol=4)
        encoded = base64.b64encode(pickled).decode("ascii")
        sig = Signal(
            analyzer="density_analyzer",
            signal_id="DENS010",
            confidence=Confidence.MEDIUM,
            scope=Scope.MODULE,
            location=SourceLocation(line=1, column=0),
            description="test",
            context={
                "length": len(encoded),
                "_full_value": encoded,
            },
            enrichment_hints=frozenset({"payload_peek"}),
        )
        ctx = ScanContext(
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="setup.py",
            internal_path="setup.py",
            file_kind=None,
            triage_reason="test",
        )
        out = list(peek.enrich((sig,), b"", ctx))
        enriched = [s for s in out if s.signal_id == "DENS010"]
        self.assertEqual(len(enriched), 1)
        decoded = enriched[0].context["decoded"]
        self.assertTrue(decoded["pickle_warning"])
        self.assertEqual(decoded["final_kind"], "pickle_data")


# ===========================================================================
# Statelessness and picklability
# ===========================================================================

class StatelessnessAndPicklabilityTests(unittest.TestCase):

    def test_peek_is_stateless(self):
        # Two consecutive runs must produce the same result.
        peek = PayloadPeek(min_length=MIN_LENGTH_FLOOR)
        content = _build_setup_py_with_chain("zlib", "base64")
        out_a = _scan_one(content, peek)
        out_b = _scan_one(content, peek)
        self.assertEqual(out_a.findings, out_b.findings)

    def test_peek_pickles(self):
        peek = PayloadPeek(min_length=2048, max_depth=2, max_budget=65536)
        round_tripped = pickle.loads(pickle.dumps(peek))
        self.assertEqual(round_tripped.min_length, 2048)
        self.assertEqual(round_tripped.max_depth, 2)
        self.assertEqual(round_tripped.max_budget, 65536)

    def test_engine_with_peek_pickles(self):
        engine = StaticEngine(
            analyzers=[CodeDensityAnalyzer()],
            enrichers=[PayloadPeek(min_length=MIN_LENGTH_FLOOR)],
            rules=[],
        )
        round_tripped = pickle.loads(pickle.dumps(engine))
        self.assertEqual(len(round_tripped.enrichers), 1)
        self.assertEqual(round_tripped.enrichers[0].name, "payload_peek")

    def test_post_enrichment_output_pickles(self):
        content = _build_setup_py_with_chain("zlib", "base64")
        out = _scan_one(content, PayloadPeek(min_length=MIN_LENGTH_FLOOR))
        round_tripped = pickle.loads(pickle.dumps(out))
        self.assertEqual(round_tripped, out)


if __name__ == "__main__":
    unittest.main()