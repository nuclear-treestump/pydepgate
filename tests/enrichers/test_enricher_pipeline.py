"""
Pipeline-shape tests for the enricher subsystem.

These tests verify the invariants that make future parallelism a
one-line change:

  Invariant 1: enrich() is a pure function in call shape.
    Calling it twice on a fresh engine with the same input produces
    the same result. self is not mutated by the call.

  Invariant 2: When the engine has enrichers configured, they are
    invoked once per scanned file, after analyzers and before rule
    evaluation.

  Invariant 3: An engine with no enrichers configured is observably
    identical to the engine pre-enricher-feature; no behavior change
    for callers who don't opt in.

  Invariant 4: A failing enricher does not abort the scan; the
    failure is recorded in diagnostics and the un-enriched stream
    proceeds to subsequent enrichers and to rule evaluation.

  Invariant 5: Multiple enrichers run in registration order, each
    seeing the output of the previous enricher.

If any of these break, parallelism either won't work at all or
will produce different results than serial execution. Lock them
down here.
"""

import dataclasses
import unittest
from typing import Iterable

from pydepgate.analyzers.base import Signal
from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.engines.base import (
    ArtifactKind,
    FileScanInput,
    ScanContext,
)
from pydepgate.engines.static import StaticEngine
from pydepgate.enrichers.base import Enricher
from pydepgate.enrichers.passthrough import NoOpEnricher


_MALICIOUS_SETUP_PY = b"""
import base64
exec(base64.b64decode('cHJpbnQoMSk='))
"""


# ---------------------------------------------------------------------------
# Test-double enrichers
# ---------------------------------------------------------------------------

class _MarkingEnricher(Enricher):
    """Adds a marker key to every signal's context.

    Stateless: the marker key/value are immutable instance config
    set at construction. The enricher does not accumulate anything
    across calls.
    """

    def __init__(self, marker_key: str = "marked", marker_value=True):
        self._marker_key = marker_key
        self._marker_value = marker_value

    @property
    def name(self) -> str:
        return f"marker_{self._marker_key}"

    def enrich(
        self,
        signals: tuple[Signal, ...],
        content: bytes,
        context: ScanContext,
    ) -> Iterable[Signal]:
        out = []
        for sig in signals:
            new_context = {**sig.context, self._marker_key: self._marker_value}
            out.append(dataclasses.replace(sig, context=new_context))
        return tuple(out)


class _RaisingEnricher(Enricher):
    """Always raises when called; tests failure containment."""

    @property
    def name(self) -> str:
        return "always_raises"

    def enrich(
        self,
        signals: tuple[Signal, ...],
        content: bytes,
        context: ScanContext,
    ) -> Iterable[Signal]:
        raise RuntimeError("simulated enricher failure")


class _CountingEnricher(Enricher):
    """Increments an `enricher_chain_depth` counter on every signal.

    Used to verify that enrichers see each other's output. When N
    counting enrichers run in a chain, every signal ends up with
    a depth value of N.
    """

    @property
    def name(self) -> str:
        return "counting"

    def enrich(
        self,
        signals: tuple[Signal, ...],
        content: bytes,
        context: ScanContext,
    ) -> Iterable[Signal]:
        out = []
        for sig in signals:
            existing = sig.context.get("enricher_chain_depth", 0)
            new_context = {
                **sig.context,
                "enricher_chain_depth": existing + 1,
            }
            out.append(dataclasses.replace(sig, context=new_context))
        return tuple(out)


def _input(content=_MALICIOUS_SETUP_PY, path="setup.py", forced=None):
    return FileScanInput(
        content=content,
        internal_path=path,
        artifact_kind=ArtifactKind.LOOSE_FILE,
        artifact_identity=path,
        forced_file_kind=forced,
    )


# ===========================================================================
# Invariant 1: enrich() is pure in call shape
# ===========================================================================

class EnrichmentIsPureTests(unittest.TestCase):
    """The enrichment pass does not mutate engine state."""

    def test_repeated_calls_produce_same_findings(self):
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[_MarkingEnricher()],
            rules=[],
        )
        out1 = engine._scan_one_file(_input())
        out2 = engine._scan_one_file(_input())
        self.assertEqual(out1.findings, out2.findings)
        self.assertEqual(
            out1.suppressed_findings, out2.suppressed_findings,
        )

    def test_engine_attributes_not_mutated_by_enrichment(self):
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[_MarkingEnricher()],
            rules=[],
        )
        analyzers_before = engine.analyzers
        enrichers_before = engine.enrichers
        engine._scan_one_file(_input())
        # Same tuple identities; engine did not rebuild internal state.
        self.assertIs(engine.analyzers, analyzers_before)
        self.assertIs(engine.enrichers, enrichers_before)


# ===========================================================================
# Invariant 2: Enrichers run after analyzers, before rules
# ===========================================================================

class EnricherOrderingTests(unittest.TestCase):

    def test_enricher_sees_analyzer_output(self):
        # If the enricher runs after the analyzer, the marker shows
        # up in the findings' context.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[_MarkingEnricher("test_marker", "abc")],
            rules=[],
        )
        out = engine._scan_one_file(_input())
        self.assertGreater(len(out.findings), 0)
        for finding in out.findings:
            self.assertEqual(
                finding.signal.context.get("test_marker"), "abc",
                msg=(
                    f"finding {finding.signal.signal_id} did not "
                    f"receive the enricher's marker; enricher may "
                    f"not be running, or may be running in the "
                    f"wrong order"
                ),
            )

    def test_enricher_runs_for_every_scanned_file(self):
        # Two scans of the same engine: each scan triggers its own
        # enrichment pass.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[_MarkingEnricher("seen", True)],
            rules=[],
        )
        out1 = engine._scan_one_file(_input())
        out2 = engine._scan_one_file(_input())
        for out in (out1, out2):
            for finding in out.findings:
                self.assertTrue(finding.signal.context.get("seen"))


# ===========================================================================
# Invariant 3: No enrichers means no behavior change
# ===========================================================================

class EnricherBackwardsCompatibilityTests(unittest.TestCase):

    def test_constructor_without_enrichers_kwarg_still_works(self):
        # Existing callers that never knew about enrichers still work.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()], rules=[],
        )
        out = engine._scan_one_file(_input())
        self.assertGreater(len(out.findings), 0)

    def test_explicit_empty_enrichers_list_is_a_noop(self):
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[],
            rules=[],
        )
        out = engine._scan_one_file(_input())
        self.assertGreater(len(out.findings), 0)

    def test_no_enrichers_findings_match_empty_enrichers(self):
        # The two construction forms must produce identical findings.
        engine_a = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            rules=[],
        )
        engine_b = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[],
            rules=[],
        )
        out_a = engine_a._scan_one_file(_input())
        out_b = engine_b._scan_one_file(_input())
        self.assertEqual(out_a.findings, out_b.findings)
        self.assertEqual(out_a.diagnostics, out_b.diagnostics)

    def test_enrichers_run_count_is_zero_with_no_enrichers(self):
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            rules=[],
        )
        out = engine._scan_one_file(_input())
        self.assertEqual(out.statistics.enrichers_run, 0)


# ===========================================================================
# Invariant 4: Failure containment
# ===========================================================================

class EnricherFailureTests(unittest.TestCase):

    def test_raising_enricher_does_not_abort_scan(self):
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[_RaisingEnricher()],
            rules=[],
        )
        out = engine._scan_one_file(_input())
        # Findings still come through (enricher failure falls back
        # to un-enriched stream, which goes on to rule evaluation).
        self.assertGreater(len(out.findings), 0)
        # And the failure is recorded in diagnostics.
        joined_diags = " ".join(out.diagnostics)
        self.assertIn("always_raises", joined_diags)

    def test_raising_enricher_does_not_block_subsequent_enrichers(self):
        # Chain: [Raising, Marking]. The Marking enricher should
        # still run on the un-enriched stream that survived the
        # raise.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[
                _RaisingEnricher(),
                _MarkingEnricher("after_raise", True),
            ],
            rules=[],
        )
        out = engine._scan_one_file(_input())
        self.assertGreater(len(out.findings), 0)
        for finding in out.findings:
            self.assertTrue(
                finding.signal.context.get("after_raise"),
                msg=(
                    "Marker enricher did not run after the raising "
                    "enricher; failure containment may be aborting "
                    "the chain instead of just that one enricher"
                ),
            )

    def test_enricher_run_count_reflects_configured_count_even_on_failure(self):
        # enrichers_run is "configured count", not "succeeded count".
        # A failure still counts toward "we ran the enrichment phase
        # with N enrichers," because that is what a parallelism
        # consumer cares about for cost accounting.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[_RaisingEnricher(), _MarkingEnricher()],
            rules=[],
        )
        out = engine._scan_one_file(_input())
        self.assertEqual(out.statistics.enrichers_run, 2)


# ===========================================================================
# Invariant 5: Multiple enrichers chain in registration order
# ===========================================================================

class EnricherChainTests(unittest.TestCase):

    def test_three_enrichers_chain_in_order(self):
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[
                _CountingEnricher(),
                _CountingEnricher(),
                _CountingEnricher(),
            ],
            rules=[],
        )
        out = engine._scan_one_file(_input())
        self.assertGreater(len(out.findings), 0)
        for finding in out.findings:
            self.assertEqual(
                finding.signal.context.get("enricher_chain_depth"), 3,
            )

    def test_each_enricher_sees_previous_enrichers_output(self):
        # First enricher adds 'phase1', second observes whether
        # 'phase1' is present on every signal it receives.
        observations: list[bool] = []

        class Phase2Observer(Enricher):
            @property
            def name(self) -> str:
                return "phase2_observer"

            def enrich(self, signals, content, context):
                for s in signals:
                    observations.append("phase1" in s.context)
                return signals

        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[
                _MarkingEnricher("phase1", True),
                Phase2Observer(),
            ],
            rules=[],
        )
        engine._scan_one_file(_input())
        self.assertGreater(
            len(observations), 0,
            msg="Phase2Observer never saw any signals",
        )
        self.assertTrue(
            all(observations),
            msg=(
                "Phase2Observer saw signals without 'phase1' set; "
                "enrichers may not be chaining correctly"
            ),
        )


# ===========================================================================
# Invariant 6: NoOpEnricher is well-behaved
# ===========================================================================

class NoOpEnricherTests(unittest.TestCase):
    """The bundled no-op exists for wiring/pickle tests; verify it works."""

    def test_noop_does_not_change_findings(self):
        engine_no = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            rules=[],
        )
        engine_yes = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[NoOpEnricher()],
            rules=[],
        )
        out_no = engine_no._scan_one_file(_input())
        out_yes = engine_yes._scan_one_file(_input())
        self.assertEqual(out_no.findings, out_yes.findings)

    def test_noop_increments_enrichers_run_counter(self):
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[NoOpEnricher()],
            rules=[],
        )
        out = engine._scan_one_file(_input())
        self.assertEqual(out.statistics.enrichers_run, 1)


if __name__ == "__main__":
    unittest.main()