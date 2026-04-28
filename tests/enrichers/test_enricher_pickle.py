"""
Picklability contract tests for the enricher pipeline.

These tests exist to catch the day someone adds a non-picklable
value to an enricher's instance state, or to a signal's context
dict via enrichment. Until parallelism actually lands, picklability
is invisible to integration tests; this module makes it visible,
matching the role of `tests/engines/test_deploy_the_pickle.py` for
the analyzer pipeline.

The contract:
  - Every Enricher subclass is picklable when constructed normally
    (the no-op enricher exemplifies the minimum case; a configurable
    enricher with typical instance attributes exemplifies the
    realistic case).
  - StaticEngine with enrichers configured is picklable.
  - The bound method `engine._scan_one_file` is picklable when
    enrichers are configured. This is what
    `multiprocessing.Pool.map(self._scan_one_file, inputs)` pickles.
  - A FileScanOutput produced from a scan with enrichment is
    picklable and round-trips equal.

If any of these break, the planned parallel executor cannot
schedule scans on workers when the user has enabled --peek (or
any future enricher-driven flag).
"""

import dataclasses
import pickle
import unittest
from typing import Iterable

from pydepgate.analyzers.base import Signal
from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.analyzers.density_analyzer import CodeDensityAnalyzer
from pydepgate.engines.base import (
    ArtifactKind,
    FileScanInput,
    FileScanOutput,
    ScanContext,
)
from pydepgate.engines.static import StaticEngine
from pydepgate.enrichers.base import Enricher
from pydepgate.enrichers._noop import NoOpEnricher


_MALICIOUS_SETUP_PY = b"""
import base64
exec(base64.b64decode('cHJpbnQoMSk='))
"""


class _ConfigurableEnricher(Enricher):
    """Holds typical configuration shape: ints and a frozenset of
    hint names.

    Mirrors what the upcoming payload_peek enricher is expected to
    look like (depth limit, byte budget, internal frozenset state).
    If any of these field types ever stops pickling cleanly, so
    does the real enricher; this test class is the canary.
    """

    def __init__(
        self,
        depth: int = 3,
        budget: int = 524288,
        recognized_hints: tuple[str, ...] = ("payload_peek",),
    ):
        self._depth = depth
        self._budget = budget
        self._recognized_hints = frozenset(recognized_hints)

    @property
    def name(self) -> str:
        return "configurable"

    def enrich(
        self,
        signals: tuple[Signal, ...],
        content: bytes,
        context: ScanContext,
    ) -> Iterable[Signal]:
        out = []
        for sig in signals:
            new_context = {
                **sig.context,
                "configurable_depth": self._depth,
                "configurable_budget": self._budget,
            }
            out.append(dataclasses.replace(sig, context=new_context))
        return tuple(out)

# ===========================================================================
# Tier 1: Enricher instances pickle
# ===========================================================================

class EnricherInstancePickleTests(unittest.TestCase):

    def test_noop_pickles(self):
        e = NoOpEnricher()
        round_tripped = pickle.loads(pickle.dumps(e))
        self.assertEqual(round_tripped.name, "noop")

    def test_configurable_pickles_default_args(self):
        e = _ConfigurableEnricher()
        round_tripped = pickle.loads(pickle.dumps(e))
        self.assertEqual(round_tripped._depth, 3)
        self.assertEqual(round_tripped._budget, 524288)
        self.assertEqual(
            round_tripped._recognized_hints,
            frozenset({"payload_peek"}),
        )

    def test_configurable_pickles_custom_args(self):
        e = _ConfigurableEnricher(
            depth=5, budget=1024, recognized_hints=("foo", "bar"),
        )
        round_tripped = pickle.loads(pickle.dumps(e))
        self.assertEqual(round_tripped._depth, 5)
        self.assertEqual(round_tripped._budget, 1024)
        self.assertEqual(
            round_tripped._recognized_hints,
            frozenset({"foo", "bar"}),
        )

    def test_unpickled_enricher_works(self):
        # Smoke test: a round-tripped enricher actually functions
        # when invoked. Catches bugs where pickle serializes the
        # instance but loses something the method needs.
        e = _ConfigurableEnricher(depth=7, budget=999)
        round_tripped = pickle.loads(pickle.dumps(e))

        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[round_tripped],
            rules=[],
        )
        out = engine._scan_one_file(_make_input())
        self.assertGreater(len(out.findings), 0)
        for finding in out.findings:
            self.assertEqual(
                finding.signal.context.get("configurable_depth"), 7,
            )
            self.assertEqual(
                finding.signal.context.get("configurable_budget"), 999,
            )


# ===========================================================================
# Tier 2: Engine with enrichers pickles
# ===========================================================================

class StaticEngineWithEnrichersPickleTests(unittest.TestCase):
    """The engine instance must pickle.

    `multiprocessing.Pool.map(self._scan_one_file, inputs)` pickles
    the bound method, which means it pickles `self`. If the engine
    ever holds a non-picklable value via its enrichers list, the
    feature breaks parallelism.
    """

    def test_engine_with_no_enrichers_still_pickles(self):
        # Backwards-compatibility check: the empty-tuple default
        # for enrichers does not introduce a pickle problem.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()], rules=[],
        )
        round_tripped = pickle.loads(pickle.dumps(engine))
        self.assertEqual(len(round_tripped.enrichers), 0)

    def test_engine_with_noop_enricher_pickles(self):
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[NoOpEnricher()],
            rules=[],
        )
        round_tripped = pickle.loads(pickle.dumps(engine))
        self.assertEqual(len(round_tripped.enrichers), 1)
        self.assertEqual(round_tripped.enrichers[0].name, "noop")

    def test_engine_with_multiple_enrichers_pickles(self):
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer(), CodeDensityAnalyzer()],
            enrichers=[NoOpEnricher(), _ConfigurableEnricher()],
            rules=[],
        )
        round_tripped = pickle.loads(pickle.dumps(engine))
        self.assertEqual(len(round_tripped.enrichers), 2)
        self.assertEqual(round_tripped.enrichers[0].name, "noop")
        self.assertEqual(round_tripped.enrichers[1].name, "configurable")


# ===========================================================================
# Tier 3: Bound _scan_one_file pickles when enrichers present
# ===========================================================================

class BoundMethodPickleTests(unittest.TestCase):
    """For `pool.map(self._scan_one_file, inputs)` to work."""

    def test_bound_method_with_enrichers_pickles(self):
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[NoOpEnricher()],
            rules=[],
        )
        method = engine._scan_one_file
        unpickled = pickle.loads(pickle.dumps(method))

        original_output = method(_make_input())
        unpickled_output = unpickled(_make_input())
        # Findings should match (timing varies).
        self.assertEqual(
            original_output.findings, unpickled_output.findings,
        )

    def test_bound_method_with_configurable_enricher_pickles(self):
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[_ConfigurableEnricher(depth=5, budget=2048)],
            rules=[],
        )
        method = engine._scan_one_file
        unpickled = pickle.loads(pickle.dumps(method))

        out = unpickled(_make_input())
        self.assertGreater(len(out.findings), 0)
        for finding in out.findings:
            self.assertEqual(
                finding.signal.context.get("configurable_depth"), 5,
            )


# ===========================================================================
# Tier 4: Output from enrichment-enabled scan pickles
# ===========================================================================

class OutputPickleTests(unittest.TestCase):

    def test_output_round_trips_after_enrichment(self):
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[_ConfigurableEnricher()],
            rules=[],
        )
        output = engine._scan_one_file(_make_input())
        self.assertGreater(
            len(output.findings) + len(output.suppressed_findings), 0,
        )
        try:
            data = pickle.dumps(output)
        except Exception as exc:
            self.fail(f"output failed to pickle: {exc}")
        round_tripped = pickle.loads(data)
        self.assertEqual(round_tripped, output)

    def test_enrichment_added_context_survives_pickle(self):
        # Keys added by the enricher must survive pickle round-trip.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[_ConfigurableEnricher(depth=7, budget=999)],
            rules=[],
        )
        output = engine._scan_one_file(_make_input())
        round_tripped = pickle.loads(pickle.dumps(output))
        for finding in round_tripped.findings:
            self.assertEqual(
                finding.signal.context.get("configurable_depth"), 7,
            )
            self.assertEqual(
                finding.signal.context.get("configurable_budget"), 999,
            )

    def test_output_with_noop_enricher_pickles(self):
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            enrichers=[NoOpEnricher()],
            rules=[],
        )
        output = engine._scan_one_file(_make_input())
        round_tripped = pickle.loads(pickle.dumps(output))
        self.assertEqual(round_tripped, output)


if __name__ == "__main__":
    unittest.main()