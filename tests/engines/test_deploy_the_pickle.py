"""
Picklability contract tests for the per-file pipeline.

These tests exist to catch the day someone adds a non-picklable value
to an analyzer's signal.context (or anywhere else in the
FileScanInput/FileScanOutput data path). Until parallelism actually
lands, picklability is invisible to integration tests; this module
makes it visible.

The contract:
  - FileScanInput is picklable.
  - FileScanOutput is picklable.
  - StaticEngine is picklable.
  - A FileScanOutput round-tripped through pickle equals the original.

If any of these break, the planned parallel executor cannot work.
"""

import pickle
import tempfile
import textwrap
import unittest
from pathlib import Path

from pydepgate.analyzers.density_analyzer import CodeDensityAnalyzer
from pydepgate.analyzers.dynamic_execution import DynamicExecutionAnalyzer
from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.analyzers.string_ops import StringOpsAnalyzer
from pydepgate.analyzers.suspicious_stdlib import SuspiciousStdlibAnalyzer
from pydepgate.engines.base import (
    ArtifactKind,
    FileScanInput,
    FileScanOutput,
)
from pydepgate.engines.static import StaticEngine
from pydepgate.traffic_control.triage import FileKind


# Source fixtures designed to fire each analyzer at least once. Each
# fixture is structured so the analyzer-of-interest produces a finding
# whose context might plausibly carry exotic values; if any analyzer
# ever puts a non-picklable thing in context, the matching test fails.

_FIXTURE_ENCODING_ABUSE = b"""
import base64
exec(base64.b64decode('cHJpbnQoMSk='))
"""

_FIXTURE_DYNAMIC_EXECUTION = b"""
payload = compute_payload()
exec(payload)
"""

_FIXTURE_STRING_OPS = b"""
fn = getattr(__builtins__, 'ev' + 'al')
fn('1+1')
"""

_FIXTURE_SUSPICIOUS_STDLIB = b"""
import subprocess
subprocess.run(['echo', 'hello'])
"""

_FIXTURE_CODE_DENSITY = b"""
# High-entropy string, base64 alphabet, dense identifiers.
_x = "QWxsIHRoZSB3b3JsZHMgYSBzdGFnZSBhbmQgYWxsIHRoZSBtZW4gYW5kIHdvbWVuIGFyZQ=="
import base64; _y = base64.b64decode; _z = lambda d: exec(_y(d))
"""


def _make_engine(analyzer_class) -> StaticEngine:
    """Build an engine with a single analyzer, no rules.

    No rules so that all signals become findings via the mechanical
    confidence-to-severity mapping. Tests that need the rule layer
    use the full-engine helper below.
    """
    return StaticEngine(analyzers=[analyzer_class()], rules=[])


def _scan(engine: StaticEngine, content: bytes) -> FileScanOutput:
    """Drive _scan_one_file directly with a fixed setup.py-style input."""
    inp = FileScanInput(
        content=content,
        internal_path="setup.py",
        artifact_kind=ArtifactKind.LOOSE_FILE,
        artifact_identity="setup.py",
        forced_file_kind=None,
    )
    return engine._scan_one_file(inp)


# =============================================================================
# Tier 1: The boundary types pickle
# =============================================================================

class FileScanInputPickleTests(unittest.TestCase):

    def test_minimal_input_pickles(self):
        inp = FileScanInput(
            content=b"x = 1\n",
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="/tmp/setup.py",
            forced_file_kind=None,
        )
        round_tripped = pickle.loads(pickle.dumps(inp))
        self.assertEqual(round_tripped, inp)

    def test_input_with_forced_kind_pickles(self):
        inp = FileScanInput(
            content=b"x = 1\n",
            internal_path="/tmp/garbage.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="/tmp/garbage.py",
            forced_file_kind=FileKind.SETUP_PY,
        )
        round_tripped = pickle.loads(pickle.dumps(inp))
        self.assertEqual(round_tripped, inp)
        self.assertIs(round_tripped.forced_file_kind, FileKind.SETUP_PY)

    def test_input_with_large_content_pickles(self):
        # 1 MB of bytes should pickle without issue. If pickle has
        # a problem with a hundred bytes it'll have a problem with
        # a million; this is just a sanity check.
        large = b"x = 1\n" * 100_000
        inp = FileScanInput(
            content=large,
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="/tmp/setup.py",
        )
        round_tripped = pickle.loads(pickle.dumps(inp))
        self.assertEqual(len(round_tripped.content), len(large))


class FileScanOutputPickleTests(unittest.TestCase):

    def test_empty_output_pickles(self):
        engine = _make_engine(EncodingAbuseAnalyzer)
        output = _scan(engine, b"x = 1\n")
        round_tripped = pickle.loads(pickle.dumps(output))
        self.assertEqual(round_tripped, output)

    def test_output_with_findings_pickles(self):
        engine = _make_engine(EncodingAbuseAnalyzer)
        output = _scan(engine, _FIXTURE_ENCODING_ABUSE)
        self.assertGreater(
            len(output.findings), 0,
            msg="fixture failed to produce findings; test is meaningless",
        )
        round_tripped = pickle.loads(pickle.dumps(output))
        self.assertEqual(round_tripped, output)


# =============================================================================
# Tier 2: Per-analyzer picklability
# =============================================================================

class PerAnalyzerPickleTests(unittest.TestCase):
    """Pickle a FileScanOutput from each analyzer's findings.

    If any analyzer ever puts a non-picklable thing in
    `signal.context` (a closure, a regex match object, an AST
    node, a bound method), that analyzer's test fails. This is
    the test that catches the bug before the day someone tries
    to enable parallelism and discovers the workers are silently
    raising PicklingError.
    """

    def _assert_round_trip_clean(self, analyzer_class, fixture):
        engine = _make_engine(analyzer_class)
        output = _scan(engine, fixture)
        self.assertGreater(
            len(output.findings) + len(output.suppressed_findings), 0,
            msg=(
                f"{analyzer_class.__name__} produced no findings on its "
                f"fixture; either the fixture is wrong or the analyzer "
                f"changed shape and this test no longer covers it."
            ),
        )
        try:
            data = pickle.dumps(output)
        except Exception as exc:
            self.fail(
                f"{analyzer_class.__name__} output failed to pickle: {exc}"
            )
        round_tripped = pickle.loads(data)
        self.assertEqual(round_tripped, output)

    def test_encoding_abuse_picklable(self):
        self._assert_round_trip_clean(
            EncodingAbuseAnalyzer, _FIXTURE_ENCODING_ABUSE,
        )

    def test_dynamic_execution_picklable(self):
        self._assert_round_trip_clean(
            DynamicExecutionAnalyzer, _FIXTURE_DYNAMIC_EXECUTION,
        )

    def test_string_ops_picklable(self):
        self._assert_round_trip_clean(
            StringOpsAnalyzer, _FIXTURE_STRING_OPS,
        )

    def test_suspicious_stdlib_picklable(self):
        self._assert_round_trip_clean(
            SuspiciousStdlibAnalyzer, _FIXTURE_SUSPICIOUS_STDLIB,
        )

    def test_code_density_picklable(self):
        self._assert_round_trip_clean(
            CodeDensityAnalyzer, _FIXTURE_CODE_DENSITY,
        )


# =============================================================================
# Tier 3: The engine itself pickles
# =============================================================================

class StaticEnginePickleTests(unittest.TestCase):
    """The engine instance must pickle.

    `multiprocessing.Pool.map(self._scan_one_file, inputs)` pickles
    the bound method, which means it pickles `self`. If the engine
    ever holds a non-picklable value, parallelism breaks.
    """

    def test_engine_with_no_analyzers_pickles(self):
        engine = StaticEngine(analyzers=[], rules=[])
        round_tripped = pickle.loads(pickle.dumps(engine))
        self.assertEqual(len(round_tripped.analyzers), 0)
        self.assertEqual(len(round_tripped.rules), 0)

    def test_engine_with_all_analyzers_pickles(self):
        engine = StaticEngine(
            analyzers=[
                EncodingAbuseAnalyzer(),
                DynamicExecutionAnalyzer(),
                StringOpsAnalyzer(),
                SuspiciousStdlibAnalyzer(),
                CodeDensityAnalyzer(),
            ],
            rules=[],
        )
        round_tripped = pickle.loads(pickle.dumps(engine))
        self.assertEqual(len(round_tripped.analyzers), 5)

    def test_engine_with_default_rules_pickles(self):
        # Default rules are loaded from defaults.py. If any rule ever
        # holds a closure or other non-picklable value (e.g. a lambda
        # in an effect), this fails.
        engine = StaticEngine(
            analyzers=[CodeDensityAnalyzer()],
            rules=None,  # None triggers DEFAULT_RULES loading
        )
        round_tripped = pickle.loads(pickle.dumps(engine))
        self.assertEqual(len(round_tripped.rules), len(engine.rules))

    def test_engine_method_is_picklable(self):
        # Bound method picklability is what multiprocessing.Pool.map
        # actually uses. Test it explicitly.
        engine = StaticEngine(analyzers=[CodeDensityAnalyzer()], rules=[])
        method = engine._scan_one_file
        round_tripped = pickle.loads(pickle.dumps(method))
        # Smoke test: the unpickled method works the same way.
        inp = FileScanInput(
            content=b"x = 1\n",
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="setup.py",
        )
        original_output = method(inp)
        unpickled_output = round_tripped(inp)
        # Stats include duration_seconds which varies; compare findings.
        self.assertEqual(
            original_output.findings, unpickled_output.findings,
        )


if __name__ == "__main__":
    unittest.main()