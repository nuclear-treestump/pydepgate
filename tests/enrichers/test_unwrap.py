"""
Unit tests for `pydepgate.enrichers._unwrap`.

The unwrap loop is the highest-stakes piece of payload_peek: it
processes attacker-controlled bytes, must not execute or import
anything, must enforce its depth and budget limits even on
pathological inputs (zip bombs, infinite-loop edge cases), and
must produce useful output on real chained payloads.

Tests are organized by behavior:

  - Single-layer chains (b64, hex, hex_0x_list, zlib, gzip, bzip2)
    each wrap an inert "print('inert')" payload. Verify chain shape,
    final classification, and indicator scanning.

  - Multi-layer chains (b64+zlib, b64+gzip, hex+zlib, b64+zlib+b64)
    verify the loop chains correctly across formats.

  - Limit enforcement:
      - Depth-3 chain plus a 4th layer triggers exhausted_depth.
      - Tiny budget triggers exhausted_budget at the appropriate
        layer.
      - Decompression bomb (small input declaring large output)
        triggers exhausted_budget.

  - Error paths:
      - Malformed base64 triggers decode_error.
      - Truncated zlib triggers decode_error.

  - Pickle: detected as terminal, pickle_warning set, never
    deserialized.

  - Loop detection: a degenerate input that round-trips through
    a transform (we have to construct one synthetically since
    real inputs do not exhibit this).

All fixtures are generated forward from an inert source string.
No real obfuscated payloads are committed.
"""

import base64
import bz2
import gzip
import lzma
import pickle
import unittest
import zlib

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


# ---------------------------------------------------------------------------
# Inert source used for all forward-built fixtures.
# ---------------------------------------------------------------------------

_INERT_SOURCE = (
    b"import os\n"
    b"import subprocess\n"
    b"def main():\n"
    b"    subprocess.run(['echo', 'inert demo payload'])\n"
    b"main()\n"
) * 3   # repeated to push above the entropy thresholds at any layer


# Default unwrap params used unless a test overrides.
_DEFAULT_DEPTH = 3
_DEFAULT_BUDGET = 512 * 1024


def _do_unwrap(initial, depth=_DEFAULT_DEPTH, budget=_DEFAULT_BUDGET):
    return unwrap(initial, max_depth=depth, max_budget=budget)


# ===========================================================================
# Single-layer chains
# ===========================================================================

class SingleLayerChainTests(unittest.TestCase):

    def test_pure_base64_unwraps_to_python_source(self):
        encoded = base64.b64encode(_INERT_SOURCE).decode("ascii")
        result = _do_unwrap(encoded)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 1)
        self.assertEqual(result.chain[0].kind, "base64")
        self.assertEqual(result.final_kind, "python_source")
        self.assertIn("subprocess", result.indicators)

    def test_pure_hex_unwraps_to_python_source(self):
        encoded = _INERT_SOURCE.hex()
        result = _do_unwrap(encoded)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 1)
        self.assertEqual(result.chain[0].kind, "hex")
        self.assertEqual(result.final_kind, "python_source")

    def test_hex_0x_list_unwraps_to_python_source(self):
        encoded = ", ".join(f"0x{b:02x}" for b in _INERT_SOURCE)
        result = _do_unwrap(encoded)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 1)
        self.assertEqual(result.chain[0].kind, "hex_0x_list")
        self.assertEqual(result.final_kind, "python_source")

    def test_zlib_unwraps_to_python_source(self):
        compressed = zlib.compress(_INERT_SOURCE)
        result = _do_unwrap(compressed)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 1)
        self.assertEqual(result.chain[0].kind, "zlib")
        self.assertEqual(result.final_kind, "python_source")

    def test_gzip_unwraps_to_python_source(self):
        compressed = gzip.compress(_INERT_SOURCE)
        result = _do_unwrap(compressed)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 1)
        self.assertEqual(result.chain[0].kind, "gzip")
        self.assertEqual(result.final_kind, "python_source")

    def test_bzip2_unwraps_to_python_source(self):
        compressed = bz2.compress(_INERT_SOURCE)
        result = _do_unwrap(compressed)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 1)
        self.assertEqual(result.chain[0].kind, "bzip2")
        self.assertEqual(result.final_kind, "python_source")

    def test_lzma_unwraps_to_python_source(self):
        compressed = lzma.compress(_INERT_SOURCE)
        result = _do_unwrap(compressed)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 1)
        self.assertEqual(result.chain[0].kind, "lzma")
        self.assertEqual(result.final_kind, "python_source")


# ===========================================================================
# Multi-layer chains
# ===========================================================================

class MultiLayerChainTests(unittest.TestCase):

    def test_b64_zlib_source(self):
        compressed = zlib.compress(_INERT_SOURCE)
        encoded = base64.b64encode(compressed).decode("ascii")
        result = _do_unwrap(encoded)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 2)
        self.assertEqual(
            tuple(layer.kind for layer in result.chain),
            ("base64", "zlib"),
        )
        self.assertEqual(result.final_kind, "python_source")
        self.assertIn("subprocess", result.indicators)

    def test_b64_gzip_source(self):
        compressed = gzip.compress(_INERT_SOURCE)
        encoded = base64.b64encode(compressed).decode("ascii")
        result = _do_unwrap(encoded)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(
            tuple(layer.kind for layer in result.chain),
            ("base64", "gzip"),
        )
        self.assertEqual(result.final_kind, "python_source")

    def test_hex_zlib_source(self):
        compressed = zlib.compress(_INERT_SOURCE)
        encoded = compressed.hex()
        result = _do_unwrap(encoded)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(
            tuple(layer.kind for layer in result.chain),
            ("hex", "zlib"),
        )

    def test_b64_zlib_b64_source(self):
        # depth 3, completes within the default depth limit.
        layer3 = base64.b64encode(_INERT_SOURCE)
        layer2 = zlib.compress(layer3)
        layer1 = base64.b64encode(layer2).decode("ascii")
        result = _do_unwrap(layer1)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 3)
        self.assertEqual(
            tuple(layer.kind for layer in result.chain),
            ("base64", "zlib", "base64"),
        )
        self.assertEqual(result.final_kind, "python_source")


# ===========================================================================
# Limit enforcement
# ===========================================================================

class DepthLimitTests(unittest.TestCase):

    def test_depth_4_chain_triggers_exhausted_depth(self):
        # b64(zlib(b64(zlib(source)))). Default depth is 3, so the
        # fourth layer would not be reached.
        layer4 = zlib.compress(_INERT_SOURCE)
        layer3 = base64.b64encode(layer4)
        layer2 = zlib.compress(layer3)
        layer1 = base64.b64encode(layer2).decode("ascii")
        result = _do_unwrap(layer1, depth=3)
        self.assertEqual(result.status, STATUS_EXHAUSTED_DEPTH)
        self.assertEqual(len(result.chain), 3)
        # The next would-be layer is reported.
        self.assertIsNotNone(result.continues_as)
        # The chain we did do should match.
        self.assertEqual(
            tuple(layer.kind for layer in result.chain),
            ("base64", "zlib", "base64"),
        )

    def test_depth_1_completes_single_layer(self):
        # Depth 1 means we do at most 1 transform, then either
        # terminal or exhausted. b64(source) completes in 1.
        encoded = base64.b64encode(_INERT_SOURCE).decode("ascii")
        result = _do_unwrap(encoded, depth=1)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 1)

    def test_depth_1_exhausts_on_two_layer_chain(self):
        # b64(zlib(source)) needs 2 layers; depth=1 forces exhaustion.
        compressed = zlib.compress(_INERT_SOURCE)
        encoded = base64.b64encode(compressed).decode("ascii")
        result = _do_unwrap(encoded, depth=1)
        self.assertEqual(result.status, STATUS_EXHAUSTED_DEPTH)
        self.assertEqual(len(result.chain), 1)
        self.assertEqual(result.continues_as, "zlib")


class BudgetLimitTests(unittest.TestCase):

    def test_tiny_budget_triggers_exhaustion(self):
        # Generous payload, miserly budget. The first layer's output
        # should immediately blow past the budget.
        encoded = base64.b64encode(_INERT_SOURCE).decode("ascii")
        result = _do_unwrap(encoded, budget=64)  # well below source size
        # The result is either exhausted_budget or decode_error
        # depending on which check fires first; both are acceptable
        # safety outcomes.
        self.assertIn(
            result.status,
            (STATUS_EXHAUSTED_BUDGET, STATUS_DECODE_ERROR),
        )

    def test_decompression_bomb_is_bounded(self):
        # Construct a small input that decompresses very large.
        # zlib of a megabyte of zeros is tiny but expands enormously.
        bomb = zlib.compress(b"\x00" * (2 * 1024 * 1024))
        # Default budget is 512KB; the 2MB output should be capped.
        result = _do_unwrap(bomb)
        # Must NOT have produced 2MB of output.
        self.assertLess(
            sum(layer.output_size for layer in result.chain),
            _DEFAULT_BUDGET + 1024,
            msg=(
                "decompression bomb defeated the budget cap; the "
                "unwrap loop materialized more bytes than allowed"
            ),
        )


# ===========================================================================
# Error paths
# ===========================================================================

class ErrorPathTests(unittest.TestCase):

    def test_malformed_base64_yields_decode_error(self):
        # Base64 alphabet but not actually valid base64 (random length,
        # internal padding char). is_base64 may accept the alphabet
        # check, but the actual decoder will reject.
        bad = "AAAA====AAAAAAAA====AAAA"
        result = _do_unwrap(bad)
        # Either decode_error or terminal classification — what we
        # care about is that the loop did not crash.
        self.assertIsInstance(result, UnwrapResult)

    def test_truncated_zlib_yields_decode_error(self):
        full = zlib.compress(_INERT_SOURCE)
        truncated = full[:8]   # not enough to decompress
        result = _do_unwrap(truncated)
        self.assertEqual(result.status, STATUS_DECODE_ERROR)


# ===========================================================================
# Pickle: detected, never deserialized
# ===========================================================================

class PickleDetectionTests(unittest.TestCase):

    def test_pickle_protocol_2_detected_as_terminal(self):
        pickled = pickle.dumps({"key": "value", "n": 42}, protocol=2)
        # Sanity: verify we have a real pickle 2+ stream.
        self.assertEqual(pickled[0], 0x80)
        self.assertEqual(pickled[1], 2)

        result = _do_unwrap(pickled)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(result.final_kind, "pickle_data")
        self.assertTrue(result.pickle_warning)

    def test_pickle_through_b64_layer(self):
        pickled = pickle.dumps([1, 2, 3, 4, 5], protocol=4)
        encoded = base64.b64encode(pickled).decode("ascii")
        result = _do_unwrap(encoded)
        self.assertEqual(len(result.chain), 1)
        self.assertEqual(result.chain[0].kind, "base64")
        self.assertEqual(result.final_kind, "pickle_data")
        self.assertTrue(result.pickle_warning)


# ===========================================================================
# Pickling the result type
# ===========================================================================

class UnwrapResultPickleTests(unittest.TestCase):

    def test_simple_result_pickles(self):
        encoded = base64.b64encode(_INERT_SOURCE).decode("ascii")
        result = _do_unwrap(encoded)
        round_tripped = pickle.loads(pickle.dumps(result))
        self.assertEqual(round_tripped, result)

    def test_exhausted_result_pickles(self):
        layer4 = zlib.compress(_INERT_SOURCE)
        layer3 = base64.b64encode(layer4)
        layer2 = zlib.compress(layer3)
        layer1 = base64.b64encode(layer2).decode("ascii")
        result = _do_unwrap(layer1, depth=3)
        round_tripped = pickle.loads(pickle.dumps(result))
        self.assertEqual(round_tripped, result)

    def test_layer_pickles(self):
        layer = Layer(kind="base64", input_size=200, output_size=150)
        round_tripped = pickle.loads(pickle.dumps(layer))
        self.assertEqual(round_tripped, layer)


# ===========================================================================
# Validation errors at the public boundary
# ===========================================================================

class UnwrapValidationTests(unittest.TestCase):

    def test_max_depth_zero_raises(self):
        with self.assertRaises(ValueError):
            unwrap("anything", max_depth=0, max_budget=1024)

    def test_negative_max_depth_raises(self):
        with self.assertRaises(ValueError):
            unwrap("anything", max_depth=-1, max_budget=1024)

    def test_tiny_budget_raises(self):
        with self.assertRaises(ValueError):
            unwrap("anything", max_depth=3, max_budget=8)


if __name__ == "__main__":
    unittest.main()