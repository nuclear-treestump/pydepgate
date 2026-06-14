"""IOC mode regression tests for decoded payload extraction."""

from __future__ import annotations

import unittest

from pydepgate.enrichers.decode_payloads import _extract_iocs


class DecodePayloadIocModeTests(unittest.TestCase):
    def test_hash_mode_does_not_keep_decoded_source(self):
        ioc = _extract_iocs(
            "encoded",
            b"print('decoded source')\n",
            "python_source",
            include_decoded_source=False,
        )
        self.assertIsNone(ioc.decoded_source)
        self.assertIsNotNone(ioc.original_sha256)
        self.assertIsNotNone(ioc.decoded_sha256)

    def test_full_mode_keeps_decoded_source_for_python_source(self):
        ioc = _extract_iocs(
            "encoded",
            b"print('decoded source')\n",
            "python_source",
            include_decoded_source=True,
        )
        self.assertEqual(ioc.decoded_source, "print('decoded source')\n")

    def test_full_mode_does_not_force_source_for_non_python_terminal(self):
        ioc = _extract_iocs(
            b"encoded",
            b"\x00\x01\x02",
            "binary_unknown",
            include_decoded_source=True,
        )
        self.assertIsNone(ioc.decoded_source)


if __name__ == "__main__":
    unittest.main()
