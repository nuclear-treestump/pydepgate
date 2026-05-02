"""
Tests for PR B: PEM transform plus DER classification integration.

Three scopes covered in one file because the additions touch three
modules and an integration-shape test is the most useful ground
truth for whether the wiring is right.

  Scope 1 (unit, _magic.py additions):
    - is_pem positive and negative cases
    - FormatDetection.details populated when binary_unknown looks
      like DER
    - _detect_str routes PEM ahead of base64 (priority order)

  Scope 2 (unit, _unwrap.py additions):
    - _decode_pem strips armor and base64-decodes the body
    - PEM transform integrates as a Layer in the chain
    - UnwrapResult.details surfaces the terminal DER classification

Cert fixture is regenerated with cryptography (forward-only,
matching PR A's pattern) and embedded as hex below. The PEM form
of the same cert is also embedded so PEM-armor parsing is tested
against real PEM rather than hand-crafted bytes.
"""

from __future__ import annotations

import base64
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
from pydepgate.enrichers._asn1 import (
    DERClassification,
    FormatContext,
    classify,
    looks_like_der,
)
from pydepgate.enrichers._magic import (
    FormatDetection,
    detect_format,
    is_pem,
)
from pydepgate.enrichers._unwrap import (
    Layer,
    STATUS_COMPLETED,
    STATUS_DECODE_ERROR,
    UnwrapResult,
    unwrap,
)
from pydepgate.enrichers.payload_peek import (
    DEFAULT_MAX_BUDGET,
    DEFAULT_MAX_DEPTH,
    MIN_LENGTH_FLOOR,
    PayloadPeek,
)
from pydepgate.parsers.pysource import SourceLocation


# ---------------------------------------------------------------------------
# Cert fixtures (regenerated with cryptography; see test docstring).
# ---------------------------------------------------------------------------

# Same cert content in both forms: a self-signed RSA-2048 cert with
# CN=pem.example.com, O=PEM Test Org, serial 54321, validity 2025-2026.
# CERT_PEM_DER is what we expect to see after PEM transform decode.
CERT_PEM_DER = bytes.fromhex(
    "308202dd308201c5a003020102020300d431300d06092a864886f70d01010b05"
    "0030313118301606035504030c0f70656d2e6578616d706c652e636f6d311530"
    "13060355040a0c0c50454d2054657374204f7267301e170d3235303130313030"
    "303030305a170d3236303130313030303030305a30313118301606035504030c"
    "0f70656d2e6578616d706c652e636f6d31153013060355040a0c0c50454d2054"
    "657374204f726730820122300d06092a864886f70d01010105000382010f0030"
    "82010a0282010100ce2ff818f8f8596f560de6fed1ad5aa8aabae90f742c97cf"
    "e80f4e0d08505ee5a26f770834e708a7d9b75e87e62989a4ab1de1fefdaa4f16"
    "199ba4af618abcbafdf32bec872cfe21cb7756ec869df35ae669e605dfd391a3"
    "45a5ef1580ee590abfb21e252266de4d42425653f479f194e2b72da680558ed4"
    "a87ec9ccb3d6fc792f5afdd9b29ab917697ff7d4f79f9a1b602ee444fa1d6a6a"
    "d611058829edc7e01c513eb637e990f44729f686d428ccc6cb776b051d7dca6e"
    "806e44ac7c646f9fa0d4504581c27000e64cbfb83f7ff5e1971c9c4e649769c7"
    "49395d4505ea79f82c1cc397213f62b592ac61e37ddf24518ef5291660737667"
    "6bb4bf6fe220eee90203010001300d06092a864886f70d01010b050003820101"
    "0018fd048fdc008a890ac1504fe85b2de0159385c2b16727eb7ee43c605e3768"
    "6513a1c4b6c3a151e17e061464428a00c99d9330722888b2c2944c7af296f36d"
    "9cc3f272eee6b06bf11129e4834824d01cd6649965b326bcac642c11604e7e01"
    "d4a0127f185c64ace8d06926ff777ee649d24aed094e833d690b23441def2d65"
    "b5f09b23043f6ed47732e0f77b92b9b7b54bf557ecfd481481466bba45fbcc15"
    "14ba1fc5ddf93629db72c5d2fcf76d576fd8f627c354bd3ca4313bd99df266d6"
    "d3d1b09adf95651928e2ed4f4ecd300f4c1d4c8b24a2f7b0b6c41972c87f9569"
    "fa59f8e3d2fb24b68dc99026df59d4b48a7d5f1bd568c796410be0f0838a724d"
    "5d"
)

CERT_PEM_TEXT = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC3TCCAcWgAwIBAgIDANQxMA0GCSqGSIb3DQEBCwUAMDExGDAWBgNVBAMMD3Bl\n"
    "bS5leGFtcGxlLmNvbTEVMBMGA1UECgwMUEVNIFRlc3QgT3JnMB4XDTI1MDEwMTAw\n"
    "MDAwMFoXDTI2MDEwMTAwMDAwMFowMTEYMBYGA1UEAwwPcGVtLmV4YW1wbGUuY29t\n"
    "MRUwEwYDVQQKDAxQRU0gVGVzdCBPcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n"
    "ggEKAoIBAQDOL/gY+PhZb1YN5v7RrVqoqrrpD3Qsl8/oD04NCFBe5aJvdwg05win\n"
    "2bdeh+YpiaSrHeH+/apPFhmbpK9hiry6/fMr7Ics/iHLd1bshp3zWuZp5gXf05Gj\n"
    "RaXvFYDuWQq/sh4lImbeTUJCVlP0efGU4rctpoBVjtSofsnMs9b8eS9a/dmymrkX\n"
    "aX/31PefmhtgLuRE+h1qatYRBYgp7cfgHFE+tjfpkPRHKfaG1CjMxst3awUdfcpu\n"
    "gG5ErHxkb5+g1FBFgcJwAOZMv7g/f/XhlxycTmSXacdJOV1FBep5+Cwcw5chP2K1\n"
    "kqxh433fJFGO9SkWYHN2Z2u0v2/iIO7pAgMBAAEwDQYJKoZIhvcNAQELBQADggEB\n"
    "ABj9BI/cAIqJCsFQT+hbLeAVk4XCsWcn637kPGBeN2hlE6HEtsOhUeF+BhRkQooA\n"
    "yZ2TMHIoiLLClEx68pbzbZzD8nLu5rBr8REp5INIJNAc1mSZZbMmvKxkLBFgTn4B\n"
    "1KASfxhcZKzo0Gkm/3d+5knSSu0JToM9aQsjRB3vLWW18JsjBD9u1Hcy4Pd7krm3\n"
    "tUv1V+z9SBSBRmu6RfvMFRS6H8Xd+TYp23LF0vz3bVdv2PYnw1S9PKQxO9md8mbW\n"
    "09Gwmt+VZRko4u1PTs0wD0wdTIskovewtsQZcsh/lWn6Wfjj0vskto3JkCbfWdS0\n"
    "in1fG9Vox5ZBC+Dwg4pyTV0=\n"
    "-----END CERTIFICATE-----\n"
)


def _build_setup_py_with_literal(literal_value: str) -> bytes:
    """Build a setup.py with `literal_value` as a top-level constant.

    The literal is large enough to hit min_length thresholds in the
    payload_peek enricher. The wrapping `setup()` call is a stub
    that doesn't affect the analyzer.
    """
    quoted = repr(literal_value)
    src = (
        "from setuptools import setup\n"
        f"DATA = {quoted}\n"
        "setup(name='test')\n"
    )
    return src.encode("utf-8")


def _scan_one(content: bytes, peek: PayloadPeek):
    """Run the static engine on `content` with the given enricher."""
    ctx = ScanContext(
        artifact_kind=ArtifactKind.LOOSE_FILE,
        artifact_identity="setup.py",
        internal_path="setup.py",
        file_kind=None,
        triage_reason="test",
    )
    engine = StaticEngine(enrichers=(peek,))
    inp = FileScanInput(
        content=content,
        internal_path="setup.py",
        file_kind=None,
        context=ctx,
    )
    return list(engine._scan_one_file(inp).findings)


# ---------------------------------------------------------------------------
# Scope 1: _magic.py unit tests
# ---------------------------------------------------------------------------

class IsPemTests(unittest.TestCase):
    """is_pem positive and negative cases."""

    def test_certificate_armor_positive(self):
        self.assertTrue(is_pem(CERT_PEM_TEXT))

    def test_other_armor_labels_positive(self):
        for label in (
            "RSA PRIVATE KEY",
            "PUBLIC KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "PGP MESSAGE",
        ):
            with self.subTest(label=label):
                text = (
                    f"-----BEGIN {label}-----\n"
                    "AAAAB3NzaC1yc2EAAAADAQABAAABAQ==\n"
                    f"-----END {label}-----\n"
                )
                self.assertTrue(is_pem(text))

    def test_unmatched_begin_end_negative(self):
        # Mismatched label between BEGIN and END.
        text = (
            "-----BEGIN CERTIFICATE-----\n"
            "AAAA\n"
            "-----END PUBLIC KEY-----\n"
        )
        self.assertFalse(is_pem(text))

    def test_begin_only_no_end_negative(self):
        text = "-----BEGIN CERTIFICATE-----\nAAAA\n"
        self.assertFalse(is_pem(text))

    def test_no_armor_negative(self):
        self.assertFalse(is_pem("just some plain text"))

    def test_base64_alphabet_only_negative(self):
        # Pure base64 (no PEM markers) must not match is_pem.
        self.assertFalse(is_pem("SGVsbG8gd29ybGQh" * 10))

    def test_empty_negative(self):
        self.assertFalse(is_pem(""))


class DetectFormatPemPriorityTests(unittest.TestCase):
    """PEM detection runs ahead of base64 in _detect_str priority."""

    def test_pem_text_routes_to_pem_not_base64(self):
        det = detect_format(CERT_PEM_TEXT)
        self.assertEqual(det.kind, "pem")
        self.assertFalse(det.is_terminal)

    def test_pem_bytes_routes_to_pem_via_ascii_fallback(self):
        # Bytes-form PEM should also route to pem (via the
        # _ascii_decode_or_none fallback in _detect_bytes).
        det = detect_format(CERT_PEM_TEXT.encode("ascii"))
        self.assertEqual(det.kind, "pem")
        self.assertFalse(det.is_terminal)


class FormatDetectionDetailsTests(unittest.TestCase):
    """FormatDetection.details populated for binary_unknown DER inputs."""

    def test_der_cert_bytes_attaches_classification(self):
        det = detect_format(CERT_PEM_DER)
        self.assertEqual(det.kind, "binary_unknown")
        self.assertTrue(det.is_terminal)
        self.assertIsNotNone(det.details)
        self.assertIsInstance(det.details, DERClassification)
        self.assertIsInstance(det.details, FormatContext)
        self.assertEqual(det.details.kind, "x509_certificate")
        self.assertEqual(det.details.bit_size, 2048)

    def test_non_der_binary_has_no_details(self):
        # Truly opaque binary that doesn't start with 0x30.
        garbage = b"\xab\xcd\xef" * 100
        det = detect_format(garbage)
        self.assertEqual(det.kind, "binary_unknown")
        self.assertIsNone(det.details)

    def test_coincidental_sequence_byte_unknown_der(self):
        # First byte happens to be 0x30 but the rest is random;
        # classify() returns kind="unknown_der" but details still
        # populates so the consumer can see the anomalies.
        coincidence = b"\x30" + b"\xab" * 200
        det = detect_format(coincidence)
        self.assertEqual(det.kind, "binary_unknown")
        self.assertIsNotNone(det.details)
        # The walk produces "unknown_der" with anomalies recorded.
        self.assertEqual(det.details.kind, "unknown_der")

    def test_python_source_does_not_attach_details(self):
        # Sanity: details only attaches on the binary_unknown path,
        # not on python_source or any other terminal.
        det = detect_format("import os\ndef f():\n    return 1\n")
        self.assertEqual(det.kind, "python_source")
        self.assertIsNone(det.details)


# ---------------------------------------------------------------------------
# Scope 2: _unwrap.py unit tests
# ---------------------------------------------------------------------------

class PemTransformTests(unittest.TestCase):
    """PEM transform integrates as a Layer in the unwrap chain."""

    def test_pem_armored_cert_unwraps_to_der(self):
        result = unwrap(
            CERT_PEM_TEXT,
            max_depth=DEFAULT_MAX_DEPTH,
            max_budget=DEFAULT_MAX_BUDGET,
        )
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 1)
        self.assertEqual(result.chain[0].kind, "pem")
        # The output of the PEM layer is exactly the DER bytes.
        self.assertEqual(result.final_bytes, CERT_PEM_DER)

    def test_pem_terminal_classification_is_binary_unknown(self):
        # The DER bytes after PEM transform are binary_unknown at
        # the magic-byte level (no PE/ELF/PNG/zip/etc. match).
        result = unwrap(
            CERT_PEM_TEXT,
            max_depth=DEFAULT_MAX_DEPTH,
            max_budget=DEFAULT_MAX_BUDGET,
        )
        self.assertEqual(result.final_kind, "binary_unknown")

    def test_unwrap_result_details_is_der_classification(self):
        # The whole point of PR B: details flows through to the
        # UnwrapResult so consumers see the cert structure.
        result = unwrap(
            CERT_PEM_TEXT,
            max_depth=DEFAULT_MAX_DEPTH,
            max_budget=DEFAULT_MAX_BUDGET,
        )
        self.assertIsNotNone(result.details)
        self.assertIsInstance(result.details, DERClassification)
        self.assertEqual(result.details.kind, "x509_certificate")
        self.assertEqual(
            result.details.fields["cert_subject_cn"],
            "pem.example.com",
        )

    def test_base64_wrapped_pem_chain(self):
        # base64-encode the PEM text. Unwrap should chain
        # [base64 -> pem] and end at the DER bytes.
        wrapped = base64.b64encode(CERT_PEM_TEXT.encode("ascii"))
        result = unwrap(
            wrapped,
            max_depth=DEFAULT_MAX_DEPTH,
            max_budget=DEFAULT_MAX_BUDGET,
        )
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 2)
        self.assertEqual(result.chain[0].kind, "base64")
        self.assertEqual(result.chain[1].kind, "pem")
        self.assertEqual(result.final_bytes, CERT_PEM_DER)
        self.assertIsNotNone(result.details)
        self.assertEqual(result.details.kind, "x509_certificate")

    def test_zlib_wrapped_pem_chain(self):
        # zlib-compressed PEM; unwrap chain is [zlib -> pem].
        compressed = zlib.compress(CERT_PEM_TEXT.encode("ascii"))
        result = unwrap(
            compressed,
            max_depth=DEFAULT_MAX_DEPTH,
            max_budget=DEFAULT_MAX_BUDGET,
        )
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 2)
        self.assertEqual(result.chain[0].kind, "zlib")
        self.assertEqual(result.chain[1].kind, "pem")
        self.assertEqual(result.final_bytes, CERT_PEM_DER)

    def test_malformed_pem_decode_error(self):
        # BEGIN with no matching END after; transform should fail.
        # Note: is_pem will return False here so it routes as
        # ascii_text instead of erroring. We construct a case
        # where is_pem returns True but the body is garbage.
        text = (
            "-----BEGIN CERTIFICATE-----\n"
            "@@@not-base64@@@\n"
            "-----END CERTIFICATE-----\n"
        )
        result = unwrap(
            text,
            max_depth=DEFAULT_MAX_DEPTH,
            max_budget=DEFAULT_MAX_BUDGET,
        )
        self.assertEqual(result.status, STATUS_DECODE_ERROR)


class BareDerInputTests(unittest.TestCase):
    """A bare DER blob with no encoding wrapper still surfaces details."""

    def test_bare_der_has_empty_chain_but_details_set(self):
        # No transforms run: input is already "terminal" at
        # binary_unknown. But details should still be populated.
        result = unwrap(
            CERT_PEM_DER,
            max_depth=DEFAULT_MAX_DEPTH,
            max_budget=DEFAULT_MAX_BUDGET,
        )
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertEqual(len(result.chain), 0)
        self.assertEqual(result.final_kind, "binary_unknown")
        self.assertIsNotNone(result.details)
        self.assertEqual(result.details.kind, "x509_certificate")


if __name__ == "__main__":
    unittest.main()