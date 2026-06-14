"""Tests for pydepgate.api.

These tests lock down the public API boundary added for the contextless scan
facade. The important security invariant is that normal API use may expose
metadata, hash IOCs, and bounded payload previews, but must not expose full
payload strings, decoded source, or native scanner internals unless an explicit
UNSAFE token is supplied.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
import unittest

import pydepgate.api as api

ROOT = Path(__file__).resolve().parents[2]
OBFUSCATED_SETUP = ROOT / "test_files" / "obfuscated_setup.py"

FORBIDDEN_PAYLOAD_KEYS = {
    "_full_value",
    "_full_value_truncated",
    "decoded_source",
    "raw_payload",
    "der_full",
}
FORBIDDEN_TEXT_MARKERS = (
    "_full_value",
    "_full_value_truncated",
    "decoded_source='",
    '"decoded_source"',
    "raw_payload",
)


def _walk(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _walk(item)


class ApiValidationTests(unittest.TestCase):
    """Validate public API request guardrails."""

    def test_single_true_is_blocked_for_archive_targets(self):
        archive_targets = (
            "bad.whl",
            "BAD.WHL",
            "bad.zip",
            "bad.tar",
            "bad.tar.gz",
            "bad.tgz",
            "bad.tar.bz2",
            "bad.tar.xz",
        )
        for target in archive_targets:
            with self.subTest(target=target):
                with self.assertRaises(api.PyDepGateApiError):
                    api.scan(target, single=True)

    def test_invalid_mode_is_rejected(self):
        with self.assertRaisesRegex(api.PyDepGateApiError, "mode='static'"):
            api.scan(str(OBFUSCATED_SETUP), mode="dynamic")

    def test_url_targets_are_rejected_until_intake_exists(self):
        with self.assertRaisesRegex(api.PyDepGateApiError, "URL targets"):
            api.scan("https://example.invalid/package.whl")

    def test_decode_iocs_requires_known_mode(self):
        with self.assertRaisesRegex(api.PyDepGateApiError, "decode_iocs"):
            api.scan(str(OBFUSCATED_SETUP), single=True, decode=True, decode_iocs="yes")

    def test_decode_iocs_requires_decode_enabled(self):
        with self.assertRaisesRegex(api.PyDepGateApiError, "decode=True"):
            api.scan(str(OBFUSCATED_SETUP), single=True, decode_iocs="hashes")

    def test_single_and_deep_are_rejected_together(self):
        with self.assertRaisesRegex(api.PyDepGateApiError, "single=True and deep=True"):
            api.scan(str(OBFUSCATED_SETUP), single=True, deep=True)

    def test_as_kind_requires_single_mode(self):
        with self.assertRaisesRegex(api.PyDepGateApiError, "as_kind"):
            api.scan(str(OBFUSCATED_SETUP), as_kind="setup_py")

    def test_output_format_validation_and_human_alias(self):
        self.assertEqual(api._normalize_output_format("human"), "text")
        self.assertEqual(api._normalize_output_format(" text "), "text")
        self.assertEqual(api._normalize_output_format("json"), "json")
        self.assertEqual(api._normalize_output_format("sarif"), "sarif")
        with self.assertRaises(api.PyDepGateApiError):
            api._normalize_output_format("xml")


class ApiSafeFindingTests(unittest.TestCase):
    """Unit tests for safe finding context sanitization."""

    def test_sanitize_mapping_preserves_bounded_decoded_preview(self):
        context = {
            "length": 34460,
            "_full_value": "very-large-payload",
            "_private": "secret",
            "value_preview": "handled as normal non-secret field",
            "decoded": {
                "chain": ["base64"],
                "layers_count": 1,
                "final_kind": "python_source",
                "final_bytes_size": 25844,
                "unwrap_status": "completed",
                "preview_hex": "696d706f7274",
                "preview_text": "import subprocess",
                "preview_truncated": True,
                "indicators": ["subprocess"],
                "pickle_warning": False,
                "decoded_source": "full decoded source must not leak",
                "raw_payload": "raw bytes must not leak",
                "unknown_future_field": "not safe until explicitly allowed",
            },
        }

        clean = api._sanitize_mapping(context)

        self.assertNotIn("_full_value", clean)
        self.assertNotIn("_private", clean)
        self.assertIn("decoded", clean)
        self.assertEqual(clean["decoded"]["preview_text"], "import subprocess")
        self.assertEqual(clean["decoded"]["preview_hex"], "696d706f7274")
        self.assertNotIn("decoded_source", clean["decoded"])
        self.assertNotIn("raw_payload", clean["decoded"])
        self.assertNotIn("unknown_future_field", clean["decoded"])

    def test_sanitize_mapping_removes_nested_private_keys(self):
        clean = api._sanitize_mapping(
            {
                "outer": {
                    "ok": True,
                    "_full_value": "nested payload",
                    "items": [{"_secret": "x", "safe": "y"}],
                }
            }
        )
        self.assertEqual(clean["outer"]["ok"], True)
        self.assertNotIn("_full_value", clean["outer"])
        self.assertNotIn("_secret", clean["outer"]["items"][0])
        self.assertEqual(clean["outer"]["items"][0]["safe"], "y")


class ApiScanResultTests(unittest.TestCase):
    """Exercise the public API against a small known-bad fixture."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir_obj = tempfile.TemporaryDirectory()
        cls.tmpdir = Path(cls.tmpdir_obj.name)
        cls.event_log = cls.tmpdir / "events.jsonl"
        cls.result = api.scan(
            str(OBFUSCATED_SETUP),
            mode="static",
            single=True,
            peek=True,
            peek_chain=True,
            decode=True,
            decode_payload_depth=3,
            decode_iocs="hashes",
            min_severity="high",
            output_format="text",
            event_log=cls.event_log,
        )

    @classmethod
    def tearDownClass(cls):
        cls.tmpdir_obj.cleanup()

    def test_repr_is_compact_and_does_not_dump_native_objects(self):
        text = repr(self.result)
        self.assertIn("ScanApiResult", text)
        self.assertIn("finding_count=", text)
        self.assertIn("ioc_count=", text)
        self.assertNotIn("ScanResult(", text)
        self.assertNotIn("StaticScanOutcome(", text)
        self.assertNotIn("_full_value", text)
        self.assertLess(len(text), 600)

    def test_summary_contains_expected_public_fields(self):
        summary = self.result.to_summary()
        for key in (
            "mode",
            "target",
            "artifact_identity",
            "artifact_kind",
            "finding_count",
            "diagnostic_count",
            "ioc_count",
            "event_count",
            "ruleset_fingerprint",
            "decode_iocs",
            "statistics",
        ):
            self.assertIn(key, summary)
        self.assertEqual(summary["artifact_kind"], "loose_file")
        self.assertEqual(summary["decode_iocs"], "hashes")
        self.assertGreaterEqual(summary["finding_count"], 1)

    def test_public_internals_are_blocked(self):
        for attr_name in ("result", "outcome", "decoded_tree"):
            with self.subTest(attr_name=attr_name):
                with self.assertRaises(api.PyDepGateApiError):
                    getattr(self.result, attr_name)

    def test_unsafe_getters_require_exact_tokens(self):
        with self.assertRaises(api.PyDepGateApiError):
            self.result.get_native_result(unsafe=True)
        with self.assertRaises(api.PyDepGateApiError):
            self.result.get_decoded_tree(unsafe=api.UNSAFE.ALLOW_NATIVE_RESULT)

        native = self.result.get_native_result(unsafe=api.UNSAFE.ALLOW_NATIVE_RESULT)
        tree = self.result.get_decoded_tree(unsafe=api.UNSAFE.ALLOW_DECODED_TREE)
        self.assertIsNotNone(native)
        self.assertIsNotNone(tree)

    def test_hashes_mode_decoded_tree_does_not_retain_decoded_source(self):
        tree = self.result.get_decoded_tree(unsafe=api.UNSAFE.ALLOW_DECODED_TREE)
        self.assertNotIn("decoded_source='", repr(tree))

    def test_safe_findings_do_not_contain_full_payload_material(self):
        self.assertGreaterEqual(len(self.result.findings), 1)
        for finding in self.result.findings:
            as_dict = finding.to_dict()
            for key, _ in _walk(as_dict):
                self.assertNotIn(key, FORBIDDEN_PAYLOAD_KEYS)
            text = json.dumps(as_dict, sort_keys=True)
            for marker in FORBIDDEN_TEXT_MARKERS:
                self.assertNotIn(marker, text)

    def test_iocs_are_hash_only_public_records(self):
        self.assertGreaterEqual(len(self.result.iocs), 1)
        for ioc in self.result.iocs:
            record = ioc.to_dict()
            self.assertIn("decoded_sha256", record)
            self.assertIn("decoded_sha512", record)
            self.assertNotIn("decoded_source", record)
            self.assertNotIn("raw_payload", record)

    def test_event_log_contains_ordered_lifecycle_and_decode_summary(self):
        rows = [
            json.loads(line)
            for line in self.event_log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        event_types = [row["event_type"] for row in rows]
        required = [
            "internal.scanner.scan_grant_issued",
            "internal.scanner.engine_created",
            "internal.scanner.scan_started",
            "internal.scanner.scan_completed",
            "internal.scanner.decode_started",
            "internal.scanner.decode_completed",
            "internal.scanner.run_completed",
        ]
        self.assertEqual(
            [event_types.index(item) for item in required],
            sorted(event_types.index(item) for item in required),
        )

        scan_completed = next(
            row
            for row in rows
            if row["event_type"] == "internal.scanner.scan_completed"
        )
        self.assertEqual(
            scan_completed["payload"]["finding_count"],
            self.result.finding_count,
        )

        decode_completed = next(
            row
            for row in rows
            if row["event_type"] == "internal.scanner.decode_completed"
        )
        self.assertIn("ioc_count", decode_completed["payload"])
        self.assertEqual(decode_completed["payload"]["decode_iocs"], "hashes")

    def test_renderers_parse_and_do_not_leak_full_payload_material(self):
        text_report = self.result.render(format="human")
        json_report = self.result.render(format="json")
        sarif_report = self.result.render(format="sarif")

        self.assertIn("findings", json_report)
        self.assertIn("version", sarif_report)
        json.loads(json_report)
        sarif_doc = json.loads(sarif_report)
        self.assertEqual(sarif_doc["version"], "2.1.0")
        self.assertIsInstance(text_report, str)

        for name, report_text in (
            ("json", json_report),
            ("sarif", sarif_report),
        ):
            with self.subTest(format=name):
                for marker in FORBIDDEN_TEXT_MARKERS:
                    self.assertNotIn(marker, report_text)

    def test_write_report_and_iocs_create_files(self):
        out_dir = self.tmpdir / "reports"
        text_path = self.result.write_report(out_dir / "report.txt", format="text")
        json_path = self.result.write_report(out_dir / "report.json", format="json")
        sarif_path = self.result.write_report(
            out_dir / "report.sarif.json", format="sarif"
        )
        iocs_path = self.result.write_iocs(out_dir / "iocs.txt")

        for path in (text_path, json_path, sarif_path, iocs_path):
            self.assertTrue(path.exists())
            self.assertGreater(path.stat().st_size, 0)

    def test_payload_archive_export_is_blocked_in_hashes_mode(self):
        with self.assertRaises(api.PyDepGateApiError):
            self.result.write_payload_archive(
                self.tmpdir / "payloads.zip",
                unsafe=api.UNSAFE.ALLOW_PAYLOAD_ARCHIVE_EXPORT,
            )


class ApiFullModeTests(unittest.TestCase):
    """Full mode is the only mode that may produce payload archives."""

    def test_full_mode_required_for_payload_archive_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            result = api.scan(
                str(OBFUSCATED_SETUP),
                mode="static",
                single=True,
                peek=True,
                decode=True,
                decode_payload_depth=2,
                decode_iocs="full",
            )
            with self.assertRaises(api.PyDepGateApiError):
                result.write_payload_archive(tmpdir / "bad.zip", unsafe=True)

            archive = result.write_payload_archive(
                tmpdir / "payloads.zip",
                unsafe=api.UNSAFE.ALLOW_PAYLOAD_ARCHIVE_EXPORT,
            )
            self.assertTrue(archive.exists())
            self.assertGreater(archive.stat().st_size, 0)
            sidecar = archive.with_suffix(archive.suffix + ".iocs.txt")
            self.assertTrue(sidecar.exists())
            self.assertGreater(sidecar.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
