"""Tests for event envelopes."""

from __future__ import annotations

import json
import unittest
from types import MappingProxyType

from pydepgate.events.envelope import EventEnvelope, EventEnvelopeError
from pydepgate.events.freeze import FrozenMapping


class TestEventEnvelopeBasics(unittest.TestCase):
    def test_envelope_builds_required_fields(self):
        event = EventEnvelope(
            event_type="internal.scanner.scan_started",
            producer="pydepgate.tests",
            payload={"target_kind": "wheel"},
        )

        self.assertEqual(event.schema_version, 1)
        self.assertTrue(event.event_id)
        self.assertTrue(event.run_id)
        self.assertEqual(event.correlation_id, event.run_id)
        self.assertEqual(event.severity, "info")
        self.assertEqual(event.payload["target_kind"], "wheel")
        self.assertEqual(len(event.payload_digest), 64)

    def test_payload_is_frozen_and_detached(self):
        source = {"items": ["alpha"], "nested": {"count": 1}}
        event = EventEnvelope(
            event_type="internal.scanner.scan_completed",
            producer="pydepgate.tests",
            payload=source,
        )

        source["items"].append("bravo")
        source["nested"]["count"] = 99
        source["added"] = True

        self.assertIsInstance(event.payload, FrozenMapping)
        self.assertEqual(event.payload["items"], ("alpha",))
        self.assertEqual(event.payload["nested"]["count"], 1)
        self.assertNotIn("added", event.payload)
        with self.assertRaises(TypeError):
            event.payload["new"] = True

    def test_mapping_proxy_payload_is_detached(self):
        source = {"nested": {"value": "original"}}
        event = EventEnvelope(
            event_type="internal.policy.policy_applied",
            producer="pydepgate.tests",
            payload=MappingProxyType(source),
        )

        source["nested"]["value"] = "changed"

        self.assertEqual(event.payload["nested"]["value"], "original")

    def test_to_dict_is_json_compatible(self):
        event = EventEnvelope(
            event_type="external.feed.package_observed",
            producer="pydepgate.tests",
            payload={"tags": {"beta", "alpha"}, "count": 2},
            ticket_id="sgt_test",
            parent_event_id="parent-test",
            payload_schema="pydepgate.test.schema.v1",
            severity="warning",
        )

        output = event.to_dict()
        self.assertEqual(output["ticket_id"], "sgt_test")
        self.assertEqual(output["payload"]["tags"], ["alpha", "beta"])
        json.dumps(output, sort_keys=True)

    def test_to_json_is_stable(self):
        event = EventEnvelope(
            event_type="internal.scanner.scan_completed",
            producer="pydepgate.tests",
            payload={"b": 2, "a": 1},
        )

        first = event.to_json()
        second = event.to_json()

        self.assertEqual(first, second)
        decoded = json.loads(first)
        self.assertEqual(decoded["payload"], {"a": 1, "b": 2})


class TestEventEnvelopeValidation(unittest.TestCase):
    def test_event_type_requires_known_prefix(self):
        with self.assertRaises(EventEnvelopeError):
            EventEnvelope(
                event_type="scanner.scan_started",
                producer="pydepgate.tests",
                payload={},
            )

    def test_event_type_requires_non_empty_string(self):
        with self.assertRaises(EventEnvelopeError):
            EventEnvelope(event_type="", producer="pydepgate.tests", payload={})

    def test_producer_requires_non_empty_string(self):
        with self.assertRaises(EventEnvelopeError):
            EventEnvelope(
                event_type="internal.scanner.scan_started",
                producer=" ",
                payload={},
            )

    def test_payload_must_be_mapping(self):
        with self.assertRaises(EventEnvelopeError):
            EventEnvelope(
                event_type="internal.scanner.scan_started",
                producer="pydepgate.tests",
                payload=["not", "a", "mapping"],
            )

    def test_payload_keys_must_be_json_strings(self):
        with self.assertRaises(EventEnvelopeError):
            EventEnvelope(
                event_type="internal.scanner.scan_started",
                producer="pydepgate.tests",
                payload={1: "not-json-key"},
            )

    def test_payload_rejects_bytes(self):
        with self.assertRaises(EventEnvelopeError):
            EventEnvelope(
                event_type="internal.scanner.scan_started",
                producer="pydepgate.tests",
                payload={"blob": b"abc"},
            )

    def test_severity_must_be_supported(self):
        with self.assertRaises(EventEnvelopeError):
            EventEnvelope(
                event_type="internal.scanner.scan_started",
                producer="pydepgate.tests",
                payload={},
                severity="loud",
            )


if __name__ == "__main__":
    unittest.main()
