"""Adversarial tests for the event subsystem.

These tests treat event payloads, sinks, and JSONL output as hostile surfaces.
The important invariant is that event records remain immutable, JSON-safe,
deterministic, and fail closed before untrusted payload material reaches sinks.
"""

from __future__ import annotations

import json
import math
import tempfile
from pathlib import Path
import unittest

from pydepgate.events import (
    EventEmitter,
    EventEnvelope,
    EventEnvelopeError,
    EventSinkError,
    JsonlEventSink,
    MemoryEventSink,
    TeeEventSink,
)


class MutatingSink:
    """Sink that tries to mutate an event after it has been emitted."""

    def write(self, event):
        event.payload["attacker"] = "modified"


class RuntimeBrokenSink:
    """Sink that raises a non-EventSinkError exception."""

    def write(self, event):
        raise RuntimeError("sink exploded")


class EventEnvelopeAdversarialTests(unittest.TestCase):
    def test_rejects_bytes_like_payloads_before_json_output(self):
        payloads = (
            {"raw": b"payload bytes"},
            {"raw": bytearray(b"payload bytes")},
            {"raw": memoryview(b"payload bytes")},
        )

        for payload in payloads:
            with self.subTest(payload_type=type(payload["raw"]).__name__):
                with self.assertRaises(EventEnvelopeError):
                    EventEnvelope(
                        event_type="internal.scanner.scan_completed",
                        producer="pydepgate.tests",
                        payload=payload,
                    )

    def test_rejects_non_finite_floats(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                with self.assertRaises(EventEnvelopeError):
                    EventEnvelope(
                        event_type="internal.scanner.scan_completed",
                        producer="pydepgate.tests",
                        payload={"duration_seconds": value},
                    )

    def test_rejects_non_string_mapping_keys(self):
        with self.assertRaises(EventEnvelopeError):
            EventEnvelope(
                event_type="internal.scanner.scan_completed",
                producer="pydepgate.tests",
                payload={"ok": True, 1: "integer key"},
            )

    def test_rejects_cycles_in_payload(self):
        payload = {"items": []}
        payload["items"].append(payload)

        with self.assertRaises(EventEnvelopeError):
            EventEnvelope(
                event_type="internal.scanner.scan_completed",
                producer="pydepgate.tests",
                payload=payload,
            )

    def test_payload_digest_is_stable_across_mapping_order(self):
        first = EventEnvelope(
            event_type="internal.scanner.scan_completed",
            producer="pydepgate.tests",
            payload={"b": 2, "a": 1, "nested": {"y": True, "x": False}},
        )
        second = EventEnvelope(
            event_type="internal.scanner.scan_completed",
            producer="pydepgate.tests",
            payload={"nested": {"x": False, "y": True}, "a": 1, "b": 2},
        )

        self.assertEqual(first.payload_digest, second.payload_digest)

    def test_sets_are_serialized_deterministically(self):
        event = EventEnvelope(
            event_type="internal.scanner.scan_completed",
            producer="pydepgate.tests",
            payload={"signals": {"DYN001", "ENC001", "DENS010"}},
        )

        payload = event.to_dict()["payload"]
        self.assertEqual(payload["signals"], ["DENS010", "DYN001", "ENC001"])

    def test_event_payload_is_detached_from_caller_mutation(self):
        payload = {"nested": {"values": ["one"]}}
        event = EventEnvelope(
            event_type="internal.scanner.scan_completed",
            producer="pydepgate.tests",
            payload=payload,
        )

        payload["nested"]["values"].append("two")
        payload["nested"]["new"] = "attacker"

        self.assertEqual(event.payload["nested"]["values"], ("one",))
        self.assertNotIn("new", event.payload["nested"])

    def test_event_payload_rejects_direct_mutation(self):
        event = EventEnvelope(
            event_type="internal.scanner.scan_completed",
            producer="pydepgate.tests",
            payload={"nested": {"values": ["one"]}},
        )

        with self.assertRaises(TypeError):
            event.payload["new"] = "blocked"
        with self.assertRaises(TypeError):
            event.payload["nested"]["new"] = "blocked"
        with self.assertRaises(AttributeError):
            event.payload["nested"]["values"].append("blocked")


class EventEmitterAndSinkAdversarialTests(unittest.TestCase):
    def test_invalid_payload_does_not_write_partial_jsonl_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            emitter = EventEmitter(
                producer="pydepgate.tests",
                sinks=(JsonlEventSink(path),),
            )

            with self.assertRaises(EventEnvelopeError):
                emitter.emit("internal.scanner.scan_completed", {"raw": b"payload"})

            self.assertFalse(path.exists())

    def test_mutating_sink_cannot_modify_event(self):
        memory = MemoryEventSink()
        emitter = EventEmitter(
            producer="pydepgate.tests",
            sinks=(memory, MutatingSink()),
        )

        with self.assertRaises(EventSinkError):
            emitter.emit("internal.scanner.scan_completed", {"ok": True})

        self.assertEqual(len(memory.events), 1)
        self.assertEqual(memory.events[0].payload["ok"], True)
        self.assertNotIn("attacker", memory.events[0].payload)

    def test_runtime_sink_exception_is_wrapped_with_sink_index(self):
        emitter = EventEmitter(
            producer="pydepgate.tests",
            sinks=(MemoryEventSink(), RuntimeBrokenSink()),
        )

        with self.assertRaisesRegex(EventSinkError, "sink 1 failed"):
            emitter.emit("internal.scanner.scan_started", {"target_kind": "wheel"})

    def test_tee_runtime_child_exception_is_wrapped_with_child_index(self):
        tee = TeeEventSink((MemoryEventSink(), RuntimeBrokenSink()))
        event = EventEnvelope(
            event_type="internal.scanner.scan_started",
            producer="pydepgate.tests",
            payload={"target_kind": "wheel"},
        )

        with self.assertRaisesRegex(EventSinkError, "child sink 1 failed"):
            tee.write(event)

    def test_jsonl_output_is_one_json_object_per_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            sink = JsonlEventSink(path)
            for index in range(3):
                sink.write(
                    EventEnvelope(
                        event_type="internal.scanner.scan_completed",
                        producer="pydepgate.tests",
                        payload={"index": index},
                    )
                )

            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 3)
            for line in lines:
                row = json.loads(line)
                self.assertIn("event_id", row)
                self.assertIn("payload_digest", row)
                self.assertIsInstance(row["payload"], dict)


if __name__ == "__main__":
    unittest.main()
