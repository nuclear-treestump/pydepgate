"""Tests for event emitters."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
import unittest

from pydepgate.events import EventEmitter
from pydepgate.events.emitter import EventEmitterError
from pydepgate.events.envelope import EventEnvelope, EventEnvelopeError
from pydepgate.events.sinks import EventSinkError, JsonlEventSink, MemoryEventSink


class BrokenSink:
    def write(self, event):
        raise RuntimeError("boom")


class TestEventEmitterBasics(unittest.TestCase):
    def test_emitter_returns_event_without_sinks(self):
        emitter = EventEmitter(
            producer="pydepgate.tests",
            run_id="run-test",
            correlation_id="corr-test",
        )

        event = emitter.emit(
            "internal.scanner.scan_started",
            {"target_kind": "wheel"},
            ticket_id="sgt_test",
        )

        self.assertIsInstance(event, EventEnvelope)
        self.assertEqual(event.producer, "pydepgate.tests")
        self.assertEqual(event.run_id, "run-test")
        self.assertEqual(event.correlation_id, "corr-test")
        self.assertEqual(event.ticket_id, "sgt_test")
        self.assertEqual(event.payload["target_kind"], "wheel")

    def test_emitter_defaults_correlation_to_run_id(self):
        emitter = EventEmitter(producer="pydepgate.tests", run_id="run-test")

        event = emitter.emit("internal.scanner.scan_started")

        self.assertEqual(event.correlation_id, "run-test")
        self.assertEqual(event.payload, {})

    def test_emitter_writes_to_memory_sink(self):
        sink = MemoryEventSink()
        emitter = EventEmitter(producer="pydepgate.tests", sinks=(sink,))

        event = emitter.emit("internal.scanner.scan_completed", {"count": 3})

        self.assertEqual(sink.events, (event,))
        self.assertIs(sink.events[0], event)

    def test_emitter_writes_to_jsonl_sink(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            emitter = EventEmitter(
                producer="pydepgate.tests",
                sinks=(JsonlEventSink(path),),
            )

            event = emitter.emit("internal.scanner.scan_started", {"n": 1})

            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["event_id"], event.event_id)

    def test_emitter_uses_optional_envelope_fields(self):
        emitter = EventEmitter(producer="pydepgate.tests", run_id="run-test")

        event = emitter.emit(
            "internal.scanner.scan_completed",
            {"ok": True},
            severity="warning",
            parent_event_id="parent-test",
            ticket_id="sgt_test",
            payload_schema="pydepgate.test.v1",
            occurred_at="2026-01-01T00:00:00Z",
        )

        self.assertEqual(event.severity, "warning")
        self.assertEqual(event.parent_event_id, "parent-test")
        self.assertEqual(event.ticket_id, "sgt_test")
        self.assertEqual(event.payload_schema, "pydepgate.test.v1")
        self.assertEqual(event.occurred_at, "2026-01-01T00:00:00Z")

    def test_emitter_detaches_payload_through_envelope(self):
        sink = MemoryEventSink()
        emitter = EventEmitter(producer="pydepgate.tests", sinks=(sink,))
        payload = {"items": ["one"]}

        event = emitter.emit("internal.scanner.scan_started", payload)
        payload["items"].append("two")

        self.assertEqual(event.payload["items"], ("one",))
        self.assertEqual(sink.events[0].payload["items"], ("one",))


class TestEventEmitterValidation(unittest.TestCase):
    def test_emitter_rejects_empty_producer(self):
        with self.assertRaises(EventEmitterError):
            EventEmitter(producer=" ")

    def test_emitter_rejects_empty_run_id(self):
        with self.assertRaises(EventEmitterError):
            EventEmitter(producer="pydepgate.tests", run_id="")

    def test_emitter_rejects_bad_sink(self):
        with self.assertRaises(EventEmitterError):
            EventEmitter(producer="pydepgate.tests", sinks=(object(),))

    def test_emit_surfaces_envelope_validation_errors(self):
        emitter = EventEmitter(producer="pydepgate.tests")

        with self.assertRaises(EventEnvelopeError):
            emitter.emit("scanner.scan_started")

    def test_emit_reports_sink_failure(self):
        emitter = EventEmitter(producer="pydepgate.tests", sinks=(BrokenSink(),))

        with self.assertRaises(EventSinkError):
            emitter.emit("internal.scanner.scan_started")

    def test_configured_sinks_are_detached_from_source_sequence(self):
        sink = MemoryEventSink()
        source = [sink]
        emitter = EventEmitter(producer="pydepgate.tests", sinks=source)
        source.clear()

        event = emitter.emit("internal.scanner.scan_started")

        self.assertEqual(sink.events, (event,))
        self.assertEqual(emitter.configured_sinks, (sink,))


if __name__ == "__main__":
    unittest.main()
