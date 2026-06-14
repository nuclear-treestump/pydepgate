"""Tests for event sinks."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
import unittest

from pydepgate.events.envelope import EventEnvelope
from pydepgate.events.sinks import (
    EventSinkError,
    JsonlEventSink,
    MemoryEventSink,
    NullEventSink,
    TeeEventSink,
)


class BrokenSink:
    def write(self, event):
        raise RuntimeError("broken")


class TestMemoryEventSink(unittest.TestCase):
    def test_memory_sink_stores_events(self):
        sink = MemoryEventSink()
        event = EventEnvelope(
            event_type="internal.scanner.scan_started",
            producer="pydepgate.tests",
            payload={"target_kind": "wheel"},
        )

        sink.write(event)

        self.assertEqual(sink.events, (event,))
        self.assertIs(sink.events[0], event)

    def test_memory_sink_returns_tuple_not_mutable_list(self):
        sink = MemoryEventSink()
        event = EventEnvelope(
            event_type="internal.scanner.scan_completed",
            producer="pydepgate.tests",
            payload={},
        )

        sink.write(event)
        events = sink.events

        self.assertIsInstance(events, tuple)
        with self.assertRaises(AttributeError):
            events.append(event)

    def test_memory_sink_can_be_bounded(self):
        sink = MemoryEventSink(max_events=2)
        first = EventEnvelope(
            event_type="internal.scanner.scan_started",
            producer="pydepgate.tests",
            payload={"n": 1},
        )
        second = EventEnvelope(
            event_type="internal.scanner.scan_started",
            producer="pydepgate.tests",
            payload={"n": 2},
        )
        third = EventEnvelope(
            event_type="internal.scanner.scan_started",
            producer="pydepgate.tests",
            payload={"n": 3},
        )

        sink.write(first)
        sink.write(second)
        sink.write(third)

        self.assertEqual(sink.events, (second, third))

    def test_memory_sink_rejects_invalid_max_events(self):
        with self.assertRaises(EventSinkError):
            MemoryEventSink(max_events=0)

    def test_memory_sink_rejects_non_event(self):
        sink = MemoryEventSink()
        with self.assertRaises(EventSinkError):
            sink.write("not an event")

    def test_memory_sink_clear_removes_events(self):
        sink = MemoryEventSink()
        event = EventEnvelope(
            event_type="internal.scanner.scan_started",
            producer="pydepgate.tests",
            payload={},
        )
        sink.write(event)

        sink.clear()

        self.assertEqual(sink.events, ())


class TestJsonlEventSink(unittest.TestCase):
    def test_jsonl_sink_writes_one_event_per_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            sink = JsonlEventSink(path)
            first = EventEnvelope(
                event_type="internal.scanner.scan_started",
                producer="pydepgate.tests",
                payload={"n": 1},
            )
            second = EventEnvelope(
                event_type="internal.scanner.scan_completed",
                producer="pydepgate.tests",
                payload={"n": 2},
            )

            sink.write(first)
            sink.write(second)

            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0])["event_id"], first.event_id)
            self.assertEqual(json.loads(lines[1])["event_id"], second.event_id)

    def test_jsonl_sink_creates_parent_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "events.jsonl"
            sink = JsonlEventSink(path)
            event = EventEnvelope(
                event_type="internal.scanner.scan_started",
                producer="pydepgate.tests",
                payload={},
            )

            sink.write(event)

            self.assertTrue(path.exists())

    def test_jsonl_sink_truncates_on_first_write_when_append_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text("old\n", encoding="utf-8")
            sink = JsonlEventSink(path, append=False)
            first = EventEnvelope(
                event_type="internal.scanner.scan_started",
                producer="pydepgate.tests",
                payload={"n": 1},
            )
            second = EventEnvelope(
                event_type="internal.scanner.scan_completed",
                producer="pydepgate.tests",
                payload={"n": 2},
            )

            sink.write(first)
            sink.write(second)

            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertNotIn("old", lines)

    def test_jsonl_sink_rejects_non_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            sink = JsonlEventSink(Path(tmp) / "events.jsonl")
            with self.assertRaises(EventSinkError):
                sink.write(object())

    def test_jsonl_sink_reports_parent_creation_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            base_file = Path(tmp) / "not-a-dir"
            base_file.write_text("x", encoding="utf-8")
            sink = JsonlEventSink(base_file / "events.jsonl")
            event = EventEnvelope(
                event_type="internal.scanner.scan_started",
                producer="pydepgate.tests",
                payload={},
            )

            with self.assertRaises(EventSinkError):
                sink.write(event)


class TestTeeAndNullEventSink(unittest.TestCase):
    def test_tee_sink_writes_to_all_children(self):
        first_sink = MemoryEventSink()
        second_sink = MemoryEventSink()
        tee = TeeEventSink((first_sink, second_sink))
        event = EventEnvelope(
            event_type="internal.scanner.scan_completed",
            producer="pydepgate.tests",
            payload={"ok": True},
        )

        tee.write(event)

        self.assertEqual(first_sink.events, (event,))
        self.assertEqual(second_sink.events, (event,))

    def test_tee_sink_rejects_empty_children(self):
        with self.assertRaises(EventSinkError):
            TeeEventSink(())

    def test_tee_sink_rejects_non_sink_child(self):
        with self.assertRaises(EventSinkError):
            TeeEventSink((object(),))

    def test_tee_sink_reports_child_failure(self):
        good_sink = MemoryEventSink()
        tee = TeeEventSink((good_sink, BrokenSink()))
        event = EventEnvelope(
            event_type="internal.scanner.scan_started",
            producer="pydepgate.tests",
            payload={},
        )

        with self.assertRaises(EventSinkError):
            tee.write(event)
        self.assertEqual(good_sink.events, (event,))

    def test_null_sink_accepts_event(self):
        sink = NullEventSink()
        event = EventEnvelope(
            event_type="internal.scanner.scan_started",
            producer="pydepgate.tests",
            payload={},
        )

        sink.write(event)


if __name__ == "__main__":
    unittest.main()
