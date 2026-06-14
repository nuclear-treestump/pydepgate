"""Adversarial event-flow tests for the static runner.

These tests force failure paths and sink errors so event handling is exercised
outside the happy path. They specifically guard the scan_failed path, parent
chains, ticket correlation, and non-strict sink behavior.
"""

from __future__ import annotations

from pathlib import Path
import unittest
from unittest.mock import patch

from pydepgate.events import EventEmitter, EventSinkError, MemoryEventSink, mintsgt
from pydepgate.rules.defaults import DEFAULT_RULES
from pydepgate.scanning import (
    ScanTargetRef,
    StaticDecodeOptions,
    StaticScanRequest,
    execute_static_scan,
)

ROOT = Path(__file__).resolve().parents[2]
OBFUSCATED_SETUP = ROOT / "test_files" / "obfuscated_setup.py"


class SelectiveFailSink:
    """Sink that fails only for selected event types."""

    def __init__(self, *event_types: str):
        self.event_types = set(event_types)

    def write(self, event):
        if event.event_type in self.event_types:
            raise RuntimeError(f"forced sink failure for {event.event_type}")


def _ticket(
    *,
    decode: bool = False,
    allowed_actions=("scan",),
    budget: dict | None = None,
):
    full_budget = {"single": True}
    if decode:
        full_budget.update(
            {
                "decode_enabled": True,
                "decode_payload_depth": 2,
                "decode_iocs": "hashes",
            }
        )
    if budget:
        full_budget.update(budget)

    return mintsgt(
        target_kind="loose_file",
        target_identity=str(OBFUSCATED_SETUP),
        scan_mode="static.single",
        allowed_actions=allowed_actions,
        budget=full_budget,
        issuer="tests",
        actor="unit-test",
        require_cli_stack=False,
    )


def _request(
    *,
    ticket,
    sink,
    grant_event_id: str | None = "grant-event-test",
    strict_event_sinks: bool = False,
    warnings: list[str] | None = None,
):
    return StaticScanRequest(
        ticket=ticket,
        target_ref=ScanTargetRef(
            kind="loose_file",
            identity=str(OBFUSCATED_SETUP),
            location=str(OBFUSCATED_SETUP),
        ),
        rules=tuple(DEFAULT_RULES),
        emitter=EventEmitter(
            "test.static_runner.events",
            sinks=(sink,),
            run_id=ticket.run_id,
            correlation_id=ticket.correlation_id,
        ),
        grant_event_id=grant_event_id,
        decode_options=StaticDecodeOptions(min_severity="high"),
        strict_event_sinks=strict_event_sinks,
        event_warning=warnings.append if warnings is not None else None,
    )


class StaticRunnerEventAdversarialTests(unittest.TestCase):
    def test_dispatch_exception_emits_scan_failed_and_reraises_original(self):
        sink = MemoryEventSink()
        request = _request(ticket=_ticket(), sink=sink)

        with patch(
            "pydepgate.scanning.static_runner._dispatch_static_scan",
            side_effect=RuntimeError("hostile dispatch failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "hostile dispatch failure"):
                execute_static_scan(request)

        event_types = [event.event_type for event in sink.events]
        self.assertEqual(
            event_types,
            [
                "internal.scanner.engine_created",
                "internal.scanner.scan_started",
                "internal.scanner.scan_failed",
            ],
        )
        scan_started = sink.events[1]
        scan_failed = sink.events[2]
        self.assertEqual(scan_failed.parent_event_id, scan_started.event_id)
        self.assertEqual(scan_failed.ticket_id, request.ticket.ticket_id)
        self.assertEqual(scan_failed.severity, "error")
        self.assertEqual(scan_failed.payload["exception_type"], "RuntimeError")
        self.assertEqual(scan_failed.payload["message"], "hostile dispatch failure")

    def test_happy_path_event_parent_chain_and_ticket_correlation(self):
        sink = MemoryEventSink()
        ticket = _ticket(decode=True, allowed_actions=("scan", "decode"))
        request = _request(ticket=ticket, sink=sink, grant_event_id="grant-123")

        outcome = execute_static_scan(request)

        self.assertIsNotNone(outcome.scan_completed_event_id)
        event_by_type = {event.event_type: event for event in sink.events}
        engine_created = event_by_type["internal.scanner.engine_created"]
        scan_started = event_by_type["internal.scanner.scan_started"]
        scan_completed = event_by_type["internal.scanner.scan_completed"]
        decode_started = event_by_type["internal.scanner.decode_started"]
        decode_completed = event_by_type["internal.scanner.decode_completed"]

        self.assertEqual(engine_created.parent_event_id, "grant-123")
        self.assertEqual(scan_started.parent_event_id, engine_created.event_id)
        self.assertEqual(scan_completed.parent_event_id, scan_started.event_id)
        self.assertEqual(decode_started.parent_event_id, scan_completed.event_id)
        self.assertEqual(decode_completed.parent_event_id, decode_started.event_id)

        for event in sink.events:
            self.assertEqual(event.run_id, ticket.run_id)
            self.assertEqual(event.correlation_id, ticket.correlation_id)
            self.assertEqual(event.ticket_id, ticket.ticket_id)

        self.assertEqual(decode_completed.payload["decode_iocs"], "hashes")
        self.assertIn("ioc_count", decode_completed.payload)
        self.assertIn("total_node_count", decode_completed.payload)

    def test_non_strict_sink_failure_warns_and_scan_continues(self):
        memory = MemoryEventSink()
        failing = SelectiveFailSink("internal.scanner.scan_completed")
        from pydepgate.events import TeeEventSink

        warnings: list[str] = []
        request = _request(
            ticket=_ticket(),
            sink=TeeEventSink((memory, failing)),
            warnings=warnings,
            strict_event_sinks=False,
        )

        outcome = execute_static_scan(request)

        self.assertGreaterEqual(len(outcome.result.findings), 1)
        self.assertTrue(any("scan_completed" in warning for warning in warnings))
        self.assertIn(
            "internal.scanner.scan_completed",
            [event.event_type for event in memory.events],
        )
        self.assertIsNone(outcome.scan_completed_event_id)

    def test_strict_sink_failure_surfaces_event_sink_error(self):
        from pydepgate.events import TeeEventSink

        memory = MemoryEventSink()
        failing = SelectiveFailSink("internal.scanner.engine_created")
        request = _request(
            ticket=_ticket(),
            sink=TeeEventSink((memory, failing)),
            strict_event_sinks=True,
        )

        with self.assertRaises(EventSinkError):
            execute_static_scan(request)

        self.assertEqual(
            [event.event_type for event in memory.events],
            ["internal.scanner.engine_created"],
        )

    def test_decode_failure_warns_and_emits_warning_completion_event(self):
        sink = MemoryEventSink()
        warnings: list[str] = []
        ticket = _ticket(decode=True, allowed_actions=("scan", "decode"))
        request = _request(ticket=ticket, sink=sink, warnings=warnings)

        with patch(
            "pydepgate.scanning.static_runner.decode_payloads",
            side_effect=ValueError("decode bomb"),
        ):
            outcome = execute_static_scan(request)

        self.assertIsNone(outcome.decoded_tree)
        self.assertTrue(any("decoded-payload pass failed" in item for item in warnings))
        decode_completed = next(
            event
            for event in sink.events
            if event.event_type == "internal.scanner.decode_completed"
        )
        self.assertEqual(decode_completed.severity, "warning")
        self.assertEqual(decode_completed.payload["tree_available"], False)
        self.assertEqual(decode_completed.payload["ioc_count"], 0)
        self.assertEqual(decode_completed.payload["total_node_count"], 0)


if __name__ == "__main__":
    unittest.main()
