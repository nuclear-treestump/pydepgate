"""Tests for the granted CVE scanner runner."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest
from unittest.mock import patch

from pydepgate.events import (
    EventEmitter,
    EventSinkError,
    MemoryEventSink,
    ScanGrantingTicket,
    TeeEventSink,
    mintsgt,
)
from pydepgate.package_tools.cvescanner import scanner
from pydepgate.scanning import (
    CveScanError,
    CveScanRequest,
    ScanTargetRef,
    execute_cve_scan,
)

ROOT = Path(__file__).resolve().parents[2]
WHEEL_TARGET = ROOT / "demo-1.0.0-py3-none-any.whl"


class SelectiveFailSink:
    """Sink that fails only for selected event types."""

    def __init__(self, *event_types: str):
        self.event_types = set(event_types)

    def write(self, event):
        if event.event_type in self.event_types:
            raise RuntimeError(f"forced sink failure for {event.event_type}")


def _ticket(
    *,
    target_kind: str = "wheel",
    target_identity: str | None = str(WHEEL_TARGET),
    scan_mode: str = "cve.artifact",
    allowed_actions=("cve.scan",),
):
    return mintsgt(
        target_kind=target_kind,
        target_identity=target_identity,
        scan_mode=scan_mode,
        allowed_actions=allowed_actions,
        budget={"require_database": False},
        issuer="tests",
        actor="unit-test",
        require_cli_stack=False,
    )


def _expired_ticket():
    issued = datetime.now(timezone.utc) - timedelta(minutes=30)
    expires = issued + timedelta(minutes=1)
    return ScanGrantingTicket(
        issuer="tests",
        actor="unit-test",
        target_kind="wheel",
        target_identity=str(WHEEL_TARGET),
        scan_mode="cve.artifact",
        allowed_actions=("cve.scan",),
        issued_at=issued.isoformat().replace("+00:00", "Z"),
        expires_at=expires.isoformat().replace("+00:00", "Z"),
    )


def _request(
    *,
    ticket=None,
    target_ref: ScanTargetRef | None = None,
    sink=None,
    grant_event_id: str | None = "grant-event-test",
    strict_event_sinks: bool = False,
    warnings: list[str] | None = None,
):
    ticket = ticket or _ticket()
    sink = sink or MemoryEventSink()
    return CveScanRequest(
        ticket=ticket,
        target_ref=target_ref
        or ScanTargetRef(
            kind="wheel",
            identity=str(WHEEL_TARGET),
            location=str(WHEEL_TARGET),
        ),
        emitter=EventEmitter(
            "test.cve_runner.events",
            sinks=(sink,),
            run_id=ticket.run_id,
            correlation_id=ticket.correlation_id,
        ),
        db_path="/tmp/pydepgate-cvedb-test.sqlite",
        require_database=False,
        grant_event_id=grant_event_id,
        strict_event_sinks=strict_event_sinks,
        event_warning=warnings.append if warnings is not None else None,
    )


def _result():
    return scanner.CveScanResult(
        package_name="demo-pkg",
        normalized_package_name="demo-pkg",
        package_version="1.0.0",
        package_metadata=None,
        findings=(),
        unevaluated_ranges=(),
        warnings=(),
        attribution="test attribution",
        database_path=Path("/tmp/pydepgate-cvedb-test.sqlite"),
        applied_policy_result=None,
    )


class CveRunnerTests(unittest.TestCase):
    def test_execute_calls_scanner_and_emits_lifecycle_events(self):
        sink = MemoryEventSink()
        request = _request(sink=sink)

        with patch(
            "pydepgate.scanning.cve_runner.scanner.scan_artifact",
            return_value=_result(),
        ) as scan_artifact:
            outcome = execute_cve_scan(request)

        scan_artifact.assert_called_once_with(
            str(WHEEL_TARGET),
            db_path="/tmp/pydepgate-cvedb-test.sqlite",
            applied_policy_result=None,
            require_database=False,
        )
        self.assertEqual(outcome.result.package_name, "demo-pkg")
        self.assertIsNotNone(outcome.scan_started_event_id)
        self.assertIsNotNone(outcome.scan_completed_event_id)

        event_types = [event.event_type for event in sink.events]
        self.assertEqual(
            event_types,
            [
                "internal.scanner.cve_scan_started",
                "internal.scanner.cve_scan_completed",
            ],
        )
        started = sink.events[0]
        completed = sink.events[1]
        self.assertEqual(started.parent_event_id, "grant-event-test")
        self.assertEqual(completed.parent_event_id, started.event_id)
        self.assertEqual(started.ticket_id, request.ticket.ticket_id)
        self.assertEqual(completed.ticket_id, request.ticket.ticket_id)
        self.assertEqual(started.payload["scan_mode"], "cve.artifact")
        self.assertEqual(started.payload["target_ref"]["kind"], "wheel")
        self.assertEqual(completed.payload["package_name"], "demo-pkg")
        self.assertEqual(completed.payload["finding_count"], 0)

    def test_scanner_exception_emits_failed_event_and_reraises_original(self):
        sink = MemoryEventSink()
        request = _request(sink=sink)

        with patch(
            "pydepgate.scanning.cve_runner.scanner.scan_artifact",
            side_effect=RuntimeError("lookup exploded"),
        ):
            with self.assertRaisesRegex(RuntimeError, "lookup exploded"):
                execute_cve_scan(request)

        event_types = [event.event_type for event in sink.events]
        self.assertEqual(
            event_types,
            [
                "internal.scanner.cve_scan_started",
                "internal.scanner.cve_scan_failed",
            ],
        )
        failed = sink.events[1]
        self.assertEqual(failed.parent_event_id, sink.events[0].event_id)
        self.assertEqual(failed.severity, "error")
        self.assertEqual(failed.payload["exception_type"], "RuntimeError")
        self.assertEqual(failed.payload["message"], "lookup exploded")

    def test_rejects_expired_ticket(self):
        request = _request(ticket=_expired_ticket())
        with self.assertRaisesRegex(CveScanError, "expired"):
            execute_cve_scan(request)

    def test_rejects_ticket_without_cve_scan_action(self):
        request = _request(ticket=_ticket(allowed_actions=("static.scan",)))
        with self.assertRaisesRegex(CveScanError, "does not authorize"):
            execute_cve_scan(request)

    def test_accepts_generic_scan_action_for_combined_orchestration(self):
        sink = MemoryEventSink()
        ticket = _ticket(allowed_actions=("scan",), scan_mode="combined.artifact")
        request = _request(ticket=ticket, sink=sink)

        with patch(
            "pydepgate.scanning.cve_runner.scanner.scan_artifact",
            return_value=_result(),
        ):
            outcome = execute_cve_scan(request)

        self.assertEqual(outcome.result.package_name, "demo-pkg")
        self.assertEqual(sink.events[0].payload["scan_mode"], "combined.artifact")

    def test_rejects_target_identity_mismatch(self):
        ticket = _ticket(target_identity="expected.whl")
        target_ref = ScanTargetRef("wheel", "other.whl", "other.whl")
        request = _request(ticket=ticket, target_ref=target_ref)
        with self.assertRaisesRegex(CveScanError, "target reference"):
            execute_cve_scan(request)

    def test_rejects_installed_package_ref_kind(self):
        ticket = _ticket(target_kind="wheel", target_identity="demo-pkg")
        target_ref = ScanTargetRef("installed_package", "demo-pkg", "demo-pkg")
        request = _request(ticket=ticket, target_ref=target_ref)
        with self.assertRaisesRegex(CveScanError, "target ref kind"):
            execute_cve_scan(request)

    def test_rejects_non_wheel_archive_target(self):
        ticket = _ticket(target_kind="package_artifact", target_identity="demo.tar.gz")
        target_ref = ScanTargetRef("package_artifact", "demo.tar.gz", "demo.tar.gz")
        request = _request(ticket=ticket, target_ref=target_ref)
        with self.assertRaisesRegex(CveScanError, "wheel artifacts only"):
            execute_cve_scan(request)

    def test_rejects_wheel_kind_without_wheel_location(self):
        ticket = _ticket(target_kind="wheel", target_identity="demo")
        target_ref = ScanTargetRef("wheel", "demo", "demo")
        request = _request(ticket=ticket, target_ref=target_ref)
        with self.assertRaisesRegex(CveScanError, r"\.whl"):
            execute_cve_scan(request)

    def test_non_strict_sink_failure_warns_and_scan_continues(self):
        memory = MemoryEventSink()
        failing = SelectiveFailSink("internal.scanner.cve_scan_completed")
        warnings: list[str] = []
        request = _request(
            sink=TeeEventSink((memory, failing)),
            warnings=warnings,
            strict_event_sinks=False,
        )

        with patch(
            "pydepgate.scanning.cve_runner.scanner.scan_artifact",
            return_value=_result(),
        ):
            outcome = execute_cve_scan(request)

        self.assertEqual(outcome.result.package_name, "demo-pkg")
        self.assertIsNone(outcome.scan_completed_event_id)
        self.assertTrue(any("cve_scan_completed" in warning for warning in warnings))
        self.assertIn(
            "internal.scanner.cve_scan_completed",
            [event.event_type for event in memory.events],
        )

    def test_strict_sink_failure_surfaces_event_sink_error(self):
        memory = MemoryEventSink()
        failing = SelectiveFailSink("internal.scanner.cve_scan_started")
        request = _request(
            sink=TeeEventSink((memory, failing)),
            strict_event_sinks=True,
        )

        with self.assertRaises(EventSinkError):
            execute_cve_scan(request)

        self.assertEqual(
            [event.event_type for event in memory.events],
            ["internal.scanner.cve_scan_started"],
        )


if __name__ == "__main__":
    unittest.main()
