"""Contract tests for the static scan runner.

These tests focus on authorization and target consistency checks. They do not
need real artifacts because all assertions should fire before dispatch reaches
the scanner engine.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from pydepgate.engines.base import ArtifactKind, ScanResult, ScanStatistics
from pydepgate.events import EventEmitter, MemoryEventSink, mintsgt
from pydepgate.rules.defaults import DEFAULT_RULES
from pydepgate.scanning import ScanTargetRef, StaticScanRequest, execute_static_scan
from pydepgate.scanning.static_runner import StaticScanError


def _request(
    *,
    ticket,
    target_ref,
    ruleset_fingerprint: str | None = None,
    sink=None,
    grant_event_id: str | None = "grant-event-test",
):
    sink = sink or MemoryEventSink()
    return StaticScanRequest(
        ticket=ticket,
        target_ref=target_ref,
        rules=tuple(DEFAULT_RULES),
        emitter=EventEmitter(
            "test.static_runner",
            sinks=(sink,),
            run_id=ticket.run_id,
            correlation_id=ticket.correlation_id,
        ),
        ruleset_fingerprint=ruleset_fingerprint,
        grant_event_id=grant_event_id,
    )


def _ticket(
    *,
    target_kind: str,
    target_identity: str = "target.whl",
    scan_mode: str = "static.artifact",
    allowed_actions=("scan",),
    ruleset_fingerprint: str | None = None,
    budget: dict | None = None,
):
    return mintsgt(
        target_kind=target_kind,
        target_identity=target_identity,
        scan_mode=scan_mode,
        allowed_actions=allowed_actions,
        ruleset_fingerprint=ruleset_fingerprint,
        budget=budget or {},
        issuer="tests",
        actor="unit-test",
        require_cli_stack=False,
    )


class StaticRunnerContractTests(unittest.TestCase):
    def test_rejects_ticket_without_scan_action(self):
        ticket = _ticket(target_kind="wheel", allowed_actions=("decode",))
        request = _request(
            ticket=ticket,
            target_ref=ScanTargetRef("auto", "target.whl", "target.whl"),
        )
        with self.assertRaisesRegex(StaticScanError, "does not authorize"):
            execute_static_scan(request)

    def test_rejects_ruleset_fingerprint_mismatch(self):
        ticket = _ticket(target_kind="wheel", ruleset_fingerprint="abc")
        request = _request(
            ticket=ticket,
            target_ref=ScanTargetRef("auto", "target.whl", "target.whl"),
            ruleset_fingerprint="def",
        )
        with self.assertRaisesRegex(StaticScanError, "ruleset fingerprint"):
            execute_static_scan(request)

    def test_rejects_loose_file_ref_for_wheel_ticket(self):
        ticket = _ticket(target_kind="wheel")
        request = _request(
            ticket=ticket,
            target_ref=ScanTargetRef("loose_file", "target.whl", "target.whl"),
        )
        with self.assertRaisesRegex(StaticScanError, "loose-file target ref"):
            execute_static_scan(request)

    def test_rejects_archive_as_loose_file_ticket(self):
        ticket = _ticket(
            target_kind="loose_file",
            scan_mode="static.single",
            budget={"single": True},
        )
        request = _request(
            ticket=ticket,
            target_ref=ScanTargetRef("loose_file", "target.whl", "target.whl"),
        )
        with self.assertRaisesRegex(StaticScanError, "archive artifacts"):
            execute_static_scan(request)

    def test_rejects_single_budget_on_non_loose_ticket(self):
        ticket = _ticket(target_kind="wheel", budget={"single": True})
        request = _request(
            ticket=ticket,
            target_ref=ScanTargetRef("auto", "target.whl", "target.whl"),
        )
        with self.assertRaisesRegex(StaticScanError, "single-file budget"):
            execute_static_scan(request)

    def test_rejects_incompatible_ref_kind_for_wheel_ticket(self):
        ticket = _ticket(target_kind="wheel", target_identity="package")
        request = _request(
            ticket=ticket,
            target_ref=ScanTargetRef("installed_package", "package", "package"),
        )
        with self.assertRaisesRegex(StaticScanError, "wheel ticket"):
            execute_static_scan(request)

    def test_rejects_incompatible_ref_kind_for_sdist_ticket(self):
        ticket = _ticket(target_kind="sdist", target_identity="package")
        request = _request(
            ticket=ticket,
            target_ref=ScanTargetRef("installed_package", "package", "package"),
        )
        with self.assertRaisesRegex(StaticScanError, "sdist ticket"):
            execute_static_scan(request)

    def test_completed_event_includes_combined_report_context(self):
        sink = MemoryEventSink()
        ticket = _ticket(target_kind="wheel", allowed_actions=("static.scan",))
        request = _request(
            ticket=ticket,
            target_ref=ScanTargetRef("auto", "target.whl", "target.whl"),
            sink=sink,
        )
        fake_result = ScanResult(
            artifact_identity="target.whl",
            artifact_kind=ArtifactKind.WHEEL,
            findings=(),
            skipped=(),
            statistics=ScanStatistics(files_total=1, files_scanned=1),
        )

        with patch(
            "pydepgate.scanning.static_runner._dispatch_static_scan",
            return_value=fake_result,
        ):
            outcome = execute_static_scan(request)

        self.assertEqual(outcome.result.artifact_identity, "target.whl")
        event_types = [event.event_type for event in sink.events]
        self.assertEqual(
            event_types,
            [
                "internal.scanner.engine_created",
                "internal.scanner.scan_started",
                "internal.scanner.scan_completed",
            ],
        )
        completed = sink.events[2]
        self.assertEqual(completed.parent_event_id, sink.events[1].event_id)
        self.assertEqual(completed.payload["scan_mode"], "static.artifact")
        self.assertEqual(completed.payload["target_kind"], "wheel")
        self.assertEqual(completed.payload["target_identity"], "target.whl")
        self.assertEqual(completed.payload["target_ref"]["kind"], "auto")
        self.assertEqual(completed.payload["result_kind"], "static_analysis")
        self.assertEqual(completed.payload["artifact_identity"], "target.whl")
        self.assertEqual(completed.payload["artifact_kind"], "wheel")

    def test_failed_event_includes_combined_report_context(self):
        sink = MemoryEventSink()
        ticket = _ticket(target_kind="wheel", allowed_actions=("static.scan",))
        request = _request(
            ticket=ticket,
            target_ref=ScanTargetRef("auto", "target.whl", "target.whl"),
            sink=sink,
        )

        with patch(
            "pydepgate.scanning.static_runner._dispatch_static_scan",
            side_effect=RuntimeError("static exploded"),
        ):
            with self.assertRaisesRegex(RuntimeError, "static exploded"):
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
        failed = sink.events[2]
        self.assertEqual(failed.parent_event_id, sink.events[1].event_id)
        self.assertEqual(failed.severity, "error")
        self.assertEqual(failed.payload["scan_mode"], "static.artifact")
        self.assertEqual(failed.payload["target_ref"]["kind"], "auto")
        self.assertEqual(failed.payload["result_kind"], "static_analysis")
        self.assertEqual(failed.payload["exception_type"], "RuntimeError")
        self.assertEqual(failed.payload["message"], "static exploded")


if __name__ == "__main__":
    unittest.main()
