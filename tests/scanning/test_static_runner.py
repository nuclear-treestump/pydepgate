"""Contract tests for the static scan runner.

These tests focus on authorization and target consistency checks. They do not
need real artifacts because all assertions should fire before dispatch reaches
the scanner engine.
"""

from __future__ import annotations

import unittest

from pydepgate.events import EventEmitter, MemoryEventSink, mintsgt
from pydepgate.rules.defaults import DEFAULT_RULES
from pydepgate.scanning import ScanTargetRef, StaticScanRequest, execute_static_scan
from pydepgate.scanning.static_runner import StaticScanError


def _request(*, ticket, target_ref, ruleset_fingerprint: str | None = None):
    return StaticScanRequest(
        ticket=ticket,
        target_ref=target_ref,
        rules=tuple(DEFAULT_RULES),
        emitter=EventEmitter("test.static_runner", sinks=(MemoryEventSink(),)),
        ruleset_fingerprint=ruleset_fingerprint,
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


if __name__ == "__main__":
    unittest.main()
