"""Tests for Scan Granting Tickets."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import unittest

from pydepgate.events.freeze import FrozenMapping
from pydepgate.events.tickets import (
    LocalInvocationError,
    ScanGrantingTicket,
    ScanGrantingTicketError,
    mintsgt,
)


class TestMintScanGrantingTicket(unittest.TestCase):
    def test_mintsgt_builds_ticket(self):
        ticket = mintsgt(
            target_kind="wheel",
            target_identity="example-1.0.0-py3-none-any.whl",
            scan_mode="static.deep",
            allowed_actions=("scan", "decode"),
            policy_fingerprint="policy-sha256-test",
            ruleset_fingerprint="rules-sha256-test",
            budget={"workers": 2, "decode_depth": 1},
            metadata={"source": "unit-test"},
            ttl_seconds=60,
        )

        self.assertIsInstance(ticket, ScanGrantingTicket)
        self.assertTrue(ticket.ticket_id.startswith("sgt_"))
        self.assertTrue(ticket.ticket_nonce)
        self.assertEqual(ticket.correlation_id, ticket.run_id)
        self.assertTrue(ticket.allows_action("scan"))
        self.assertTrue(ticket.allows_action("decode"))
        self.assertFalse(ticket.allows_action("serve"))
        self.assertFalse(ticket.is_expired())
        self.assertEqual(len(ticket.ticket_digest), 64)

    def test_mintsgt_records_local_invocation_evidence(self):
        ticket = mintsgt(target_kind="single_file", require_cli_stack=False)

        evidence = ticket.local_invocation
        self.assertIsInstance(evidence, FrozenMapping)
        self.assertIn("process_id", evidence)
        self.assertIn("parent_process_id", evidence)
        self.assertIn("argv_digest", evidence)
        self.assertIn("stack_modules", evidence)
        self.assertTrue(evidence["has_pydepgate_frame"])

    def test_require_cli_stack_fails_without_cli_frame(self):
        with self.assertRaises(LocalInvocationError):
            mintsgt(target_kind="wheel", require_cli_stack=True)

    def test_mintsgt_rejects_bad_ttl(self):
        with self.assertRaises(ScanGrantingTicketError):
            mintsgt(ttl_seconds=0)

    def test_mintsgt_detaches_source_mappings(self):
        budget = {"workers": 4, "limits": {"decode_depth": 1}}
        metadata = {"labels": ["local"]}

        ticket = mintsgt(budget=budget, metadata=metadata)

        budget["workers"] = 99
        budget["limits"]["decode_depth"] = 9
        metadata["labels"].append("changed")

        self.assertEqual(ticket.budget["workers"], 4)
        self.assertEqual(ticket.budget["limits"]["decode_depth"], 1)
        self.assertEqual(ticket.metadata["labels"], ("local",))

    def test_to_json_is_json_compatible(self):
        ticket = mintsgt(
            target_kind="wheel",
            budget={"workers": 2},
            metadata={"tags": {"beta", "alpha"}},
        )

        decoded = json.loads(ticket.to_json())

        self.assertEqual(decoded["target_kind"], "wheel")
        self.assertEqual(decoded["metadata"]["tags"], ["alpha", "beta"])
        self.assertEqual(decoded["ticket_digest"], ticket.ticket_digest)


class TestScanGrantingTicketValidation(unittest.TestCase):
    def test_ticket_requires_allowed_actions(self):
        with self.assertRaises(ScanGrantingTicketError):
            ScanGrantingTicket(allowed_actions=())

    def test_ticket_rejects_blank_action(self):
        with self.assertRaises(ScanGrantingTicketError):
            ScanGrantingTicket(allowed_actions=("scan", " "))

    def test_ticket_rejects_string_allowed_actions(self):
        with self.assertRaises(ScanGrantingTicketError):
            ScanGrantingTicket(allowed_actions="scan")

    def test_ticket_rejects_non_mapping_budget(self):
        with self.assertRaises(ScanGrantingTicketError):
            ScanGrantingTicket(budget=[("workers", 2)])

    def test_ticket_rejects_non_json_metadata(self):
        with self.assertRaises(ScanGrantingTicketError):
            ScanGrantingTicket(metadata={"blob": b"abc"})

    def test_ticket_expiry_check(self):
        issued = datetime.now(timezone.utc) - timedelta(minutes=10)
        expires = issued + timedelta(minutes=1)
        ticket = ScanGrantingTicket(
            issued_at=issued.isoformat().replace("+00:00", "Z"),
            expires_at=expires.isoformat().replace("+00:00", "Z"),
        )

        self.assertTrue(ticket.is_expired(datetime.now(timezone.utc)))

    def test_ticket_fields_are_frozen(self):
        ticket = mintsgt(budget={"workers": 1}, metadata={"source": "test"})

        self.assertIsInstance(ticket.budget, FrozenMapping)
        self.assertIsInstance(ticket.metadata, FrozenMapping)
        with self.assertRaises(TypeError):
            ticket.budget["workers"] = 2
        with self.assertRaises(TypeError):
            ticket.metadata["source"] = "changed"


if __name__ == "__main__":
    unittest.main()
