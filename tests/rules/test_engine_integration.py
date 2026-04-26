"""Tests that the static engine correctly uses the rules engine."""

import unittest

from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.engines.base import ArtifactKind, Severity
from pydepgate.engines.static import StaticEngine
from pydepgate.rules.base import (
    Rule,
    RuleAction,
    RuleEffect,
    RuleMatch,
    RuleSource,
)


class EngineRulesIntegrationTests(unittest.TestCase):

    def test_default_rules_promote_setup_py_findings_to_critical(self):
        """A setup.py with encoded-payload-then-exec gets CRITICAL severity."""
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])
        result = engine.scan_bytes(
            content=source,
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(len(result.findings), 1)
        # ENC001 in setup.py: default rule says CRITICAL.
        self.assertEqual(result.findings[0].severity, Severity.CRITICAL)

    def test_user_suppression_rule_silences_finding(self):
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        user_rule = Rule(
            rule_id="USER_test",
            source=RuleSource.USER,
            match=RuleMatch(signal_id="ENC001"),
            effect=RuleEffect(action=RuleAction.SUPPRESS),
            explain="testing suppression",
        )
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            rules=[user_rule],
        )
        result = engine.scan_bytes(
            content=source,
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        # No active findings.
        self.assertEqual(len(result.findings), 0)
        # But suppression is recorded.
        self.assertEqual(len(result.suppressed_findings), 1)
        self.assertEqual(
            result.suppressed_findings[0].suppressing_rule_id, "USER_test"
        )
        self.assertEqual(
            result.suppressed_findings[0].suppressing_rule_source, "user"
        )

    def test_empty_rules_list_falls_back_to_mechanical_mapping(self):
        long_payload = "A" * 80  # Triggers DEFINITE confidence in encoding_abuse.
        source = (
            f"import base64\n"
            f"exec(base64.b64decode('{long_payload}'))\n"
        ).encode("utf-8")
        # Pass empty rules to test pre-rules behavior.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            rules=[],
        )
        result = engine.scan_bytes(
            content=source,
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(len(result.findings), 1)
        # DEFINITE confidence (90) -> HIGH severity via mechanical mapping.
        # No default rules applied because rules=[] was passed.
        self.assertEqual(result.findings[0].severity, Severity.HIGH)


if __name__ == "__main__":
    unittest.main()