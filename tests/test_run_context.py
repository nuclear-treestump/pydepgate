"""Tests for run_context.

Coverage:

  * UUID format: matches str(uuid.uuid4()) shape (36 chars,
    lowercase hex, hyphens at fixed positions).
  * Caching: repeated get_current_run_uuid calls return the same
    value within a process.
  * Reset: reset_for_new_run produces a different value and
    changes what subsequent gets return.
  * Thread safety: concurrent first-access from 20 threads all
    observe a single shared UUID.
  * Uniqueness sanity: 100 resets produce 100 distinct values.

The tests reset module state in setUp so cross-test contamination
does not appear in failure modes.
"""

from __future__ import annotations

import re
import threading
import unittest

from pydepgate import run_context

_UUID4_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


class TestRunUuidLifecycle(unittest.TestCase):
    def setUp(self):
        # Reset before each test so we get clean state. This is
        # exactly the pattern the docstring documents for test
        # harnesses.
        run_context.reset_for_new_run()

    def test_first_call_returns_uuid4_string(self):
        uid = run_context.get_current_run_uuid()
        self.assertIsInstance(uid, str)
        self.assertRegex(uid, _UUID4_REGEX)

    def test_subsequent_calls_return_same_value(self):
        first = run_context.get_current_run_uuid()
        second = run_context.get_current_run_uuid()
        third = run_context.get_current_run_uuid()
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_uuid_is_36_chars_with_hyphens(self):
        uid = run_context.get_current_run_uuid()
        self.assertEqual(len(uid), 36)
        # Positions of hyphens in a UUID4 string
        self.assertEqual(uid[8], "-")
        self.assertEqual(uid[13], "-")
        self.assertEqual(uid[18], "-")
        self.assertEqual(uid[23], "-")

    def test_uuid_is_lowercase(self):
        uid = run_context.get_current_run_uuid()
        self.assertEqual(uid, uid.lower())


class TestReset(unittest.TestCase):
    def test_reset_returns_new_uuid(self):
        run_context.reset_for_new_run()
        first = run_context.get_current_run_uuid()
        new_uid = run_context.reset_for_new_run()
        self.assertNotEqual(first, new_uid)
        self.assertRegex(new_uid, _UUID4_REGEX)

    def test_reset_changes_subsequent_get(self):
        run_context.reset_for_new_run()
        first = run_context.get_current_run_uuid()
        run_context.reset_for_new_run()
        second = run_context.get_current_run_uuid()
        self.assertNotEqual(first, second)

    def test_reset_without_prior_get_works(self):
        # Resetting before any get is fine: just generates.
        run_context.reset_for_new_run()
        new_uid = run_context.reset_for_new_run()
        # Both calls produce valid UUIDs
        self.assertRegex(new_uid, _UUID4_REGEX)


class TestThreadSafety(unittest.TestCase):
    def test_concurrent_first_access_returns_same_uuid(self):
        """Multiple threads racing on first access share one UUID."""
        # Reset to ensure fresh state, then immediately spawn
        # threads that all call get_current_run_uuid for the
        # first time concurrently.
        run_context.reset_for_new_run()
        # Force a real first-access race by resetting state to None
        run_context._current_run_uuid = None

        results: list[str] = []
        barrier = threading.Barrier(20)

        def worker():
            barrier.wait()  # All threads start at the same time
            results.append(run_context.get_current_run_uuid())

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 20)
        # All threads observed the same UUID
        self.assertEqual(len(set(results)), 1)
        self.assertRegex(results[0], _UUID4_REGEX)


class TestUniqueness(unittest.TestCase):
    def test_resets_produce_different_uuids(self):
        """Sanity check: UUID4 collision should not happen across resets."""
        uuids = set()
        for _ in range(100):
            run_context.reset_for_new_run()
            uuids.add(run_context.get_current_run_uuid())
        self.assertEqual(len(uuids), 100)


if __name__ == "__main__":
    unittest.main()
