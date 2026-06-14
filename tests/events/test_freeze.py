"""Tests for event deep-freeze helpers."""

from __future__ import annotations

import unittest
from types import MappingProxyType

from pydepgate.events.freeze import DeepFreezeError, FrozenMapping, deep_freeze


class TestDeepFreezeMappings(unittest.TestCase):
    def test_mapping_becomes_mapping_proxy(self):
        frozen = deep_freeze({"a": 1})

        self.assertIsInstance(frozen, FrozenMapping)
        self.assertEqual(frozen["a"], 1)
        with self.assertRaises(TypeError):
            frozen["b"] = 2

    def test_nested_mapping_is_frozen(self):
        frozen = deep_freeze({"outer": {"inner": "value"}})

        self.assertIsInstance(frozen["outer"], FrozenMapping)
        with self.assertRaises(TypeError):
            frozen["outer"]["inner"] = "changed"

    def test_source_mapping_mutation_does_not_affect_frozen_value(self):
        source = {"items": ["alpha"], "nested": {"count": 1}}
        frozen = deep_freeze(source)

        source["items"].append("bravo")
        source["nested"]["count"] = 99
        source["new"] = True

        self.assertEqual(frozen["items"], ("alpha",))
        self.assertEqual(frozen["nested"]["count"], 1)
        self.assertNotIn("new", frozen)

    def test_mapping_proxy_input_is_detached(self):
        source = {"nested": {"value": "original"}}
        proxy = MappingProxyType(source)
        frozen = deep_freeze(proxy)

        source["nested"]["value"] = "changed"
        source["added"] = True

        self.assertEqual(frozen["nested"]["value"], "original")
        self.assertNotIn("added", frozen)


class TestDeepFreezeSequences(unittest.TestCase):
    def test_list_and_tuple_become_tuples(self):
        frozen = deep_freeze([1, [2, 3], (4, [5])])

        self.assertEqual(frozen, (1, (2, 3), (4, (5,))))
        self.assertIsInstance(frozen, tuple)
        self.assertIsInstance(frozen[1], tuple)
        self.assertIsInstance(frozen[2], tuple)
        self.assertIsInstance(frozen[2][1], tuple)

    def test_set_and_frozenset_become_frozensets(self):
        frozen = deep_freeze({"tags": {"a", "b"}, "fixed": frozenset({"c"})})

        self.assertIsInstance(frozen["tags"], frozenset)
        self.assertEqual(frozen["tags"], frozenset({"a", "b"}))
        self.assertIsInstance(frozen["fixed"], frozenset)
        self.assertEqual(frozen["fixed"], frozenset({"c"}))

    def test_source_sequence_mutation_does_not_affect_frozen_value(self):
        source = ["alpha", ["bravo"]]
        frozen = deep_freeze(source)

        source.append("charlie")
        source[1].append("delta")

        self.assertEqual(frozen, ("alpha", ("bravo",)))


class TestDeepFreezeByteContainers(unittest.TestCase):
    def test_bytearray_becomes_bytes_and_is_detached(self):
        source = bytearray(b"abc")
        frozen = deep_freeze({"blob": source})

        source[0] = ord("z")

        self.assertEqual(frozen["blob"], b"abc")
        self.assertIsInstance(frozen["blob"], bytes)

    def test_memoryview_becomes_bytes_and_is_detached(self):
        source = bytearray(b"abc")
        frozen = deep_freeze({"blob": memoryview(source)})

        source[0] = ord("z")

        self.assertEqual(frozen["blob"], b"abc")
        self.assertIsInstance(frozen["blob"], bytes)


class TestDeepFreezeCycles(unittest.TestCase):
    def test_list_cycle_is_rejected(self):
        value = []
        value.append(value)

        with self.assertRaises(DeepFreezeError):
            deep_freeze(value)

    def test_mapping_cycle_is_rejected(self):
        value = {}
        value["self"] = value

        with self.assertRaises(DeepFreezeError):
            deep_freeze(value)

    def test_indirect_cycle_is_rejected(self):
        first = []
        second = {"first": first}
        first.append(second)

        with self.assertRaises(DeepFreezeError):
            deep_freeze(first)


class TestDeepFreezeScalars(unittest.TestCase):
    def test_immutable_scalars_are_returned_unchanged(self):
        for value in (None, True, False, 1, 1.5, "text", b"bytes"):
            with self.subTest(value=value):
                self.assertIs(deep_freeze(value), value)

    def test_unknown_objects_are_rejected(self):
        value = object()

        with self.assertRaises(DeepFreezeError):
            deep_freeze(value)


if __name__ == "__main__":
    unittest.main()
