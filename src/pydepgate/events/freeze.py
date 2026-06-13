"""Immutable container helpers for pydepgate events.

The event system needs payloads and metadata that cannot be changed after
creation. MappingProxyType gives a read-only mapping view, but it does not
freeze nested values and it does not protect against later mutation of the
original source mapping.

This module provides deep_freeze, which recursively copies supported mutable
containers into immutable equivalents before wrapping mappings. Unsupported
objects are rejected so event payloads do not accidentally retain mutable
application state.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

_IMMUTABLE_SCALARS = (str, bytes, int, float, bool, type(None))


class DeepFreezeError(TypeError):
    """Raised when a value cannot be safely deep-frozen."""


FrozenMapping = type(MappingProxyType({}))


def deep_freeze(value: Any) -> Any:
    """Return an immutable, detached copy of a supported value.

    Supported conversions:
    - dict and other mappings become MappingProxyType over a copied dict.
    - list and tuple become tuple.
    - set and frozenset become frozenset.
    - bytearray and memoryview become bytes.
    - scalar immutable values are returned as-is.

    Cyclic structures are rejected because event payloads and ticket metadata
    must be acyclic, serializable shapes. Unsupported objects are also
    rejected because preserving them could leave mutable state reachable from
    an otherwise frozen event.
    """
    return _deep_freeze(value, seen=set())


def _deep_freeze(value: Any, seen: set[int]) -> Any:
    if isinstance(value, _IMMUTABLE_SCALARS):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, memoryview):
        return value.tobytes()

    value_id = id(value)

    if isinstance(value, Mapping):
        _enter(value_id, seen)
        try:
            frozen_items = {}
            for key, item in value.items():
                frozen_key = _deep_freeze(key, seen)
                _require_hashable_key(frozen_key, key)
                frozen_items[frozen_key] = _deep_freeze(item, seen)
        finally:
            seen.remove(value_id)
        return MappingProxyType(frozen_items)

    if isinstance(value, tuple):
        _enter(value_id, seen)
        try:
            return tuple(_deep_freeze(item, seen) for item in value)
        finally:
            seen.remove(value_id)

    if isinstance(value, list):
        _enter(value_id, seen)
        try:
            return tuple(_deep_freeze(item, seen) for item in value)
        finally:
            seen.remove(value_id)

    if isinstance(value, (set, frozenset)):
        _enter(value_id, seen)
        try:
            return frozenset(_deep_freeze(item, seen) for item in value)
        finally:
            seen.remove(value_id)

    raise DeepFreezeError(f"unsupported value for deep_freeze: {type(value).__name__}")


def _enter(value_id: int, seen: set[int]) -> None:
    if value_id in seen:
        raise DeepFreezeError("cannot deep-freeze cyclic structures")
    seen.add(value_id)


def _require_hashable_key(frozen_key: Any, original_key: Any) -> None:
    try:
        hash(frozen_key)
    except TypeError as exc:
        raise DeepFreezeError(
            "mapping key cannot be frozen into a hashable value: "
            f"{type(original_key).__name__}"
        ) from exc
