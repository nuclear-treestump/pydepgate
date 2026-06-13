"""JSON serialization helpers for event-system data.

Event envelopes and tickets need stable JSON output for durable records,
digests, and local audit traces. These helpers accept the immutable container
shapes produced by deep_freeze and reject values that cannot be represented as
structured JSON.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence, Set
from typing import Any


class EventSerializationError(TypeError):
    """Raised when event-system data cannot be serialized as JSON."""


def to_jsonable(value: Any) -> Any:
    """Convert supported immutable values into JSON-compatible containers."""
    if value is None or isinstance(value, (str, int, bool)):
        return value

    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise EventSerializationError("non-finite floats are not JSON-safe")
        return value

    if isinstance(value, bytes):
        raise EventSerializationError("bytes are not allowed in event JSON")

    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise EventSerializationError("event JSON mappings require string keys")
            output[key] = to_jsonable(item)
        return output

    if isinstance(value, Set) and not isinstance(value, (str, bytes, bytearray)):
        items = [to_jsonable(item) for item in value]
        return sorted(items, key=_stable_sort_key)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [to_jsonable(item) for item in value]

    raise EventSerializationError(
        f"unsupported value for event JSON: {type(value).__name__}"
    )


def stable_json_dumps(value: Any) -> str:
    """Return deterministic compact JSON for supported event-system data."""
    jsonable = to_jsonable(value)
    try:
        return json.dumps(
            jsonable,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise EventSerializationError(str(exc)) from exc


def stable_sha256_json(value: Any) -> str:
    """Return a SHA-256 digest over deterministic JSON."""
    data = stable_json_dumps(value).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _stable_sort_key(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
