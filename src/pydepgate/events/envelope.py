"""Event envelope primitives for pydepgate.

An EventEnvelope is the durable wrapper around a structured event payload. It
carries correlation fields, timing fields, producer identity, and a stable
payload digest. Payloads are deep-frozen during construction so callers cannot
change an event after it has been created.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from collections.abc import Mapping

from pydepgate.events.freeze import DeepFreezeError, deep_freeze
from pydepgate.events.serialization import (
    EventSerializationError,
    stable_sha256_json,
    to_jsonable,
    stable_json_dumps,
)
from pydepgate.run_context import _generate_uuid7_str, get_current_run_uuid

_EVENT_PREFIXES = ("internal.", "external.")
_ALLOWED_SEVERITIES = frozenset({"debug", "info", "warning", "error", "critical"})


class EventEnvelopeError(ValueError):
    """Raised when an event envelope cannot be built safely."""


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    """Immutable event record used by pydepgate event producers."""

    event_type: str
    producer: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = 1
    event_id: str = field(default_factory=_generate_uuid7_str)
    run_id: str = field(default_factory=get_current_run_uuid)
    correlation_id: str | None = None
    parent_event_id: str | None = None
    ticket_id: str | None = None
    occurred_at: str = field(default_factory=_utc_now)
    emitted_at: str = field(default_factory=_utc_now)
    severity: str = "info"
    payload_schema: str | None = None
    payload_digest: str = field(init=False)

    def __post_init__(self) -> None:
        _require_non_empty_string(self.event_type, "event_type")
        if not self.event_type.startswith(_EVENT_PREFIXES):
            raise EventEnvelopeError(
                "event_type must start with internal. or external."
            )

        _require_non_empty_string(self.producer, "producer")
        _require_non_empty_string(self.event_id, "event_id")
        _require_non_empty_string(self.run_id, "run_id")
        _require_non_empty_string(self.occurred_at, "occurred_at")
        _require_non_empty_string(self.emitted_at, "emitted_at")

        if not isinstance(self.schema_version, int) or self.schema_version < 1:
            raise EventEnvelopeError("schema_version must be a positive integer")

        if self.severity not in _ALLOWED_SEVERITIES:
            raise EventEnvelopeError(f"unsupported severity: {self.severity}")

        for field_name in (
            "correlation_id",
            "parent_event_id",
            "ticket_id",
            "payload_schema",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _require_non_empty_string(value, field_name)

        if not isinstance(self.payload, Mapping):
            raise EventEnvelopeError("payload must be a mapping")

        try:
            frozen_payload = deep_freeze(dict(self.payload))
            payload_digest = stable_sha256_json(frozen_payload)
        except (DeepFreezeError, EventSerializationError) as exc:
            raise EventEnvelopeError(str(exc)) from exc

        object.__setattr__(self, "payload", frozen_payload)
        object.__setattr__(self, "payload_digest", payload_digest)

        if self.correlation_id is None:
            object.__setattr__(self, "correlation_id", self.run_id)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible dictionary for this envelope."""
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "producer": self.producer,
            "run_id": self.run_id,
            "correlation_id": self.correlation_id,
            "parent_event_id": self.parent_event_id,
            "ticket_id": self.ticket_id,
            "occurred_at": self.occurred_at,
            "emitted_at": self.emitted_at,
            "severity": self.severity,
            "payload_schema": self.payload_schema,
            "payload_digest": self.payload_digest,
            "payload": to_jsonable(self.payload),
        }

    def to_json(self) -> str:
        """Return deterministic JSON for this envelope."""
        return stable_json_dumps(self.to_dict())


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_non_empty_string(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise EventEnvelopeError(f"{field_name} must be a non-empty string")
