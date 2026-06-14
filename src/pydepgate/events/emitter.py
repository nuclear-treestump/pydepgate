"""Event emitter primitives for pydepgate.

An EventEmitter owns producer identity and default correlation fields. Calling
emit creates one EventEnvelope, sends that immutable envelope to each configured
sink, and returns the envelope to the caller.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from pydepgate.events.envelope import EventEnvelope
from pydepgate.events.sinks import EventSink, EventSinkError, _require_sink
from pydepgate.run_context import get_current_run_uuid


class EventEmitterError(RuntimeError):
    """Raised when an emitter is configured incorrectly."""


@dataclass(slots=True)
class EventEmitter:
    """Create event envelopes and deliver them to configured sinks."""

    producer: str
    sinks: Sequence[EventSink] = field(default_factory=tuple)
    run_id: str = field(default_factory=get_current_run_uuid)
    correlation_id: str | None = None
    _sinks: tuple[EventSink, ...] = field(init=False)

    def __post_init__(self) -> None:
        _require_non_empty_string(self.producer, "producer")
        _require_non_empty_string(self.run_id, "run_id")
        if self.correlation_id is None:
            self.correlation_id = self.run_id
        else:
            _require_non_empty_string(self.correlation_id, "correlation_id")

        self._sinks = tuple(self.sinks)
        for sink in self._sinks:
            try:
                _require_sink(sink)
            except EventSinkError as exc:
                raise EventEmitterError(str(exc)) from exc

    @property
    def configured_sinks(self) -> tuple[EventSink, ...]:
        """Return configured sinks as an immutable tuple."""
        return self._sinks

    def emit(
        self,
        event_type: str,
        payload: Mapping[str, Any] | None = None,
        *,
        severity: str = "info",
        parent_event_id: str | None = None,
        ticket_id: str | None = None,
        payload_schema: str | None = None,
        occurred_at: str | None = None,
    ) -> EventEnvelope:
        """Create and deliver an event envelope."""
        event_kwargs: dict[str, Any] = {
            "event_type": event_type,
            "producer": self.producer,
            "payload": {} if payload is None else payload,
            "run_id": self.run_id,
            "correlation_id": self.correlation_id,
            "parent_event_id": parent_event_id,
            "ticket_id": ticket_id,
            "severity": severity,
            "payload_schema": payload_schema,
        }
        if occurred_at is not None:
            event_kwargs["occurred_at"] = occurred_at

        event = EventEnvelope(**event_kwargs)
        for index, sink in enumerate(self._sinks):
            try:
                sink.write(event)
            except Exception as exc:
                if isinstance(exc, EventSinkError):
                    message = str(exc)
                else:
                    message = f"{type(exc).__name__}: {exc}"
                raise EventSinkError(
                    f"sink {index} failed while emitting {event.event_id}: {message}"
                ) from exc
        return event


def _require_non_empty_string(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise EventEmitterError(f"{field_name} must be a non-empty string")
