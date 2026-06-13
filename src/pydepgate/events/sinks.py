"""Event sink primitives for pydepgate.

Sinks receive immutable EventEnvelope instances from an EventEmitter. They do not
create events and they do not mutate events. The first sinks are intentionally
small so local CLI runs can keep an in-memory trace, write a JSONL trace, or tee
the same event to multiple destinations.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from pydepgate.events.envelope import EventEnvelope


class EventSinkError(RuntimeError):
    """Raised when an event sink cannot accept an event."""


class EventSink(Protocol):
    """Protocol implemented by event sinks."""

    def write(self, event: EventEnvelope) -> None:
        """Accept one immutable event envelope."""


@dataclass(slots=True)
class NullEventSink:
    """Sink that accepts events and discards them."""

    def write(self, event: EventEnvelope) -> None:
        """Accept an event without storing it."""
        _require_event(event)


@dataclass(slots=True)
class MemoryEventSink:
    """In-memory sink for tests, local traces, and debugging."""

    max_events: int | None = None
    _events: list[EventEnvelope] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        if self.max_events is not None:
            if not isinstance(self.max_events, int) or self.max_events <= 0:
                raise EventSinkError("max_events must be a positive integer or None")

    @property
    def events(self) -> tuple[EventEnvelope, ...]:
        """Return stored events as an immutable tuple."""
        return tuple(self._events)

    def write(self, event: EventEnvelope) -> None:
        """Store one event envelope."""
        _require_event(event)
        self._events.append(event)
        if self.max_events is not None and len(self._events) > self.max_events:
            del self._events[: len(self._events) - self.max_events]

    def clear(self) -> None:
        """Remove all stored events."""
        self._events.clear()


@dataclass(slots=True)
class JsonlEventSink:
    """Sink that writes one event envelope per JSONL line."""

    path: str | Path
    append: bool = True
    create_parents: bool = True
    encoding: str = "utf-8"
    _path: Path = field(init=False)
    _initialized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self._path = Path(self.path)
        if not isinstance(self.encoding, str) or not self.encoding:
            raise EventSinkError("encoding must be a non-empty string")

    @property
    def resolved_path(self) -> Path:
        """Return the filesystem path used by this sink."""
        return self._path

    def write(self, event: EventEnvelope) -> None:
        """Append one event envelope to the JSONL file."""
        _require_event(event)
        if self.create_parents:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise EventSinkError(str(exc)) from exc

        mode = "a"
        if not self.append and not self._initialized:
            mode = "w"

        try:
            with self._path.open(mode, encoding=self.encoding) as handle:
                handle.write(event.to_json())
                handle.write("\n")
        except OSError as exc:
            raise EventSinkError(str(exc)) from exc
        self._initialized = True


@dataclass(slots=True)
class TeeEventSink:
    """Sink that writes each event to multiple child sinks."""

    sinks: Sequence[EventSink]
    _sinks: tuple[EventSink, ...] = field(init=False)

    def __post_init__(self) -> None:
        self._sinks = tuple(self.sinks)
        if not self._sinks:
            raise EventSinkError("TeeEventSink requires at least one child sink")
        for sink in self._sinks:
            _require_sink(sink)

    @property
    def children(self) -> tuple[EventSink, ...]:
        """Return child sinks as an immutable tuple."""
        return self._sinks

    def write(self, event: EventEnvelope) -> None:
        """Write one event envelope to all child sinks in order."""
        _require_event(event)
        for index, sink in enumerate(self._sinks):
            try:
                sink.write(event)
            except Exception as exc:
                if isinstance(exc, EventSinkError):
                    message = str(exc)
                else:
                    message = f"{type(exc).__name__}: {exc}"
                raise EventSinkError(f"child sink {index} failed: {message}") from exc


def _require_event(event: EventEnvelope) -> None:
    if not isinstance(event, EventEnvelope):
        raise EventSinkError("event must be an EventEnvelope")


def _require_sink(sink: EventSink) -> None:
    write = getattr(sink, "write", None)
    if not callable(write):
        raise EventSinkError("sink must provide a callable write(event) method")
