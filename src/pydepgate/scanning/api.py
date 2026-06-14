"""pydepgate.scanning.api

Internal scan API contracts.

These types sit below the CLI and public facade. They describe scanner work in
plain Python objects so the CLI, future daemons, workplan, and public API can
share the same execution path without passing argparse objects around.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from pydepgate.events.freeze import DeepFreezeError, FrozenMapping, deep_freeze


class ScanApiContractError(ValueError):
    """Raised when a scan API object is not well formed."""


@dataclass(frozen=True, slots=True)
class ScanTargetRef:
    """Reference to scan material.

    identity is the security-facing name for the target. location is how this
    process can access it. For local CLI scans these are often the same string.
    Future intake, warehouse, and explorer paths can keep a stable identity while
    pointing location at a cached artifact or blob reference.
    """

    kind: str
    identity: str
    location: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_string(self.kind, "kind")
        _require_non_empty_string(self.identity, "identity")
        if self.location is not None:
            _require_non_empty_string(self.location, "location")
        if not isinstance(self.metadata, Mapping):
            raise ScanApiContractError("metadata must be a mapping")
        try:
            frozen = deep_freeze(dict(self.metadata))
        except DeepFreezeError as exc:
            raise ScanApiContractError(str(exc)) from exc
        object.__setattr__(self, "metadata", frozen)

    @property
    def access_location(self) -> str:
        """Return the location to pass to a scanner."""
        return self.location if self.location is not None else self.identity

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for event payloads."""
        return {
            "kind": self.kind,
            "identity": self.identity,
            "location": self.location,
            "metadata": _plain_mapping(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class EvidenceWriteResult:
    """Result of a local evidence write attempt."""

    ok: bool
    scan_run_id: int | None = None
    artifact_id: int | None = None
    error_type: str | None = None
    error_message: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.ok, bool):
            raise ScanApiContractError("ok must be a bool")
        if self.error_type is not None:
            _require_non_empty_string(self.error_type, "error_type")
        if self.error_message is not None:
            _require_non_empty_string(self.error_message, "error_message")


def _require_non_empty_string(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ScanApiContractError(f"{field_name} must be a non-empty string")


def _plain_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, item in value.items():
        if isinstance(item, Mapping):
            out[str(key)] = _plain_mapping(item)
        elif isinstance(item, tuple):
            out[str(key)] = list(item)
        elif isinstance(item, frozenset):
            out[str(key)] = sorted(item)
        else:
            out[str(key)] = item
    return out


__all__ = [
    "EvidenceWriteResult",
    "FrozenMapping",
    "ScanApiContractError",
    "ScanTargetRef",
]
