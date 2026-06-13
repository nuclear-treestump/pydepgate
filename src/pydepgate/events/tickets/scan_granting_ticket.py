"""Scan Granting Ticket primitives.

A ScanGrantingTicket is an immutable authorization record for scanner work. In
local CLI mode, mintsgt records local process and stack evidence before issuing
a ticket. The local evidence is provenance, not cryptographic authentication.
Daemon mode can later replace that provenance with stronger caller identity.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import os
import secrets
import sys
from typing import Any

from pydepgate.events.freeze import DeepFreezeError, deep_freeze
from pydepgate.events.serialization import (
    EventSerializationError,
    stable_json_dumps,
    stable_sha256_json,
    to_jsonable,
)
from pydepgate.run_context import _generate_uuid7_str, get_current_run_uuid

_DEFAULT_TTL_SECONDS = 900
_DEFAULT_ALLOWED_ACTIONS = ("scan",)


class ScanGrantingTicketError(ValueError):
    """Raised when a scan granting ticket cannot be created safely."""


class LocalInvocationError(ScanGrantingTicketError):
    """Raised when local CLI provenance checks fail."""


@dataclass(frozen=True, slots=True)
class ScanGrantingTicket:
    """Immutable authorization record for a pydepgate scan."""

    ticket_id: str = field(default_factory=lambda: f"sgt_{_generate_uuid7_str()}")
    ticket_nonce: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    run_id: str = field(default_factory=get_current_run_uuid)
    correlation_id: str | None = None
    issuer: str = "pydepgate.local_cli"
    actor: str = "local-user"
    target_kind: str = "unknown"
    target_identity: str | None = None
    scan_mode: str = "static"
    allowed_actions: Iterable[str] = field(
        default_factory=lambda: _DEFAULT_ALLOWED_ACTIONS
    )
    issued_at: str = field(default_factory=_utc_now)
    expires_at: str | None = None
    policy_fingerprint: str | None = None
    ruleset_fingerprint: str | None = None
    budget: Mapping[str, Any] = field(default_factory=dict)
    local_invocation: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    ticket_digest: str = field(init=False)

    def __post_init__(self) -> None:
        for field_name in (
            "ticket_id",
            "ticket_nonce",
            "run_id",
            "issuer",
            "actor",
            "target_kind",
            "scan_mode",
            "issued_at",
        ):
            _require_non_empty_string(getattr(self, field_name), field_name)

        if self.correlation_id is None:
            object.__setattr__(self, "correlation_id", self.run_id)
        else:
            _require_non_empty_string(self.correlation_id, "correlation_id")

        for field_name in (
            "target_identity",
            "expires_at",
            "policy_fingerprint",
            "ruleset_fingerprint",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _require_non_empty_string(value, field_name)

        if isinstance(self.allowed_actions, str):
            raise ScanGrantingTicketError(
                "allowed_actions must be an iterable of action strings"
            )
        actions = tuple(self.allowed_actions)
        if not actions:
            raise ScanGrantingTicketError("allowed_actions must not be empty")
        for action in actions:
            _require_non_empty_string(action, "allowed_actions item")
        object.__setattr__(self, "allowed_actions", actions)

        if self.expires_at is None:
            issued_at = _parse_utc(self.issued_at, "issued_at")
            expires_at = issued_at + timedelta(seconds=_DEFAULT_TTL_SECONDS)
            object.__setattr__(self, "expires_at", _format_utc(expires_at))
        else:
            _parse_utc(self.expires_at, "expires_at")

        for field_name in ("budget", "local_invocation", "metadata"):
            value = getattr(self, field_name)
            if not isinstance(value, Mapping):
                raise ScanGrantingTicketError(f"{field_name} must be a mapping")
            try:
                frozen = deep_freeze(dict(value))
            except DeepFreezeError as exc:
                raise ScanGrantingTicketError(str(exc)) from exc
            object.__setattr__(self, field_name, frozen)

        try:
            digest = stable_sha256_json(self._digest_source_dict())
        except EventSerializationError as exc:
            raise ScanGrantingTicketError(str(exc)) from exc
        object.__setattr__(self, "ticket_digest", digest)

    def allows_action(self, action: str) -> bool:
        """Return True when this ticket authorizes the requested action."""
        return action in self.allowed_actions

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return True when the ticket expiry time has passed."""
        if now is None:
            now = datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        expiry = _parse_utc(self.expires_at, "expires_at")
        return now >= expiry

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible dictionary for this ticket."""
        output = self._digest_source_dict()
        output["ticket_digest"] = self.ticket_digest
        return output

    def to_json(self) -> str:
        """Return deterministic JSON for this ticket."""
        return stable_json_dumps(self.to_dict())

    def _digest_source_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "ticket_nonce": self.ticket_nonce,
            "run_id": self.run_id,
            "correlation_id": self.correlation_id,
            "issuer": self.issuer,
            "actor": self.actor,
            "target_kind": self.target_kind,
            "target_identity": self.target_identity,
            "scan_mode": self.scan_mode,
            "allowed_actions": list(self.allowed_actions),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "policy_fingerprint": self.policy_fingerprint,
            "ruleset_fingerprint": self.ruleset_fingerprint,
            "budget": to_jsonable(self.budget),
            "local_invocation": to_jsonable(self.local_invocation),
            "metadata": to_jsonable(self.metadata),
        }


def mintsgt(
    *,
    target_kind: str = "unknown",
    target_identity: str | None = None,
    scan_mode: str = "static",
    allowed_actions: Iterable[str] = _DEFAULT_ALLOWED_ACTIONS,
    policy_fingerprint: str | None = None,
    ruleset_fingerprint: str | None = None,
    budget: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    issuer: str = "pydepgate.local_cli",
    actor: str = "local-user",
    run_id: str | None = None,
    correlation_id: str | None = None,
    require_cli_stack: bool = False,
) -> ScanGrantingTicket:
    """Mint a local Scan Granting Ticket for scanner work."""
    if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
        raise ScanGrantingTicketError("ttl_seconds must be a positive integer")

    issued = datetime.now(timezone.utc)
    expires = issued + timedelta(seconds=ttl_seconds)
    invocation = _collect_local_invocation_evidence()

    if require_cli_stack and not invocation["has_pydepgate_cli_frame"]:
        raise LocalInvocationError("no pydepgate CLI frame found in call stack")

    return ScanGrantingTicket(
        run_id=run_id or get_current_run_uuid(),
        correlation_id=correlation_id,
        issuer=issuer,
        actor=actor,
        target_kind=target_kind,
        target_identity=target_identity,
        scan_mode=scan_mode,
        allowed_actions=allowed_actions,
        issued_at=_format_utc(issued),
        expires_at=_format_utc(expires),
        policy_fingerprint=policy_fingerprint,
        ruleset_fingerprint=ruleset_fingerprint,
        budget=budget or {},
        local_invocation=invocation,
        metadata=metadata or {},
    )


def _collect_local_invocation_evidence(max_depth: int = 48) -> dict[str, Any]:
    modules: list[str] = []
    functions: list[str] = []
    frame = inspect.currentframe()
    depth = 0

    try:
        while frame is not None and depth < max_depth:
            module_name = str(frame.f_globals.get("__name__", ""))
            function_name = str(frame.f_code.co_name)
            modules.append(module_name)
            functions.append(function_name)
            frame = frame.f_back
            depth += 1
    finally:
        del frame

    argv = tuple(sys.argv)
    argv_digest = hashlib.sha256("\x00".join(argv).encode("utf-8")).hexdigest()

    return {
        "process_id": os.getpid(),
        "parent_process_id": os.getppid(),
        "python_executable": sys.executable,
        "argv0": argv[0] if argv else "",
        "argv_digest": argv_digest,
        "stack_depth_observed": len(modules),
        "stack_modules": tuple(modules),
        "stack_functions": tuple(functions),
        "has_pydepgate_frame": any(
            module == "pydepgate" or module.startswith("pydepgate.")
            for module in modules
        ),
        "has_pydepgate_cli_frame": any(
            module == "pydepgate.cli" or module.startswith("pydepgate.cli.")
            for module in modules
        ),
    }


def _utc_now() -> str:
    return _format_utc(datetime.now(timezone.utc))


def _format_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc(value: str | None, field_name: str) -> datetime:
    if value is None:
        raise ScanGrantingTicketError(f"{field_name} must not be None")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScanGrantingTicketError(f"{field_name} must be an ISO timestamp") from exc


def _require_non_empty_string(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ScanGrantingTicketError(f"{field_name} must be a non-empty string")
