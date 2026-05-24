"""pydepgate.run_context

Per-invocation run UUID for forensic correlation across pydepgate's subsystems.
A single UUID7 is generated on first access during a Python process lifetime
and returned identically by all subsequent calls.

This ID ties together everything pydepgate does during one invocation:
SARIF run identifiers (automationDetails.id), scan findings, import operations,
audit logs (when those land), and any future cross-subsystem correlation surface.

Public API:
    get_current_run_uuid() -> str
        Return the run UUID for this Python process. Lazy-generated on first call;
        cached thereafter.
    reset_for_new_run() -> str
        Discard the cached UUID and generate a new one. Returns the new value.

The UUID format is exactly what str(uuid.uuid7()) produces: 36 characters,
lowercase hex, hyphen-separated. This format is part of the public contract.

Thread safety: the first-call generation is guarded by a lock so two threads
racing on first access observe a single shared UUID. After the first call
returns, reads are lock-free (a plain attribute load on a module-level
variable is atomic under CPython's GIL).
"""

from __future__ import annotations

import os
import threading
import time

_lock = threading.Lock()
_current_run_uuid: str | None = None


def _generate_uuid7_str() -> str:
    """Generate a raw RFC 9562 UUIDv7 string using standard library tools.

    Layout: 48-bit timestamp + 4-bit version (7) + 12-bit rand + 2-bit variant (2) + 62-bit rand
    """
    # 1. 48-bit Unix timestamp in milliseconds
    ms_timestamp = int(time.time() * 1000) & 0xFFFFFFFFFFFF

    # 2. 10 bytes (80 bits) of secure randomness
    rand_bytes = os.urandom(10)

    # 3. Construct 128-bit integer sequence
    # Extract random bits for the two distinct entropy fields
    rand_a = int.from_bytes(rand_bytes[:2], "big") & 0x0FFF
    rand_b = int.from_bytes(rand_bytes[2:], "big") & 0x3FFFFFFFFFFFFFFF

    # Assemble using standard bitwise shifts
    uuid_int = (
        (ms_timestamp << 80)
        | (0x7000 << 64)  # Version 7
        | (rand_a << 64)
        | (0x8000000000000000)  # Variant 2 (RFC 4122)
        | rand_b
    )

    # 4. Format to standard 8-4-4-4-12 hex representation
    hex_str = f"{uuid_int:032x}"
    return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:]}"


def get_current_run_uuid() -> str:
    """Return the run UUID for this Python process.

    On first call, generates a new UUID7 and caches it.
    All subsequent calls return the same value until reset_for_new_run is invoked.

    Returns:
        A 36-character lowercase hex UUID7 string with hyphens.
    """
    global _current_run_uuid

    # Fast path: already generated. Module-level attribute reads
    # are atomic under CPython's GIL, so no lock is needed here.
    if _current_run_uuid is not None:
        return _current_run_uuid

    # Slow path: first call, acquire lock to serialize generation.
    # The double-check inside the lock handles the case where
    # another thread generated while we were waiting.
    with _lock:
        if _current_run_uuid is None:
            _current_run_uuid = _generate_uuid7_str()
        return _current_run_uuid


def reset_for_new_run() -> str:
    """Generate a fresh run UUID, discarding the previous one.

    Returns the new UUID. Use this in:
    - Test setUp: each test should run with a fresh UUID.
    - Daemon mode: when one Python process serves multiple logical runs.

    Returns:
        The newly generated UUID7 string.
    """
    global _current_run_uuid
    with _lock:
        _current_run_uuid = _generate_uuid7_str()
        return _current_run_uuid
