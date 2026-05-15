"""pydepgate.run_context

Per-invocation run UUID for forensic correlation across pydepgate's
subsystems.

A single UUID4 is generated on first access during a Python process
lifetime and returned identically by all subsequent calls. This ID
ties together everything pydepgate does during one invocation:
SARIF run identifiers (automationDetails.id), scan findings, import
operations, audit logs (when those land), and any future cross-
subsystem correlation surface.

Public API:

    get_current_run_uuid() -> str
        Return the run UUID for this Python process. Lazy-generated
        on first call; cached thereafter.

    reset_for_new_run() -> str
        Discard the cached UUID and generate a new one. Returns the
        new value. Intended for test isolation (call in setUp so
        prior test state does not leak into the run ID) and for
        hypothetical daemon-mode use cases where one Python process
        serves multiple logical runs.

The UUID format is exactly what str(uuid.uuid4()) produces: 36
characters, lowercase hex, hyphen-separated. This format is part
of the public contract; downstream consumers (SARIF emission, the
cvedb metadata block, future log correlation tools) parse and
store it verbatim.

Thread safety: the first-call generation is guarded by a lock so
two threads racing on first access observe a single shared UUID.
After the first call returns, reads are lock-free (a plain
attribute load on a module-level variable is atomic under
CPython's GIL).

Why a module rather than a class: a class would require dependency-
injecting an instance through every subsystem that needs the UUID,
which means changing function signatures across the codebase. A
module-level function with cached state matches how everything
else in pydepgate is structured (paths.py, exit_codes.py, etc.)
and is callable from anywhere without ceremony.
"""

from __future__ import annotations

import threading
import uuid

_lock = threading.Lock()
_current_run_uuid: str | None = None


def get_current_run_uuid() -> str:
    """Return the run UUID for this Python process.

    On first call, generates a new UUID4 and caches it. All
    subsequent calls return the same value until reset_for_new_run
    is invoked.

    Returns:
        A 36-character lowercase hex UUID4 string with hyphens,
        e.g. "550e8400-e29b-41d4-a716-446655440000".
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
            _current_run_uuid = str(uuid.uuid4())
        return _current_run_uuid


def reset_for_new_run() -> str:
    """Generate a fresh run UUID, discarding the previous one.

    Returns the new UUID. Use this in:
      - Test setUp: each test should run with a fresh UUID so
        cross-test correlation does not appear in reports.
      - Daemon mode: when one Python process serves multiple
        logical runs, call this at the start of each run.

    Returns:
        The newly generated UUID4 string.
    """
    global _current_run_uuid
    with _lock:
        _current_run_uuid = str(uuid.uuid4())
        return _current_run_uuid
