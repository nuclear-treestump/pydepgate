"""pydepgate.engines._hashes

Hash helpers for the static engine.

Centralizes SHA256 and SHA512 computation so every scan entry point
produces identically-formatted hashes for downstream consumers.

Why a separate module: the engine, the enumerators, and the decode
driver all need to hash bytes the same way. Inlining hashlib calls
in each location risks drift (hex vs bytes, lowercase vs uppercase,
SHA-256 vs SHA512 vs both). Centralizing produces one
authoritative implementation that's trivial to test.
"""

from __future__ import annotations

import hashlib


def hash_pair(content: bytes) -> tuple[str, str]:
    """Compute (SHA256, SHA512) hex digests for a byte string.

    Both digests are lowercase hex with no separators or prefixes,
    matching the format used in IOC sidecars and downstream tools
    (VirusTotal, MalwareBazaar, etc).

    Returns a 2-tuple so callers can unpack as
        sha256, sha512 = hash_pair(content)
    or stash both at once. Cost is one pass through the content
    per algorithm; on modern hardware, a 50MB wheel hashes in well
    under 100ms.
    """
    return (
        hashlib.sha256(content).hexdigest(),
        hashlib.sha512(content).hexdigest(),
    )