"""pydepgate.reporters.sarif.fingerprints

Computes SARIF partialFingerprints values that GitHub code
scanning uses to deduplicate alerts across runs.

Output format
-------------
The function returns a string of the form:

    {24-hex-character-digest}:1

where the trailing ':1' is the algorithm version. Future
algorithm changes bump this suffix to invalidate existing
fingerprints intentionally; consumers see new alert IDs and
the old alerts are closed by GitHub.

Hash inputs
-----------
The hash is taken over a pipe-separated concatenation of:

    rule_id              the SARIF result's ruleId
    normalized_path      forward-slash, leading-slash-stripped
    line                 the 1-based line number
    context_hash         a short hash of a content string

The context_hash is intended to be sourced from
signal.context['_full_value'] when available (the literal
matched value, which uniquely identifies what was found at
the location), or from the finding description as a
fallback. Callers are responsible for selecting an
appropriate context string; this module only hashes it.

Stability properties
--------------------
Identical inputs produce identical outputs across runs.
Different inputs produce different outputs with a 96-bit
collision space (24 hex characters = 96 bits), which is
vastly more than required at any plausible pydepgate scale
but provides headroom against hash collisions in the rare
case that two different findings happen to produce
colliding context strings.

The fingerprint survives:
  - Whitespace edits to OTHER lines in the same file.
  - Reordering of unrelated parts of the file.
  - Path-prefix changes that the path normalization absorbs.

The fingerprint does NOT survive:
  - Edits to the line itself (line content typically
    changes the context).
  - Renaming of the containing file.
  - Changes to the rule_id (a different signal_id).

This is the intended behavior: if any of those change, the
finding is meaningfully different and a new alert is the
correct outcome.

Algorithm width rationale
-------------------------
The CodeQL convention is 16 hex characters; pydepgate uses
24. GitHub does not parse the hex portion for length; it
treats the full pre-suffix string as an opaque equality
key. The wider hash adds 8 bytes per finding (negligible
against the 10MB compressed upload limit) in exchange for
2^32 times more collision space, which is cheap insurance.
"""

from __future__ import annotations

import hashlib

# The algorithm-version suffix. Bumping this string
# invalidates all prior fingerprints across consumer
# repositories; reserve for major algorithm changes only.
ALGORITHM_VERSION = "1"

# The number of leading hex characters from the SHA-256
# digest used as the fingerprint identifier. 24 hex chars
# equals 96 bits of collision space.
DIGEST_LENGTH = 24

# The number of leading hex characters from the SHA-256
# digest of the context string used as the context_hash
# component of the input. Short enough to keep the joined
# string compact, long enough to differentiate distinct
# context values.
CONTEXT_HASH_LENGTH = 8


def primary_location_line_hash(
    rule_id: str,
    internal_path: str,
    line: int,
    context: str,
) -> str:
    """Compute primaryLocationLineHash for a SARIF result.

    Args:
        rule_id: the SARIF rule identifier (typically a
            pydepgate signal_id, e.g., 'DENS010').
        internal_path: the path of the file containing the
            finding. Backslashes are normalized to forward
            slashes; leading slashes are stripped before
            hashing so the same logical location produces
            the same hash regardless of separator
            convention or absolute/relative form.
        line: the 1-based line number of the finding.
            Findings with line=0 (whole-file signals) are
            permitted; the line value is included in the
            hash so multiple whole-file signals on the same
            file produce different hashes only if their
            other inputs differ.
        context: a content string identifying what was
            found. Typically signal.context['_full_value']
            when populated by the analyzer (the literal
            matched value), otherwise the finding
            description. Empty strings are accepted but
            reduce collision resistance.

    Returns:
        A string of the form '{24hex}:1' suitable for use
        as the value of
        SARIF result.partialFingerprints.primaryLocationLineHash.
    """
    normalized_path = _normalize_path_for_hash(internal_path)
    context_hash = _hash_context(context)

    components = [rule_id, normalized_path, str(line), context_hash]
    joined = "|".join(components)
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:DIGEST_LENGTH]
    return f"{digest}:{ALGORITHM_VERSION}"


def _normalize_path_for_hash(path: str) -> str:
    """Normalize a path for inclusion in the fingerprint hash.

    Mirrors the URI normalization in uris._normalize_path()
    so that the same logical location always produces the
    same fingerprint, regardless of separator or
    leading-slash convention.
    """
    normalized = path.replace("\\", "/")
    while normalized.startswith("/"):
        normalized = normalized[1:]
    return normalized


def _hash_context(context: str) -> str:
    """Produce the short context hash component."""
    return hashlib.sha256(context.encode("utf-8")).hexdigest()[:CONTEXT_HASH_LENGTH]
