"""pydepgate.reporters.sarif.uris

URI scheme decisions for SARIF artifactLocation entries.

Pydepgate findings can carry three kinds of paths:

  1. Real on-disk paths (loose-file scan, --single mode).
     These point at files the user has access to.

  2. Artifact-internal paths inside a wheel or sdist.
     These point at files inside an archive that may or may
     not exist on disk at the time of SARIF consumption.

  3. Synthetic decoded paths produced by the decode pass.
     These point at locations inside a decoded payload that
     never existed as a file. The marker is the substring
     '<decoded:' embedded in the path.

This module produces SARIF artifactLocation dicts for each
kind. The general entry point is make_artifact_location();
synthetic decoded paths constructed from typed inputs use
make_artifact_location_for_decoded() instead.

URI form decisions:

  Real paths and artifact-internal paths are emitted as
  forward-slash relative URIs. GitHub resolves these against
  the repository root by default, or against the
  originalUriBaseIds.PROJECTROOT entry if the document
  declares one (controlled by the optional use_srcroot
  parameter).

  Synthetic decoded paths use the 'pydepgate-decoded:' URI
  scheme followed by the parent path (URL-encoded) and an
  optional query string carrying decode coordinates. This
  is honest about the location being virtual: GitHub will
  display the URI text but will not attempt to link to a
  file. The URI scheme is unique to pydepgate so consumers
  can recognize and special-case it if they wish.

Example URIs:

  Real:       'litellm/_init_.py'
  With root:  {'uri': 'setup.py', 'uriBaseId': 'PROJECTROOT'}
  Decoded:    'pydepgate-decoded:setup.py?layer=1&line=7'
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

# The URI scheme for synthetic decoded payload locations.
# Distinctive enough that consumers can pattern-match on it
# to detect virtual paths.
DECODED_URI_SCHEME = "pydepgate-decoded"

# The originalUriBaseIds key used when the user provides a
# srcroot via the --sarif-srcroot CLI flag (Phase F).
SRCROOT_BASE_ID = "PROJECTROOT"

# Substring that identifies a synthetic decoded path. The
# decode pass embeds this marker when constructing virtual
# paths for nodes inside a decoded payload chain.
_DECODED_MARKER = "<decoded:"


def make_artifact_location(
    internal_path: str,
    use_srcroot: bool = False,
) -> dict[str, str]:
    """Build a SARIF artifactLocation dict for a real path.

    Real paths cover both on-disk files (loose-file scans)
    and artifact-internal paths (wheel/sdist scans). Both
    are normalized to forward-slash relative URIs.

    Synthetic decoded paths (containing '<decoded:') are
    routed to a dedicated URI scheme; callers should detect
    these and use make_artifact_location_for_decoded()
    directly when they have access to typed coordinates.
    For callers that only have the synthetic path string, a
    best-effort encoding is produced.

    Args:
        internal_path: the path to encode. Forward slashes
            and backslashes are both accepted; backslashes
            are normalized to forward slashes. Leading
            slashes are stripped to produce a relative URI.
        use_srcroot: when True, include uriBaseId
            referencing PROJECTROOT. The caller is
            responsible for ensuring the document declares
            originalUriBaseIds.PROJECTROOT when this is set.

    Returns:
        A dict with 'uri' and optionally 'uriBaseId'. Safe
        to embed directly as the artifactLocation in a
        SARIF physicalLocation.
    """
    if _DECODED_MARKER in internal_path:
        # Caller passed a synthetic path string. Produce a
        # best-effort decoded URI without parsed
        # coordinates. Phase D code paths should prefer
        # make_artifact_location_for_decoded() for richer
        # output.
        encoded = quote(_normalize_path(internal_path), safe="/")
        return {"uri": f"{DECODED_URI_SCHEME}:{encoded}"}

    location: dict[str, str] = {"uri": _normalize_path(internal_path)}
    if use_srcroot:
        location["uriBaseId"] = SRCROOT_BASE_ID
    return location


def make_artifact_location_for_decoded(
    parent_path: str,
    coords: dict[str, Any],
) -> dict[str, str]:
    """Build a SARIF artifactLocation for a synthetic decoded location.

    Decoded locations represent positions inside a payload
    that was extracted at runtime from another file. They
    have no on-disk existence and cannot be linked to by
    GitHub.

    Args:
        parent_path: the path of the file the decoded
            content was extracted from. Backslashes are
            normalized to forward slashes; leading slashes
            are stripped.
        coords: a dict of coordinate key/value pairs
            describing the position inside the decoded
            payload. Common keys are 'layer' (the recursion
            depth), 'line' (the line within the decoded
            content). Values are coerced to strings via
            str(). An empty dict produces a URI with no
            query string.

    Returns:
        A dict with a single 'uri' entry. Synthetic
        locations never receive a uriBaseId because they
        are not relative to any project root.
    """
    encoded_parent = quote(_normalize_path(parent_path), safe="/")
    if not coords:
        return {"uri": f"{DECODED_URI_SCHEME}:{encoded_parent}"}

    query_parts = [
        f"{quote(str(key))}={quote(str(value))}" for key, value in coords.items()
    ]
    query = "&".join(query_parts)
    return {"uri": f"{DECODED_URI_SCHEME}:{encoded_parent}?{query}"}


def _normalize_path(path: str) -> str:
    """Normalize a path for embedding in a SARIF URI.

    The normalization rules:
      - Backslashes become forward slashes.
      - Leading slashes are stripped (so the result is
        always relative).
      - The path is otherwise preserved verbatim.

    URL encoding happens at the call site; this function
    only handles separator and root normalization.
    """
    normalized = path.replace("\\", "/")
    while normalized.startswith("/"):
        normalized = normalized[1:]
    return normalized
