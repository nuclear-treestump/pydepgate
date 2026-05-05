"""pydepgate.reporters.decoded_tree._helpers

Private helpers shared across decoded_tree renderers.

Two functions used by multiple renderers in this package:

  _signal_repr(node) - Render the signal-id portion of a
      DecodedNode for output. When a dedup group has multiple
      triggering signals, returns them joined with '+';
      otherwise returns the primary signal_id alone. Used by
      text, sources, and iocs renderers.

  _node_file_hash_equals_artifact(tree, node) - True when a
      node's containing-file hash equals the artifact hash.
      Renderers use this to suppress redundant hash lines in
      single-file scans where artifact and containing file are
      the same bytes. Used by sources and iocs renderers.

These helpers stay private (underscore prefix) because they
are not part of the package's public API; they are an
implementation detail of how decoded_tree renderers cooperate.
"""

from __future__ import annotations

from pydepgate.enrichers.decode_payloads import DecodedNode, DecodedTree


def _signal_repr(node: DecodedNode) -> str:
    """Render the signal-id portion of a node for human-readable output."""
    if len(node.triggered_by) > 1:
        return "+".join(node.triggered_by)
    return node.outer_signal_id


def _node_file_hash_equals_artifact(
    tree: DecodedTree,
    node: DecodedNode,
) -> bool:
    """True when a node's containing-file hash equals the artifact hash.

    Used by renderers to suppress redundant lines in human output.
    For a loose-file scan (--single mode), the artifact and the
    containing file are the same bytes, so artifact_sha256 ==
    containing_file_sha256. Printing both lines is noise.
    Returns False when either hash is None (no dedup possible).
    """
    if tree.artifact_sha256 is None:
        return False
    if node.containing_file_sha256 is None:
        return False
    return tree.artifact_sha256 == node.containing_file_sha256