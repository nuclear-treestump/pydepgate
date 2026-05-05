"""pydepgate.reporters.decoded_tree.iocs

IOC hash renderer for pydepgate DecodedTree.

Emits hash records for forensic correlation, formatted for
grep/awk consumption. Each hash line has a fixed two-token
shape so a one-liner like:

    grep '^decoded_sha256' iocs.txt | awk '{print $2}'

extracts every decoded-payload hash.

This module exposes a single public function: render(). Callers
import the module and dispatch via it:

    from pydepgate.reporters.decoded_tree import iocs as tree_iocs
    tree_iocs.render(tree)
"""

from __future__ import annotations

from pydepgate.enrichers.decode_payloads import DecodedNode, DecodedTree
from pydepgate.reporters.decoded_tree._helpers import (
    _node_file_hash_equals_artifact,
    _signal_repr,
)


def render(tree: DecodedTree) -> str:
    """Render hash records for forensic correlation.

    Output structure:

      Header block (always emitted when artifact hashes are
      populated):
        artifact identity, SHA256, SHA512, scan timestamp.

      Per-IOC blocks (one per node with ioc_data):
        location, signal IDs, chain summary, containing-file hash
        (when meaningfully different from artifact hash), and the
        original/decoded payload hashes from IOCData.

    Hash lines have a fixed two-token shape so a one-liner like
        grep '^decoded_sha256' iocs.txt | awk '{print $2}'
    extracts every decoded-payload hash.

    Empty tree or tree with no ioc_data still emits the header
    block when artifact hashes are populated, then a stub. Phase 1
    work guarantees that DecodedTree always has artifact hashes if
    the originating ScanResult had them.
    """
    nodes_with_iocs: list[DecodedNode] = []

    def collect(node: DecodedNode) -> None:
        if node.ioc_data is not None:
            nodes_with_iocs.append(node)
        for child in node.children:
            collect(child)

    for node in tree.nodes:
        collect(node)

    lines: list[str] = []
    lines.append(f"# IOC hash records for {tree.target}")
    lines.append("# pydepgate decoded-payload IOCs")
    lines.append("# " + "=" * 63)
    lines.append("")

    # Artifact-identity header. Emitted when artifact hashes are
    # populated, regardless of whether nodes were found.
    if tree.artifact_sha256 or tree.artifact_sha512:
        lines.append(f"# artifact: {tree.target}")
        if tree.artifact_sha256:
            lines.append(f"artifact_sha256 {tree.artifact_sha256}")
        if tree.artifact_sha512:
            lines.append(f"artifact_sha512 {tree.artifact_sha512}")
        lines.append("")

    if not nodes_with_iocs:
        lines.append("# (no IOC data extracted; nothing to record)")
        lines.append("")
        return "\n".join(lines)

    for i, node in enumerate(nodes_with_iocs, 1):
        ioc = node.ioc_data
        lines.append(
            f"# IOC #{i}: {node.outer_location} ({_signal_repr(node)})"
        )
        if node.chain:
            chain_repr = " -> ".join(node.chain) + f" -> {node.final_kind}"
            lines.append(
                f"#   chain: {chain_repr} ({node.final_size} bytes)"
            )
        if ioc.extract_timestamp:
            lines.append(f"#   extracted: {ioc.extract_timestamp}")

        # Containing-file hash, when present AND different from
        # the artifact hash. For a --single loose-file scan, the
        # two are identical and emitting both is noise.
        if (
            node.containing_file_sha256
            and not _node_file_hash_equals_artifact(tree, node)
        ):
            lines.append(
                f"file_sha256 {node.containing_file_sha256}"
            )
        if (
            node.containing_file_sha512
            and not _node_file_hash_equals_artifact(tree, node)
        ):
            lines.append(
                f"file_sha512 {node.containing_file_sha512}"
            )

        if ioc.original_sha256:
            lines.append(f"original_sha256 {ioc.original_sha256}")
        if ioc.original_sha512:
            lines.append(f"original_sha512 {ioc.original_sha512}")
        if ioc.decoded_sha256:
            lines.append(f"decoded_sha256  {ioc.decoded_sha256}")
        if ioc.decoded_sha512:
            lines.append(f"decoded_sha512  {ioc.decoded_sha512}")
        lines.append("")

    return "\n".join(lines)