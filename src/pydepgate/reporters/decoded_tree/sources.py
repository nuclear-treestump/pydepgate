"""pydepgate.reporters.decoded_tree.sources

Decoded-source-dump renderer for pydepgate DecodedTree.

For each python_source terminal, emit a header block (location,
chain, containing-file context, hashes) followed by the decoded
source body, line-numbered. Other terminal kinds are skipped;
this renderer only emits what its name says.

Empty tree or tree with no python_source nodes still produces
the file with a short stub explaining why. This is intentional
so the file always exists with a defined shape inside the
archive layout.

This module exposes a single public function: render(). Callers
import the module and dispatch via it:

    from pydepgate.reporters.decoded_tree import sources as tree_sources
    tree_sources.render(tree)
"""

from __future__ import annotations

from pydepgate.enrichers.decode_payloads import DecodedNode, DecodedTree
from pydepgate.reporters.decoded_tree._helpers import (
    _node_file_hash_equals_artifact,
    _signal_repr,
)


def render(tree: DecodedTree) -> str:
    """Render decoded source code for python_source terminals.

    For each node that has ioc_data.decoded_source AND final_kind
    == 'python_source', emit a header block (location, chain,
    containing-file context, hashes) followed by the source body,
    line-numbered.

    Empty tree or tree with no python_source nodes produces a
    short stub explaining why; this is intentional so the file
    always exists with a defined shape inside the archive.

    The artifact-identity header is emitted at the top whenever
    artifact hashes are populated, matching iocs.render.
    """
    nodes_with_source: list[DecodedNode] = []

    def collect(node: DecodedNode) -> None:
        if (
            node.ioc_data is not None
            and node.ioc_data.decoded_source is not None
            and node.final_kind == "python_source"
        ):
            nodes_with_source.append(node)
        for child in node.children:
            collect(child)

    for node in tree.nodes:
        collect(node)

    lines: list[str] = []
    lines.append(f"# decoded source dumps for {tree.target}")
    lines.append("# " + "=" * 63)

    # Artifact-identity header.
    if tree.artifact_sha256 or tree.artifact_sha512:
        lines.append(f"# artifact: {tree.target}")
        if tree.artifact_sha256:
            lines.append(f"# artifact SHA256: {tree.artifact_sha256}")
        if tree.artifact_sha512:
            lines.append(f"# artifact SHA512: {tree.artifact_sha512}")
        lines.append("# " + "-" * 63)
    lines.append("")

    if not nodes_with_source:
        lines.append(
            "# (no decoded python_source terminals; no source extracted)"
        )
        lines.append("")
        return "\n".join(lines)

    for i, node in enumerate(nodes_with_source, 1):
        ioc = node.ioc_data
        lines.append(
            f"# Source #{i}: {node.outer_location} ({_signal_repr(node)})"
        )
        if node.chain:
            chain_repr = " -> ".join(node.chain) + f" -> {node.final_kind}"
            lines.append(f"# chain: {chain_repr} ({node.final_size} bytes)")

        # Containing-file context, when meaningfully different.
        if (
            node.containing_file_sha256
            and not _node_file_hash_equals_artifact(tree, node)
        ):
            lines.append(
                f"# containing file SHA256: {node.containing_file_sha256}"
            )

        if ioc.original_sha256:
            lines.append(f"# original SHA256: {ioc.original_sha256}")
        if ioc.decoded_sha256:
            lines.append(f"# decoded SHA256:  {ioc.decoded_sha256}")
        if ioc.extract_timestamp:
            lines.append(f"# extracted: {ioc.extract_timestamp}")
        lines.append("# " + "-" * 60)
        lines.append("")
        for line_num, source_line in enumerate(
            ioc.decoded_source.splitlines(), 1,
        ):
            lines.append(f"{line_num:5d}: {source_line}")
        lines.append("")
        lines.append("# " + "=" * 60)
        lines.append("")

    return "\n".join(lines)