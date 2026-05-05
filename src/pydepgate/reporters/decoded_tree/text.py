"""pydepgate.reporters.decoded_tree.text

Text renderer for pydepgate DecodedTree.

Emits the tree report in ASCII text suitable for the report
file. With include_iocs=True it also embeds an IOC section at
the bottom of the same output.

Most new callers should pass include_iocs=False and use the
sources and iocs renderers separately so the three pieces can
be packaged independently (plaintext, sidecar, archive
entries). The include_iocs=True path is retained for backward
compatibility with direct-API users.

This module exposes a single public function: render(). Callers
import the module and dispatch via it:

    from pydepgate.reporters.decoded_tree import text as tree_text
    tree_text.render(tree, include_iocs=False)
"""

from __future__ import annotations

from pydepgate.enrichers.decode_payloads import (
    DecodedNode,
    DecodedTree,
    STOP_DECODE_FAILED,
    STOP_DEPTH_LIMIT,
    STOP_NO_FULL_VALUE,
    STOP_NO_INNER_FINDINGS,
    STOP_NON_PYTHON,
)
from pydepgate.reporters.decoded_tree._helpers import _signal_repr


# Tree-drawing connector strings (private, text-only).
_T_BRANCH = "+-- "
_T_LAST   = "`-- "
_T_PIPE   = "|   "
_T_BLANK  = "    "


def render(tree: DecodedTree, *, include_iocs: bool = False) -> str:
    """Render the tree as ASCII text suitable for the report file."""
    lines: list[str] = []
    lines.append(f"decoded payload report for {tree.target}")
    lines.append(f"max recursion depth: {tree.max_depth}")
    if tree.artifact_sha256:
        lines.append(f"artifact SHA256: {tree.artifact_sha256}")
    if tree.artifact_sha512:
        lines.append(f"artifact SHA512: {tree.artifact_sha512}")
    lines.append("=" * 65)
    lines.append("")

    if not tree.nodes:
        lines.append("(no payload-bearing findings; nothing to decode)")
        if include_iocs:
            lines.append("")
            lines.extend(_render_ioc_section(tree))
        lines.append("")
        return "\n".join(lines)

    for i, node in enumerate(tree.nodes):
        _render_node_text(node, lines, prefix="", is_last=True, top_level=True)
        if i < len(tree.nodes) - 1:
            lines.append("")

    if include_iocs:
        lines.append("")
        lines.extend(_render_ioc_section(tree))

    lines.append("")
    return "\n".join(lines)


def _render_ioc_section(tree: DecodedTree) -> list[str]:
    """Render the IOC section (legacy embedded format)."""
    lines: list[str] = []
    lines.append("=" * 65)
    lines.append("IOC (INDICATORS OF COMPROMISE) SECTION")
    lines.append("=" * 65)
    lines.append("")

    nodes_with_iocs: list[DecodedNode] = []

    def collect_nodes(node: DecodedNode) -> None:
        if node.ioc_data is not None:
            nodes_with_iocs.append(node)
        for child in node.children:
            collect_nodes(child)

    for node in tree.nodes:
        collect_nodes(node)

    if not nodes_with_iocs:
        lines.append("(no IOC data extracted)")
        return lines

    for i, node in enumerate(nodes_with_iocs, 1):
        ioc = node.ioc_data
        lines.append(
            f"IOC #{i}: {node.outer_location} ({_signal_repr(node)})"
        )
        lines.append("-" * 60)

        if ioc.extract_timestamp:
            lines.append(f"Extracted: {ioc.extract_timestamp}")
            lines.append("")

        lines.append("PAYLOAD HASHES:")
        if ioc.original_sha256:
            lines.append(f"  Original SHA256: {ioc.original_sha256}")
        if ioc.original_sha512:
            lines.append(f"  Original SHA512: {ioc.original_sha512}")
        if ioc.decoded_sha256:
            lines.append(f"  Decoded SHA256:  {ioc.decoded_sha256}")
        if ioc.decoded_sha512:
            lines.append(f"  Decoded SHA512:  {ioc.decoded_sha512}")
        lines.append("")

        if ioc.decoded_source and node.final_kind == "python_source":
            lines.append("DECODED SOURCE CODE:")
            lines.append("-" * 40)
            for line_num, source_line in enumerate(
                ioc.decoded_source.splitlines(), 1,
            ):
                lines.append(f"{line_num:4d}: {source_line}")
            lines.append("-" * 40)
        elif node.final_kind != "python_source":
            lines.append(f"NON-PYTHON PAYLOAD: {node.final_kind}")
            lines.append(f"Size: {node.final_size} bytes")
            if node.indicators:
                lines.append(f"Indicators: {', '.join(node.indicators)}")

        if i < len(nodes_with_iocs):
            lines.append("")
            lines.append("")

    return lines


def _render_der_details(
    lines: list[str],
    body_prefix: str,
    summary: dict,
) -> None:
    """Emit a compact DER classification block.

    Format:

        DER: x509_certificate, RSA-2048
          subject CN: pem.example.com
          issuer CN:  pem.example.com
          validity:   2025-01-01 to 2026-01-01
          SAN:        dns:foo.example, dns:bar.example
          anomalies:  2

    Each line uses `body_prefix + "  "` so the whole block sits
    indented one level under the chain line. Fields that are None
    or absent in the summary dict are skipped silently rather than
    rendering as "subject CN: None".
    """
    kind = summary.get("kind", "unknown")
    bit_size = summary.get("bit_size")
    bit_str = f", {bit_size}-bit" if bit_size else ""
    lines.append(f"{body_prefix}DER: {kind}{bit_str}")

    inner = body_prefix + "  "

    if summary.get("subject_cn"):
        lines.append(f"{inner}subject CN: {summary['subject_cn']}")
    if summary.get("issuer_cn"):
        lines.append(f"{inner}issuer CN:  {summary['issuer_cn']}")
    if summary.get("not_before") and summary.get("not_after"):
        lines.append(
            f"{inner}validity:   "
            f"{summary['not_before']} to {summary['not_after']}"
        )
    if summary.get("serial"):
        lines.append(f"{inner}serial:     {summary['serial']}")
    if summary.get("signature_oid"):
        lines.append(
            f"{inner}sig OID:    {summary['signature_oid']}"
        )

    san_summary = summary.get("san_summary")
    if san_summary:
        if len(san_summary) <= 3:
            san_str = ", ".join(san_summary)
        else:
            san_str = (
                f"{', '.join(san_summary[:3])} "
                f"(+{len(san_summary) - 3} more)"
            )
        lines.append(f"{inner}SAN:        {san_str}")

    extension_oids = summary.get("extension_oids")
    if extension_oids:
        critical_count = sum(
            1 for e in extension_oids if e.get("critical")
        )
        ext_str = f"{len(extension_oids)} total"
        if critical_count:
            ext_str += f" ({critical_count} critical)"
        lines.append(f"{inner}extensions: {ext_str}")

    anomaly_count = summary.get("anomaly_count", 0)
    if anomaly_count > 0:
        lines.append(f"{inner}anomalies:  {anomaly_count}")


def _render_node_text(
    node: DecodedNode,
    lines: list[str],
    *,
    prefix: str,
    is_last: bool,
    top_level: bool,
) -> None:
    """Append text-rendered lines for one node into `lines`."""
    if top_level:
        lines.append(
            f"{node.outer_location} ({_signal_repr(node)}, "
            f"length {node.outer_length})"
        )
        body_prefix = "    "
    else:
        connector = _T_LAST if is_last else _T_BRANCH
        loc_parts = node.outer_location.split(":")
        loc_tail = (
            f"{loc_parts[-2]}:{loc_parts[-1]}"
            if len(loc_parts) >= 2
            else node.outer_location
        )
        lines.append(
            f"{prefix}{connector}"
            f"{_signal_repr(node)} {node.outer_severity} "
            f"at line {loc_tail}"
        )
        body_prefix = prefix + (_T_BLANK if is_last else _T_PIPE)

    if node.chain:
        chain_repr = " -> ".join(node.chain) + f" -> {node.final_kind}"
        lines.append(
            f"{body_prefix}chain: {chain_repr} "
            f"({node.final_size} bytes)"
        )
    else:
        lines.append(f"{body_prefix}chain: (no transforms applied)")

    if node.indicators:
        lines.append(
            f"{body_prefix}indicators: {', '.join(node.indicators)}"
        )

    if node.pickle_warning:
        lines.append(
            f"{body_prefix}WARNING: payload is a Python pickle "
            "stream (NOT deserialized)"
        )
    # DER classification block (currently the only structured details
    # emitter; future formats will plug in here).
    if node.details_summary is not None:
        _render_der_details(lines, body_prefix, node.details_full or node.details_summary)

    if node.stop_reason == STOP_DEPTH_LIMIT:
        lines.append(
            f"{body_prefix}(stopped: recursion depth limit reached)"
        )
    elif node.stop_reason == STOP_NON_PYTHON:
        # When we have structured details, the stop reason should
        # reflect that we DID classify the terminal, just that DER
        # is not Python and recursion stops there.
        if node.details_summary is not None:
            kind = node.details_summary.get("kind", "unknown")
            lines.append(
                f"{body_prefix}(stopped: structured {kind} terminal, "
                f"no Python recursion)"
            )
        else:
            lines.append(
                f"{body_prefix}(stopped: terminal is "
                f"{node.final_kind}, not Python source)"
            )
    elif node.stop_reason == STOP_DECODE_FAILED:
        lines.append(
            f"{body_prefix}(stopped: decode failed with status "
            f"{node.unwrap_status})"
        )
    elif node.stop_reason == STOP_NO_FULL_VALUE:
        lines.append(
            f"{body_prefix}(stopped: outer signal had no full value "
            f"to decode)"
        )
    elif node.stop_reason == STOP_NO_INNER_FINDINGS:
        lines.append(
            f"{body_prefix}(decoded successfully but inner scan "
            f"produced no findings)"
        )

    if node.child_findings:
        lines.append(f"{body_prefix}inner findings:")
        for cf in node.child_findings:
            lines.append(
                f"{body_prefix}  - {cf.signal_id} {cf.severity} "
                f"at line {cf.line}:{cf.column}: {cf.description}"
            )

    if node.children:
        if not node.child_findings:
            lines.append(f"{body_prefix}inner findings:")
        for i, child in enumerate(node.children):
            child_is_last = (i == len(node.children) - 1)
            _render_node_text(
                child,
                lines,
                prefix=body_prefix + "  ",
                is_last=child_is_last,
                top_level=False,
            )