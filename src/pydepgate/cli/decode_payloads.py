"""
Driver for the --decode-payload-depth feature.

Given a ScanResult from the engine and an enabled peek enricher, this
module finds payload-bearing findings, decodes each one into the bytes
its peek chain produced, re-runs the scan engine over those bytes
(forcing the same FileKind as the outer finding), and recurses on
findings from that re-scan. The result is a tree mirroring the
discovery path; each node records what was decoded, what was found
inside, and where the recursion stopped.

The driver lives in cli/ rather than enrichers/ because it composes
the engine with the peek enricher's output rather than being itself
an enricher. It runs after the main scan completes, in the
orchestrator process; no new picklability constraints.

Public surface:

    decode_payloads(result, *, engine, file_kind_for_finding,
                    max_depth, peek_min_length, peek_max_depth,
                    peek_max_budget) -> DecodedTree
        Run the recursion. Returns the tree (possibly empty).

    render_text(tree) -> str
    render_json(tree) -> str
        Format the tree for the report file.

    DecodedTree, DecodedNode, ChildResult, StopReason
        Public data types.

The engine is called via _scan_one_file rather than scan_bytes
because scan_bytes does not expose a forced_file_kind parameter and
the user explicitly wants the outer finding's file_kind to carry
through to the inner scan. This is a deliberate use of the engine's
"private" entry point; the FileScanInput / FileScanOutput pair is the
documented picklable boundary and is stable across engine versions.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from pydepgate.engines.base import (
    ArtifactKind,
    FileScanInput,
    Finding,
    ScanResult,
)
from pydepgate.engines.static import StaticEngine
from pydepgate.enrichers._unwrap import (
    Layer,
    STATUS_COMPLETED,
    STATUS_DECODE_ERROR,
    STATUS_EXHAUSTED_BUDGET,
    STATUS_EXHAUSTED_DEPTH,
    STATUS_LOOP_DETECTED,
    UnwrapResult,
    unwrap,
)
from pydepgate.traffic_control.triage import FileKind


# ---------------------------------------------------------------------------
# Tree types
# ---------------------------------------------------------------------------

# Stop-reason constants. A node's stop_reason explains why we did not
# recurse further from that node. Used by the formatters to render the
# correct annotation. Constants rather than an Enum for JSON-friendliness.
STOP_DEPTH_LIMIT = "depth_limit_reached"
STOP_NON_PYTHON = "non_python_terminal"
STOP_DECODE_FAILED = "decode_failed"
STOP_NO_FULL_VALUE = "no_full_value"
STOP_NO_INNER_FINDINGS = "no_inner_findings"
STOP_LEAF_TERMINAL = "leaf_terminal"


@dataclass(frozen=True)
class IOCData:
    """IOC (Indicators of Compromise) for a decoded payload.
    
    Contains hashes and metadata for threat intelligence and
    forensic analysis. All fields are optional - missing data
    is represented as None rather than empty strings.
    
    Attributes:
        original_sha256: SHA256 of the original encoded payload
            (_full_value as provided to unwrap).
        original_sha512: SHA512 of the original encoded payload.
        decoded_sha256: SHA256 of the final decoded bytes.
        decoded_sha512: SHA512 of the final decoded bytes.
        decoded_source: The decoded source code when final_kind
            is python_source. None for non-Python terminals.
        extract_timestamp: ISO timestamp when extraction occurred.
    """
    original_sha256: str | None = None
    original_sha512: str | None = None
    decoded_sha256: str | None = None
    decoded_sha512: str | None = None
    decoded_source: str | None = None
    extract_timestamp: str | None = None


@dataclass(frozen=True)
class ChildFinding:
    """One finding observed inside a decoded layer.

    Distinct from `pydepgate.engines.base.Finding`: this is the
    flattened view emitted into the report, with just the fields
    a reader of the report needs. The full Finding is preserved
    on the parent DecodedNode if a downstream consumer wants it.
    """
    signal_id: str
    severity: str
    line: int
    column: int
    description: str


@dataclass(frozen=True)
class DecodedNode:
    """One node in the decoded-payload tree.

    A node represents one finding (the "outer" finding) whose payload
    was decoded once. Its children are nodes for findings observed
    inside the decoded form, when those findings themselves bear
    payloads.

    Attributes:
        outer_signal_id: signal_id of the finding that triggered
            this decode pass.
        outer_severity: severity string for the outer finding.
        outer_location: Path:line column of the outer finding.
        outer_length: The length value from the outer finding's
            context (the raw size of the payload literal).
        chain: Tuple of layer kinds that successfully decoded.
        unwrap_status: One of the STATUS_* constants from
            pydepgate.enrichers._unwrap.
        final_kind: Terminal classification of the decoded form.
        final_size: Size of the decoded final form, in bytes.
        indicators: Indicator strings observed in the decoded form
            (for python_source / ascii_text terminals).
        pickle_warning: True iff the chain ended at a pickle.
        depth: Recursion depth at which this node was reached (0 is
            the outermost node).
        stop_reason: Why we did not recurse from this node.
        child_findings: Findings from re-scanning the decoded bytes
            that did NOT themselves trigger further recursion.
            Includes leaf signals (STDLIB001, DYN002, etc).
        children: Sub-nodes for findings whose payloads were
            themselves decoded.
        ioc_data: IOC data when IOC extraction is enabled, None
            otherwise.
    """
    outer_signal_id: str
    outer_severity: str
    outer_location: str
    outer_length: int
    chain: tuple[str, ...]
    unwrap_status: str
    final_kind: str
    final_size: int
    indicators: tuple[str, ...]
    pickle_warning: bool
    depth: int
    stop_reason: str
    child_findings: tuple[ChildFinding, ...] = ()
    children: tuple["DecodedNode", ...] = ()
    ioc_data: IOCData | None = None


@dataclass(frozen=True)
class DecodedTree:
    """The full result of a decoded-payload pass.

    Attributes:
        target: The artifact identity from the original scan.
        max_depth: The configured recursion ceiling.
        nodes: Top-level decoded nodes (one per outer payload-bearing
            finding).
    """
    target: str
    max_depth: int
    nodes: tuple[DecodedNode, ...]


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def decode_payloads(
    result: ScanResult,
    *,
    engine: StaticEngine,
    max_depth: int,
    peek_min_length: int,
    peek_max_depth: int,
    peek_max_budget: int,
    extract_iocs: bool = False,
) -> DecodedTree:
    """Run the decoded-payload recursion.

    Args:
        result: ScanResult from the main scan. Iterated for findings
            whose context carries a `_full_value` and a `decoded`
            block (which means peek processed them).
        engine: The same StaticEngine used for the main scan, with
            the peek enricher attached. The driver re-invokes it on
            decoded bytes via _scan_one_file.
        max_depth: Recursion ceiling. depth==0 means no recursion
            (still produces a tree of leaf nodes).
        peek_min_length: Min-length threshold used when re-running
            unwrap on outer findings to obtain their full final
            bytes. Must match the value the peek enricher used so
            we re-decode the same payloads.
        peek_max_depth: Unwrap depth used during the same re-decode.
        peek_max_budget: Byte budget used during the same re-decode.
        extract_iocs: If True, compute SHA256/SHA512 hashes of
            original and decoded payloads, and extract source code
            for python_source terminals. Results stored in the
            ioc_data field of each node.

    Returns:
        A DecodedTree. May have zero nodes if no findings carried
        payloads. May have nodes whose stop_reason is one of the
        non-recursion reasons (depth_limit, non_python, decode_failed)
        when recursion stopped at that node.
    """
    nodes: list[DecodedNode] = []
    for finding in result.findings:
        if not _is_payload_bearing(finding):
            continue
        node = _decode_one(
            finding=finding,
            depth=0,
            max_depth=max_depth,
            engine=engine,
            peek_min_length=peek_min_length,
            peek_max_depth=peek_max_depth,
            peek_max_budget=peek_max_budget,
            extract_iocs=extract_iocs,
        )
        if node is not None:
            nodes.append(node)
    return DecodedTree(
        target=result.artifact_identity,
        max_depth=max_depth,
        nodes=tuple(nodes),
    )


def _is_payload_bearing(finding: Finding) -> bool:
    """True iff the finding has a decoded payload we could recurse into.

    The two conditions are: the analyzer stashed the full value
    (`_full_value` in the signal context, set by the analyzers that
    request peek enrichment), and peek successfully attached a
    `decoded` block. Both must be true.
    """
    ctx = finding.signal.context
    if "_full_value" not in ctx:
        return False
    if "decoded" not in ctx:
        return False
    return True


def _decode_one(
    *,
    finding: Finding,
    depth: int,
    max_depth: int,
    engine: StaticEngine,
    peek_min_length: int,
    peek_max_depth: int,
    peek_max_budget: int,
    extract_iocs: bool,
) -> DecodedNode | None:
    """Decode one finding and (maybe) recurse.

    Returns None if the finding has nothing to decode (e.g.
    _full_value missing despite the gating check). Returns a node
    with appropriate stop_reason in all other cases.
    """
    full_value = finding.signal.context.get("_full_value")
    if full_value is None:
        return _make_leaf_node(
            finding,
            depth=depth,
            stop_reason=STOP_NO_FULL_VALUE,
            chain=(),
            unwrap_status=STATUS_DECODE_ERROR,
            final_kind="binary_unknown",
            final_size=0,
            indicators=(),
            pickle_warning=False,
            extract_iocs=extract_iocs,
        )

    if depth >= max_depth:
        # Re-decode just enough to record the chain shape we would
        # have explored. We could skip the unwrap call entirely and
        # leave chain empty, but the report is more useful when the
        # depth_limit_reached node still shows what the chain looked
        # like at the point we stopped.
        unwrap_result = unwrap(
            full_value,
            max_depth=peek_max_depth,
            max_budget=peek_max_budget,
        )
        return _make_leaf_node(
            finding,
            depth=depth,
            stop_reason=STOP_DEPTH_LIMIT,
            chain=tuple(layer.kind for layer in unwrap_result.chain),
            unwrap_status=unwrap_result.status,
            final_kind=unwrap_result.final_kind,
            final_size=len(unwrap_result.final_bytes),
            indicators=unwrap_result.indicators,
            pickle_warning=unwrap_result.pickle_warning,
            extract_iocs=extract_iocs,
            full_value=full_value,
            final_bytes=unwrap_result.final_bytes,
        )

    unwrap_result = unwrap(
        full_value,
        max_depth=peek_max_depth,
        max_budget=peek_max_budget,
    )

    # If decoding failed, exhausted budget, or detected a loop, we
    # have nothing to recurse on. Record the result.
    if unwrap_result.status in (
        STATUS_DECODE_ERROR,
        STATUS_EXHAUSTED_BUDGET,
        STATUS_LOOP_DETECTED,
    ):
        return _make_leaf_node(
            finding,
            depth=depth,
            stop_reason=STOP_DECODE_FAILED,
            chain=tuple(layer.kind for layer in unwrap_result.chain),
            unwrap_status=unwrap_result.status,
            final_kind=unwrap_result.final_kind,
            final_size=len(unwrap_result.final_bytes),
            indicators=unwrap_result.indicators,
            pickle_warning=unwrap_result.pickle_warning,
            extract_iocs=extract_iocs,
            full_value=full_value,
            final_bytes=unwrap_result.final_bytes,
        )

    # If the terminal isn't python_source, we don't recurse. Other
    # terminals (PEM keys, ELF binaries, ZIP archives, etc) are real
    # findings worth recording but not re-scanning with the engine.
    if unwrap_result.final_kind != "python_source":
        return _make_leaf_node(
            finding,
            depth=depth,
            stop_reason=STOP_NON_PYTHON,
            chain=tuple(layer.kind for layer in unwrap_result.chain),
            unwrap_status=unwrap_result.status,
            final_kind=unwrap_result.final_kind,
            final_size=len(unwrap_result.final_bytes),
            indicators=unwrap_result.indicators,
            pickle_warning=unwrap_result.pickle_warning,
            extract_iocs=extract_iocs,
            full_value=full_value,
            final_bytes=unwrap_result.final_bytes,
        )

    # We have Python source. Re-scan with the engine, preserving the
    # outer finding's file_kind. The synthetic internal_path makes
    # the source of inner findings traceable in any output that
    # references it.
    inner_kind = finding.context.file_kind
    synthetic_path = (
        f"{finding.context.internal_path}<decoded:"
        f"layer{depth + 1}@line{finding.signal.location.line}>"
    )
    inp = FileScanInput(
        content=unwrap_result.final_bytes,
        internal_path=synthetic_path,
        artifact_kind=ArtifactKind.LOOSE_FILE,
        artifact_identity=synthetic_path,
        forced_file_kind=inner_kind,
    )
    inner_output = engine._scan_one_file(inp)

    # Partition the inner findings into recursive children (those
    # bearing further payloads) and leaf child_findings (those that
    # don't). Both go into the node; only the recursive ones become
    # sub-nodes via further _decode_one calls.
    children: list[DecodedNode] = []
    leaf_children: list[ChildFinding] = []
    for inner_finding in inner_output.findings:
        if _is_payload_bearing(inner_finding):
            child_node = _decode_one(
                finding=inner_finding,
                depth=depth + 1,
                max_depth=max_depth,
                engine=engine,
                peek_min_length=peek_min_length,
                peek_max_depth=peek_max_depth,
                peek_max_budget=peek_max_budget,
                extract_iocs=extract_iocs,
            )
            if child_node is not None:
                children.append(child_node)
        else:
            leaf_children.append(_to_child_finding(inner_finding))

    # The stop_reason for this node depends on what we observed.
    # If neither recursive nor leaf inner findings appeared, the
    # decoded source is "interesting enough that an outer signal
    # fired but contains no suspicious markers itself" — note this
    # so the report doesn't render a misleading silent node.
    if not children and not leaf_children:
        stop_reason = STOP_NO_INNER_FINDINGS
    else:
        stop_reason = STOP_LEAF_TERMINAL

    # Extract IOC data if requested
    ioc_data = None
    if extract_iocs:
        ioc_data = _extract_iocs(full_value, unwrap_result.final_bytes, unwrap_result.final_kind)

    return DecodedNode(
        outer_signal_id=finding.signal.signal_id,
        outer_severity=finding.severity.value,
        outer_location=_format_location(finding),
        outer_length=int(finding.signal.context.get("length", 0)),
        chain=tuple(layer.kind for layer in unwrap_result.chain),
        unwrap_status=unwrap_result.status,
        final_kind=unwrap_result.final_kind,
        final_size=len(unwrap_result.final_bytes),
        indicators=unwrap_result.indicators,
        pickle_warning=unwrap_result.pickle_warning,
        depth=depth,
        stop_reason=stop_reason,
        child_findings=tuple(leaf_children),
        children=tuple(children),
        ioc_data=ioc_data,
    )


def _extract_iocs(
    full_value: str | bytes,
    final_bytes: bytes,
    final_kind: str,
) -> IOCData:
    """Extract IOC data from original and decoded payloads."""
    timestamp = datetime.now(timezone.utc).isoformat()
    
    # Hash the original payload
    if isinstance(full_value, str):
        original_bytes = full_value.encode("utf-8", errors="replace")
    else:
        original_bytes = full_value
    
    original_sha256 = hashlib.sha256(original_bytes).hexdigest()
    original_sha512 = hashlib.sha512(original_bytes).hexdigest()
    
    # Hash the decoded payload
    decoded_sha256 = hashlib.sha256(final_bytes).hexdigest()
    decoded_sha512 = hashlib.sha512(final_bytes).hexdigest()
    
    # Extract source code for python_source terminals
    decoded_source = None
    if final_kind == "python_source":
        try:
            decoded_source = final_bytes.decode("utf-8", errors="replace")
        except Exception:
            # If decoding fails, include the hex representation for forensics
            decoded_source = f"# Decode failed, hex representation:\n{final_bytes.hex()}"
    
    return IOCData(
        original_sha256=original_sha256,
        original_sha512=original_sha512,
        decoded_sha256=decoded_sha256,
        decoded_sha512=decoded_sha512,
        decoded_source=decoded_source,
        extract_timestamp=timestamp,
    )


def _make_leaf_node(
    finding: Finding,
    *,
    depth: int,
    stop_reason: str,
    chain: tuple[str, ...],
    unwrap_status: str,
    final_kind: str,
    final_size: int,
    indicators: tuple[str, ...],
    pickle_warning: bool,
    extract_iocs: bool,
    full_value: str | bytes | None = None,
    final_bytes: bytes | None = None,
) -> DecodedNode:
    """Build a node that records why recursion stopped here."""
    ioc_data = None
    if extract_iocs and full_value is not None and final_bytes is not None:
        ioc_data = _extract_iocs(full_value, final_bytes, final_kind)
    
    return DecodedNode(
        outer_signal_id=finding.signal.signal_id,
        outer_severity=finding.severity.value,
        outer_location=_format_location(finding),
        outer_length=int(finding.signal.context.get("length", 0)),
        chain=chain,
        unwrap_status=unwrap_status,
        final_kind=final_kind,
        final_size=final_size,
        indicators=indicators,
        pickle_warning=pickle_warning,
        depth=depth,
        stop_reason=stop_reason,
        child_findings=(),
        children=(),
        ioc_data=ioc_data,
    )


def _to_child_finding(finding: Finding) -> ChildFinding:
    """Flatten a Finding into the report's leaf-finding shape."""
    return ChildFinding(
        signal_id=finding.signal.signal_id,
        severity=finding.severity.value,
        line=finding.signal.location.line,
        column=finding.signal.location.column,
        description=finding.signal.description,
    )


def _format_location(finding: Finding) -> str:
    """Render a finding's location as 'path:line:column' for the report."""
    loc = finding.signal.location
    return (
        f"{finding.context.internal_path}:"
        f"{loc.line}:{loc.column}"
    )


# ---------------------------------------------------------------------------
# Text formatter
# ---------------------------------------------------------------------------

# ASCII tree-drawing characters. We deliberately avoid Unicode box
# drawing because the report file may be opened in text editors,
# emailed, or pasted into ticket systems that don't reliably render
# UTF-8 multi-byte sequences. ASCII renders identically everywhere.
_T_BRANCH = "+-- "
_T_LAST   = "`-- "
_T_PIPE   = "|   "
_T_BLANK  = "    "


def render_text(tree: DecodedTree, *, include_iocs: bool = False) -> str:
    """Render the tree as ASCII text suitable for the report file.

    Format example:

        decoded payload report for litellm-1.82.8.tar.gz
        max recursion depth: 3
        =================================================================

        litellm/proxy/proxy_server.py:130 (DENS011, length 34460)
            chain: base64 -> python_source (25844 bytes)
            indicators: subprocess, base64.b64decode
            inner findings:
              +-- DENS011 critical at line 22:14: ...
              |   chain: base64 -> python_source (12288 bytes)
              |   inner findings:
              |     +-- STDLIB001 critical at line 4:0: ...
              |     +-- STDLIB002 high at line 9:4: ...
              |     `-- DYN002 high at line 15:0: ...
              `-- DENS010 medium at line 7:14: ...
                  (terminal: pem_key, no further peek)
    """
    lines: list[str] = []
    lines.append(f"decoded payload report for {tree.target}")
    lines.append(f"max recursion depth: {tree.max_depth}")
    lines.append("=" * 65)
    lines.append("")

    if not tree.nodes:
        lines.append("(no payload-bearing findings; nothing to decode)")
        lines.append("")
        return "\n".join(lines)

    for i, node in enumerate(tree.nodes):
        _render_node_text(node, lines, prefix="", is_last=True, top_level=True)
        if i < len(tree.nodes) - 1:
            lines.append("")

    lines.append("")
    return "\n".join(lines)


def _render_ioc_section(tree: DecodedTree) -> list[str]:
    """Render the IOC section with hashes and extracted source code."""
    lines: list[str] = []
    lines.append("=" * 65)
    lines.append("IOC (INDICATORS OF COMPROMISE) SECTION")
    lines.append("=" * 65)
    lines.append("")
    
    # Collect all nodes with IOC data in depth-first order
    nodes_with_iocs = []
    def collect_nodes(node):
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
        lines.append(f"IOC #{i}: {node.outer_location} ({node.outer_signal_id})")
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
            # Add line numbers for readability
            for line_num, source_line in enumerate(ioc.decoded_source.splitlines(), 1):
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


def render_text(tree: DecodedTree, *, include_iocs: bool = False) -> str:
    """Render the tree as ASCII text suitable for the report file.

    Format example:

        decoded payload report for litellm-1.82.8.tar.gz
        max recursion depth: 3
        =================================================================

        litellm/proxy/proxy_server.py:130 (DENS011, length 34460)
            chain: base64 -> python_source (25844 bytes)
            indicators: subprocess, base64.b64decode
            inner findings:
              +-- DENS011 critical at line 22:14: ...
              |   chain: base64 -> python_source (12288 bytes)
              |   inner findings:
              |     +-- STDLIB001 critical at line 4:0: ...
              |     +-- STDLIB002 high at line 9:4: ...
              |     `-- DYN002 high at line 15:0: ...
              `-- DENS010 medium at line 7:14: ...
                  (terminal: pem_key, no further peek)

        If include_iocs is True, appends an IOC section with hashes
        and extracted source code for forensic analysis.
    """
    lines: list[str] = []
    lines.append(f"decoded payload report for {tree.target}")
    lines.append(f"max recursion depth: {tree.max_depth}")
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
        # Top-level nodes don't get a tree branch character; they're
        # the trunks. Their own indented body uses prefix continuation.
        lines.append(
            f"{node.outer_location} ({node.outer_signal_id}, "
            f"length {node.outer_length})"
        )
        body_prefix = "    "
    else:
        connector = _T_LAST if is_last else _T_BRANCH
        lines.append(
            f"{prefix}{connector}"
            f"{node.outer_signal_id} {node.outer_severity} "
            f"at line {node.outer_location.split(':')[-2]}:"
            f"{node.outer_location.split(':')[-1]}"
        )
        body_prefix = prefix + (_T_BLANK if is_last else _T_PIPE)

    # Chain summary.
    if node.chain:
        chain_repr = " -> ".join(node.chain) + f" -> {node.final_kind}"
        lines.append(
            f"{body_prefix}chain: {chain_repr} "
            f"({node.final_size} bytes)"
        )
    else:
        lines.append(f"{body_prefix}chain: (no transforms applied)")

    # Indicators.
    if node.indicators:
        lines.append(
            f"{body_prefix}indicators: {', '.join(node.indicators)}"
        )

    # Pickle warning.
    if node.pickle_warning:
        lines.append(
            f"{body_prefix}WARNING: payload is a Python pickle "
            "stream (NOT deserialized)"
        )

    # Stop reason annotation.
    if node.stop_reason == STOP_DEPTH_LIMIT:
        lines.append(
            f"{body_prefix}(stopped: recursion depth limit reached)"
        )
    elif node.stop_reason == STOP_NON_PYTHON:
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

    # Leaf child findings (those that didn't themselves recurse).
    if node.child_findings:
        lines.append(f"{body_prefix}inner findings:")
        for cf in node.child_findings:
            lines.append(
                f"{body_prefix}  - {cf.signal_id} {cf.severity} "
                f"at line {cf.line}:{cf.column}: {cf.description}"
            )

    # Recursive children.
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


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

def render_json(tree: DecodedTree) -> str:
    """Render the tree as JSON suitable for downstream tooling."""
    return json.dumps(_tree_to_dict(tree), indent=2) + "\n"


def _tree_to_dict(tree: DecodedTree) -> dict:
    return {
        "target": tree.target,
        "max_depth": tree.max_depth,
        "nodes": [_node_to_dict(n) for n in tree.nodes],
    }


def _node_to_dict(node: DecodedNode) -> dict:
    result = {
        "outer_signal_id": node.outer_signal_id,
        "outer_severity": node.outer_severity,
        "outer_location": node.outer_location,
        "outer_length": node.outer_length,
        "chain": list(node.chain),
        "unwrap_status": node.unwrap_status,
        "final_kind": node.final_kind,
        "final_size": node.final_size,
        "indicators": list(node.indicators),
        "pickle_warning": node.pickle_warning,
        "depth": node.depth,
        "stop_reason": node.stop_reason,
        "child_findings": [
            {
                "signal_id": cf.signal_id,
                "severity": cf.severity,
                "line": cf.line,
                "column": cf.column,
                "description": cf.description,
            }
            for cf in node.child_findings
        ],
        "children": [_node_to_dict(c) for c in node.children],
    }
    
    if node.ioc_data is not None:
        result["ioc_data"] = {
            "original_sha256": node.ioc_data.original_sha256,
            "original_sha512": node.ioc_data.original_sha512,
            "decoded_sha256": node.ioc_data.decoded_sha256,
            "decoded_sha512": node.ioc_data.decoded_sha512,
            "decoded_source": node.ioc_data.decoded_source,
            "extract_timestamp": node.ioc_data.extract_timestamp,
        }
    
    return result