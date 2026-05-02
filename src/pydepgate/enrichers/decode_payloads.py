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

    decode_payloads(result, *, engine, max_depth, peek_min_length,
                    peek_max_depth, peek_max_budget,
                    extract_iocs) -> DecodedTree
        Run the recursion. Returns the tree (possibly empty).

    filter_tree_by_severity(tree, min_severity) -> DecodedTree
        Post-decode presentation filter. Returns a new tree with
        nodes pruned to those at or above min_severity, preserving
        chains where a low-severity ancestor has high-severity
        descendants. Decoding is NOT gated by this; it always runs
        over every payload-bearing finding.

    render_text(tree, *, include_iocs) -> str
        Combined report+IOC renderer (legacy). Most callers should
        use render_text(tree, include_iocs=False) plus the
        separate render_sources and render_iocs renderers.

    render_sources(tree) -> str
        Decoded source dumps, one block per python_source terminal,
        with header and line-numbered body.

    render_iocs(tree) -> str
        Hash records suitable for grep/awk consumption.

    render_json(tree) -> str
        Structured representation for downstream tooling.

    DecodedTree, DecodedNode, ChildFinding, IOCData
        Public data types.

The engine is called via _scan_one_file rather than scan_bytes
because scan_bytes does not expose a forced_file_kind parameter and
the user explicitly wants the outer finding's file_kind to carry
through to the inner scan. This is a deliberate use of the engine's
"private" entry point; the FileScanInput / FileScanOutput pair is the
documented picklable boundary and is stable across engine versions.

Dedup behavior:

    Multiple analyzers can fire on the same payload literal at the
    same source location. The most common case is DENS010 (high-
    entropy long string) and DENS011 (base64-alphabet long string)
    both firing on a single base64 literal. Without dedup, each
    fired signal would produce its own decoded sub-tree, and the
    report would list the same decoded payload several times.

    To avoid that, findings are grouped by the four-tuple
    (internal_path, line, column, sha256(_full_value)) before any
    recursion. Each group is represented by a single DecodedNode
    whose triggered_by field carries every signal_id that fired on
    that payload, sorted alphabetically. The primary outer_signal_id
    is the highest-severity member of the group; severity ties break
    alphabetically.

    Dedup applies at the top level (when iterating result.findings)
    and recursively (when iterating an inner scan's findings).
    Non-payload-bearing findings inside an inner scan are not deduped
    because they are leaves displayed verbatim in the report; two
    different signals firing at the same line are real, distinct
    observations of that location.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from pydepgate.engines.base import (
    ArtifactKind,
    FileScanInput,
    Finding,
    ScanResult,
    Severity,
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
from pydepgate.enrichers._asn1 import DERClassification
from pydepgate.traffic_control.triage import FileKind


# ---------------------------------------------------------------------------
# Stop-reason constants
# ---------------------------------------------------------------------------

STOP_DEPTH_LIMIT = "depth_limit_reached"
STOP_NON_PYTHON = "non_python_terminal"
STOP_DECODE_FAILED = "decode_failed"
STOP_NO_FULL_VALUE = "no_full_value"
STOP_NO_INNER_FINDINGS = "no_inner_findings"
STOP_LEAF_TERMINAL = "leaf_terminal"


# ---------------------------------------------------------------------------
# Severity ranking for tie-break and filtering
# ---------------------------------------------------------------------------
#
# Two parallel maps. _SEVERITY_RANK is keyed by the Severity enum and
# is used by _pick_primary_finding to choose the dedup-group primary.
# _SEVERITY_RANK_BY_STRING is keyed by the lowercase string form
# stored in DecodedNode.outer_severity and ChildFinding.severity, and
# is used by the post-decode filter. Higher rank == more severe.

_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

_SEVERITY_RANK_BY_STRING = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


# ---------------------------------------------------------------------------
# Tree types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IOCData:
    """IOC (Indicators of Compromise) for a decoded payload."""
    original_sha256: str | None = None
    original_sha512: str | None = None
    decoded_sha256: str | None = None
    decoded_sha512: str | None = None
    decoded_source: str | None = None
    extract_timestamp: str | None = None


@dataclass(frozen=True)
class ChildFinding:
    """One finding observed inside a decoded layer."""
    signal_id: str
    severity: str
    line: int
    column: int
    description: str


@dataclass(frozen=True)
class DecodedNode:
    """One node in the decoded-payload tree.

    The new containing_file_sha256/sha512 fields are sourced from
    `finding.context.file_sha256/sha512` at decode time. They are
    None when:
      - The original scan path did not compute file hashes (older
        scans, decode driver's synthetic re-scan inputs).
      - The node is from an inner recursive scan (the bytes have
        no meaningful containing file in the original artifact).
    Renderers handle the None case gracefully.

    The details_summary and details_full fields carry the structured
    classification of binary terminals (currently DER certs and public
    keys via DERClassification, future formats welcome). Both are
    plain dicts rather than the original FormatContext object so the
    DecodedNode remains picklable, JSON-serializable, and decoupled
    from the parser modules. They are populated from
    `unwrap_result.details` via the new `summary_dict()` and
    `full_dict()` methods on DERClassification. None when the
    terminal had no structured classification (most python_source
    cases, raw zlib output, etc.).
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
    triggered_by: tuple[str, ...] = ()
    child_findings: tuple[ChildFinding, ...] = ()
    children: tuple["DecodedNode", ...] = ()
    ioc_data: IOCData | None = None
    containing_file_sha256: str | None = None
    containing_file_sha512: str | None = None
    details_summary: dict | None = None
    details_full: dict | None = None

@dataclass(frozen=True)
class DecodedTree:
    """The full result of a decoded-payload pass."""
    target: str
    max_depth: int
    nodes: tuple[DecodedNode, ...]
    artifact_sha256: str | None = None
    artifact_sha512: str | None = None


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
    """Run the decoded-payload recursion."""
    deduped = _dedupe_payload_findings(result.findings)
    nodes: list[DecodedNode] = []
    for primary, triggered_by in deduped:
        node = _decode_one(
            finding=primary,
            triggered_by=triggered_by,
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
        artifact_sha256=getattr(result, "artifact_sha256", None),
        artifact_sha512=getattr(result, "artifact_sha512", None),
    )

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

def _is_payload_bearing(finding: Finding) -> bool:
    """True if the finding has a decoded payload we could recurse into.

    Presence of `_full_value` in context is the only criterion. Whether
    the finding has also been enriched with a `decoded` block by
    payload_peek is orthogonal: enrichment adds rendering context but
    does not consume the underlying value. The recursion in
    `_decode_one` reads from `_full_value` directly and ignores
    `decoded` entirely.

    The previous version had a truth-table bug: it returned True for
    (has_full, not has_decoded), False for (not has_full, not
    has_decoded), and fell through to an implicit None for the
    remaining two cases. None is falsy, so every finding that had
    been enriched by payload_peek (i.e. (has_full, has_decoded)) was
    silently dropped from the recursion. That is why the litellm scan
    missed the inner B64_SCRIPT (above payload_peek's 1024-byte
    enrichment threshold, so enriched, so dropped) but caught the
    line-7 PEM (below the threshold, not enriched, recursed).
    """
    return "_full_value" in finding.signal.context


def _dedupe_payload_findings(
    findings: Iterable[Finding],
) -> list[tuple[Finding, tuple[str, ...]]]:
    """Group payload-bearing findings by their decoded payload identity."""
    groups: dict[tuple[str, int, int, str], list[Finding]] = {}
    order: list[tuple[str, int, int, str]] = []

    for finding in findings:
        if not _is_payload_bearing(finding):
            continue
        full_value = finding.signal.context.get("_full_value")
        if full_value is None:
            continue

        if isinstance(full_value, str):
            value_bytes = full_value.encode("utf-8", errors="replace")
        else:
            value_bytes = full_value
        value_hash = hashlib.sha256(value_bytes).hexdigest()

        key = (
            finding.context.internal_path,
            finding.signal.location.line,
            value_hash,
        )

        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)

    result: list[tuple[Finding, tuple[str, ...]]] = []
    for key in order:
        findings_at_key = groups[key]
        primary = _pick_primary_finding(findings_at_key)
        all_signal_ids = tuple(
            sorted({f.signal.signal_id for f in findings_at_key})
        )
        result.append((primary, all_signal_ids))
    return result


def _pick_primary_finding(findings: list[Finding]) -> Finding:
    """Pick the primary finding from a deduped group."""
    if len(findings) == 1:
        return findings[0]

    def sort_key(f: Finding) -> tuple[int, str]:
        rank = _SEVERITY_RANK.get(f.severity, 0)
        return (-rank, f.signal.signal_id)

    return min(findings, key=sort_key)


def _decode_one(
    *,
    finding: Finding,
    triggered_by: tuple[str, ...],
    depth: int,
    max_depth: int,
    engine: StaticEngine,
    peek_min_length: int,
    peek_max_depth: int,
    peek_max_budget: int,
    extract_iocs: bool,
) -> DecodedNode | None:
    """Decode one finding and (maybe) recurse."""
    full_value = finding.signal.context.get("_full_value")
    if full_value is None:
        return _make_leaf_node(
            finding,
            triggered_by=triggered_by,
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
        unwrap_result = unwrap(
            full_value,
            max_depth=peek_max_depth,
            max_budget=peek_max_budget,
        )
        return _make_leaf_node(
            finding,
            triggered_by=triggered_by,
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
            details=unwrap_result.details,
        )

    unwrap_result = unwrap(
        full_value,
        max_depth=peek_max_depth,
        max_budget=peek_max_budget,
    )

    if unwrap_result.status in (
        STATUS_DECODE_ERROR,
        STATUS_EXHAUSTED_BUDGET,
        STATUS_LOOP_DETECTED,
    ):
        return _make_leaf_node(
            finding,
            triggered_by=triggered_by,
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
            details=unwrap_result.details,
        )

    if unwrap_result.final_kind != "python_source":
        return _make_leaf_node(
            finding,
            triggered_by=triggered_by,
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
            details=unwrap_result.details,
        )

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

    payload_bearing: list[Finding] = []
    leaf_children: list[ChildFinding] = []
    for inner_finding in inner_output.findings:
        if _is_payload_bearing(inner_finding):
            payload_bearing.append(inner_finding)
        else:
            leaf_children.append(_to_child_finding(inner_finding))

    deduped_inner = _dedupe_payload_findings(payload_bearing)
    children: list[DecodedNode] = []
    for inner_primary, inner_triggered_by in deduped_inner:
        child_node = _decode_one(
            finding=inner_primary,
            triggered_by=inner_triggered_by,
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

    if not children and not leaf_children:
        stop_reason = STOP_NO_INNER_FINDINGS
    else:
        stop_reason = STOP_LEAF_TERMINAL

    ioc_data = None
    if extract_iocs:
        ioc_data = _extract_iocs(
            full_value, unwrap_result.final_bytes, unwrap_result.final_kind,
        )

    details_summary: dict | None = None
    details_full: dict | None = None
    if isinstance(unwrap_result.details, DERClassification):
        print(f"DEBUG: Call Site: _decode_one at depth {depth} for signal {finding.signal.signal_id} with terminal DER classification. Adding DER details to decoded block.")
        print("=== DEBUG: DER details summary dict ===")
        print(f"DEBUG: DER details summary: {unwrap_result.details.summary_dict()}")
        print(f"DEBUG: DER details full dict: {unwrap_result.details.full_dict()}")
        print("=== END DEBUG ===")
        details_summary = unwrap_result.details.summary_dict()
        details_full = unwrap_result.details.full_dict()

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
        triggered_by=triggered_by,
        child_findings=tuple(leaf_children),
        children=tuple(children),
        ioc_data=ioc_data,
        containing_file_sha256=finding.context.file_sha256,
        containing_file_sha512=finding.context.file_sha512,
        details_summary=details_summary,
        details_full=details_full,
    )


def _extract_iocs(
    full_value: str | bytes,
    final_bytes: bytes,
    final_kind: str,
) -> IOCData:
    """Extract IOC data from original and decoded payloads."""
    timestamp = datetime.now(timezone.utc).isoformat()

    if isinstance(full_value, str):
        original_bytes = full_value.encode("utf-8", errors="replace")
    else:
        original_bytes = full_value

    original_sha256 = hashlib.sha256(original_bytes).hexdigest()
    original_sha512 = hashlib.sha512(original_bytes).hexdigest()
    decoded_sha256 = hashlib.sha256(final_bytes).hexdigest()
    decoded_sha512 = hashlib.sha512(final_bytes).hexdigest()

    decoded_source = None
    if final_kind == "python_source":
        try:
            decoded_source = final_bytes.decode("utf-8", errors="replace")
        except Exception:
            decoded_source = (
                f"# Decode failed, hex representation:\n"
                f"{final_bytes.hex()}"
            )

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
    triggered_by: tuple[str, ...],
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
    details: object | None = None,
) -> DecodedNode:
    """Build a node that records why recursion stopped here.

    The `details` parameter is `unwrap_result.details` from the caller
    (typically a DERClassification or None). It gets serialized into
    the node's details_summary/details_full dicts via the
    classification's summary_dict() and full_dict() methods. Typed as
    object rather than FormatContext to keep this signature
    independent of the parser-class hierarchy; isinstance gates do
    the actual dispatch.
    """
    ioc_data = None
    if extract_iocs and full_value is not None and final_bytes is not None:
        ioc_data = _extract_iocs(full_value, final_bytes, final_kind)

    details_summary: dict | None = None
    details_full: dict | None = None
    if isinstance(details, DERClassification):
        print(f"DEBUG: Terminal is recognized DER with kind {details.kind}. Adding DER details to decoded block.")
        print("=== DEBUG: DER details summary dict ===")
        print(f"DEBUG: DER details summary: {details.summary_dict()}")
        print(f"DEBUG: DER details full dict: {details.full_dict()}")
        print("=== END DEBUG ===")
        details_summary = details.summary_dict()
        details_full = details.full_dict()

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
        triggered_by=triggered_by,
        child_findings=(),
        children=(),
        ioc_data=ioc_data,
        containing_file_sha256=finding.context.file_sha256,
        containing_file_sha512=finding.context.file_sha512,
        details_summary=details_summary,
        details_full=details_full,
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


def _signal_repr(node: DecodedNode) -> str:
    """Render the signal-id portion of a node for human-readable output."""
    if len(node.triggered_by) > 1:
        return "+".join(node.triggered_by)
    return node.outer_signal_id


# ---------------------------------------------------------------------------
# Post-decode severity filter (NEW)
# ---------------------------------------------------------------------------

def filter_tree_by_severity(
    tree: DecodedTree,
    min_severity: Severity | str | None,
) -> DecodedTree:
    """Filter a decoded tree to surface only nodes at or above min_severity.

    The rule is "keep for context": a node is preserved if its own
    outer_severity meets the threshold, OR if any of its descendants
    do. This means a low-severity outer finding that decodes to a
    critical inner finding stays in the report, because pruning the
    low-severity ancestor would orphan the critical descendant and
    lose the chain.

    child_findings (leaf, non-recursive) are filtered strictly. A
    child finding is dropped if its severity is below threshold,
    regardless of its parent.

    Decoding itself is NOT gated by min_severity. This filter runs
    after the decode pass completes, on the result tree, as a
    presentation step.

    Args:
        tree: The unfiltered tree from decode_payloads.
        min_severity: A Severity enum, a severity string ('low',
            'high', etc, case-insensitive), or None. None returns
            the tree unchanged.

    Returns:
        A new DecodedTree with filtered nodes. The original tree is
        not modified.
    """
    if min_severity is None:
        return tree

    threshold = _resolve_severity_threshold(min_severity)
    if threshold == 0:
        # Threshold below INFO is effectively no filter; bail.
        return tree

    filtered_nodes = tuple(
        n for n in (
            _filter_node_by_severity(node, threshold)
            for node in tree.nodes
        )
        if n is not None
    )

    return DecodedTree(
        target=tree.target,
        max_depth=tree.max_depth,
        nodes=filtered_nodes,
        artifact_sha256=tree.artifact_sha256,
        artifact_sha512=tree.artifact_sha512,
    )


def _resolve_severity_threshold(value: Severity | str | int) -> int:
    """Convert a severity-like value to an int rank."""
    if isinstance(value, Severity):
        return _SEVERITY_RANK.get(value, 0)
    if isinstance(value, str):
        return _SEVERITY_RANK_BY_STRING.get(value.lower(), 0)
    if isinstance(value, int):
        return value
    return 0


def _filter_node_by_severity(
    node: DecodedNode,
    threshold: int,
) -> DecodedNode | None:
    """Filter one node and its subtree.

    Returns None if the node and all its descendants are below
    threshold. Returns a (possibly trimmed) new node otherwise.
    """
    kept_child_findings = tuple(
        cf for cf in node.child_findings
        if _SEVERITY_RANK_BY_STRING.get(cf.severity.lower(), 0) >= threshold
    )

    kept_children = tuple(
        c for c in (
            _filter_node_by_severity(child, threshold)
            for child in node.children
        )
        if c is not None
    )

    own_severity_rank = _SEVERITY_RANK_BY_STRING.get(
        node.outer_severity.lower(), 0,
    )
    own_passes = own_severity_rank >= threshold
    has_kept_descendants = bool(kept_children) or bool(kept_child_findings)

    if not own_passes and not has_kept_descendants:
        return None
    
    if node.details_summary is not None or node.details_full is not None:
        print(f"DEBUG: Node {node.outer_signal_id} at depth {node.depth} has details. Preserving details in filtered node.")
        print(f"DEBUG: details_summary: {node.details_summary}")
        print(f"DEBUG: details_full: {node.details_full}")

    return DecodedNode(
        outer_signal_id=node.outer_signal_id,
        outer_severity=node.outer_severity,
        outer_location=node.outer_location,
        outer_length=node.outer_length,
        chain=node.chain,
        unwrap_status=node.unwrap_status,
        final_kind=node.final_kind,
        final_size=node.final_size,
        indicators=node.indicators,
        pickle_warning=node.pickle_warning,
        depth=node.depth,
        stop_reason=node.stop_reason,
        triggered_by=node.triggered_by,
        child_findings=kept_child_findings,
        children=kept_children,
        ioc_data=node.ioc_data,
        containing_file_sha256=node.containing_file_sha256,
        containing_file_sha512=node.containing_file_sha512,
        details_summary=node.details_summary,
        details_full=node.details_full,
    )


# ---------------------------------------------------------------------------
# Text formatter (legacy combined renderer)
# ---------------------------------------------------------------------------
#
# render_text emits the tree report. With include_iocs=True it also
# embeds an IOC section at the bottom of the same output. Most new
# callers should pass include_iocs=False and use render_iocs and
# render_sources separately so the three pieces can be packaged
# independently (plaintext, sidecar, archive entries). The
# include_iocs=True path is retained for backward compatibility with
# direct-API users.

_T_BRANCH = "+-- "
_T_LAST   = "`-- "
_T_PIPE   = "|   "
_T_BLANK  = "    "


def render_text(tree: DecodedTree, *, include_iocs: bool = False) -> str:
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
    print(f"DEBUG: Node is of kind: {node.final_kind} with size {node.final_size} bytes. Pickle warning: {node.pickle_warning}. Indicators: {node.indicators}")
    # DER classification block (currently the only structured details
    # emitter; future formats will plug in here).
    if node.details_summary is not None:
        print(f"DEBUG: Node {node.outer_signal_id} at depth {node.depth} has details. Rendering DER details block in text output.")
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


# ---------------------------------------------------------------------------
# Separate-file renderers for the three-file split (NEW)
# ---------------------------------------------------------------------------

def render_sources(tree: DecodedTree) -> str:
    """Render decoded source code for python_source terminals.

    For each node that has ioc_data.decoded_source AND final_kind
    == 'python_source', emit a header block (location, chain,
    containing-file context, hashes) followed by the source body,
    line-numbered.

    Empty tree or tree with no python_source nodes produces a
    short stub explaining why; this is intentional so the file
    always exists with a defined shape inside the archive.

    The artifact-identity header is emitted at the top whenever
    artifact hashes are populated, matching render_iocs.
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


def render_iocs(tree: DecodedTree) -> str:
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


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

def render_decode_json(tree: DecodedTree, *, include_source: bool = True) -> str:

    """Render the tree as JSON suitable for downstream tooling.

    Schema version 1: includes top-level artifact_sha256 and
    artifact_sha512, plus per-node containing_file_sha256 and
    containing_file_sha512, plus the existing IOC data block.

    The schema_version field is new in this release. Earlier
    versions of pydepgate emitted this same shape WITHOUT the
    schema_version field. Consumers built against the
    schema-versionless output continue to work because the new
    field is additive and existing keys are unchanged.
    """
    return json.dumps(_tree_to_dict(tree, include_source=include_source), indent=2) + "\n"


def _tree_to_dict(tree: DecodedTree, include_source: bool = True) -> dict:
    return {
        "report_type": "pydepgate_decoded_tree",
        "schema_version": 1,
        "target": tree.target,
        "max_depth": tree.max_depth,
        "artifact_sha256": tree.artifact_sha256,
        "artifact_sha512": tree.artifact_sha512,
        "nodes": [_node_to_dict(n, include_source=include_source) for n in tree.nodes],
    }


def _node_to_dict(node: DecodedNode, *, include_source: bool = True) -> dict:
    result = {
        "outer_signal_id": node.outer_signal_id,
        "outer_severity": node.outer_severity,
        "outer_location": node.outer_location,
        "outer_length": node.outer_length,
        "triggered_by": list(node.triggered_by),
        "chain": list(node.chain),
        "unwrap_status": node.unwrap_status,
        "final_kind": node.final_kind,
        "final_size": node.final_size,
        "indicators": list(node.indicators),
        "pickle_warning": node.pickle_warning,
        "depth": node.depth,
        "stop_reason": node.stop_reason,
        "containing_file_sha256": node.containing_file_sha256,
        "containing_file_sha512": node.containing_file_sha512,
        "details_summary": node.details_summary,
        "details_full": node.details_full,
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
        "children": [_node_to_dict(c, include_source=include_source) for c in node.children],
    }

    if node.ioc_data is not None:
        result["ioc_data"] = {
            "original_sha256": node.ioc_data.original_sha256,
            "original_sha512": node.ioc_data.original_sha512,
            "decoded_sha256": node.ioc_data.decoded_sha256,
            "decoded_sha512": node.ioc_data.decoded_sha512,
            "decoded_source": node.ioc_data.decoded_source if include_source else None,
            "extract_timestamp": node.ioc_data.extract_timestamp,
        }

    return result