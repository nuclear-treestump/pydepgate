"""pydepgate.reporters.sarif.results

Generates SARIF result entries from pydepgate findings.

This module produces SARIF result dicts for two finding
sources:

  1. ScanResult findings (one per Finding from the main
     scan pass). Built via make_result(), which takes a
     Signal plus the rule-evaluated Severity plus the
     containing file's internal_path.

  2. DecodedTree findings (one per ChildFinding observed
     inside a decoded payload). Built via
     make_results_for_decoded_node(), which walks one
     DecodedNode and its nested children, emitting one
     result per ChildFinding reached. Each result carries
     a codeFlow representing the path from the on-disk
     artifact through every decode layer down to the
     inner finding's location.

Callers pass the indices map produced by
pydepgate.reporters.sarif.rules.make_rules_array() so
each result's ruleIndex points at the correct
reportingDescriptor in the runs[0].tool.driver.rules
array.

Inputs and outputs:

  Input:  a Signal (or ChildFinding inside a DecodedNode)
          plus indices map.
  Output: a SARIF result dict (or list of dicts when
          walking a DecodedNode and its descendants)
          suitable for embedding in runs[0].results.

The result dict shape:

  ruleId               the signal_id verbatim
  ruleIndex            position of the rule in the rules
                       array
  level                SARIF level mapped from severity
  message.text         the signal's description
  locations[0]         a single physicalLocation with the
                       artifact location and source region
  partialFingerprints  the primaryLocationLineHash for
                       GitHub alert deduplication
  properties           security-severity plus pydepgate-
                       specific metadata
  codeFlows            present only on DecodedTree
                       results; carries the decode chain
                       as a threadFlow

Source ordering note: pydepgate location columns come
from ast.col_offset which is 0-indexed, while SARIF
region startColumn is 1-indexed. The +1 conversion
happens in _make_region. Lines are 1-indexed in both ast
and SARIF, so no conversion is needed there; whole-file
findings (line=0) fall back to startLine=1 because SARIF
requires a positive line in a region.
"""

from __future__ import annotations

from pydepgate.analyzers.base import Signal
from pydepgate.engines.base import Severity
from pydepgate.enrichers.decode_payloads import ChildFinding, DecodedNode

from pydepgate.reporters.sarif.fingerprints import (
    primary_location_line_hash,
)
from pydepgate.reporters.sarif.rules import analyzer_for_signal
from pydepgate.reporters.sarif.severity import (
    to_sarif_level,
    to_security_severity,
)
from pydepgate.reporters.sarif.uris import (
    make_artifact_location,
    make_artifact_location_for_decoded,
)

# ===========================================================================
# ScanResult findings
# ===========================================================================


def make_result(
    signal: Signal,
    severity: Severity,
    internal_path: str,
    indices: dict[str, int],
    use_srcroot: bool = False,
) -> dict:
    """Build a SARIF result dict for a single ScanResult finding.

    Args:
        signal: the analyzer-emitted Signal that triggered
            the finding. Carries the signal_id, location,
            description, and per-finding context dict.
        severity: the rule-evaluated Severity for this
            finding. May differ from the rule's default
            severity when a default rule promotes the
            severity for a specific file_kind or scope.
        internal_path: the file's path inside the artifact
            being scanned (wheel/sdist scans) or the
            on-disk path (loose-file scans). The URI helper
            normalizes both transparently. Synthetic
            decoded paths (containing the '<decoded:'
            marker) route to the pydepgate-decoded: URI
            scheme automatically.
        indices: the signal_id-to-rule-index map produced
            by make_rules_array() in
            pydepgate.reporters.sarif.rules. Used to set
            result.ruleIndex. Raises KeyError if signal's
            signal_id is not in the map; this indicates a
            catalog bug worth failing loudly on.
        use_srcroot: when True, the artifactLocation
            receives a uriBaseId of PROJECTROOT, which
            GitHub resolves against the
            originalUriBaseIds entry in the document. Set
            by callers that have a srcroot configured.

    Returns:
        A SARIF result dict suitable for embedding in
        runs[0].results. All values are JSON-serializable.
    """
    return {
        "ruleId": signal.signal_id,
        "ruleIndex": indices[signal.signal_id],
        "level": to_sarif_level(severity),
        "message": {"text": signal.description},
        "locations": [_make_location(signal, internal_path, use_srcroot)],
        "partialFingerprints": _make_partial_fingerprints(signal, internal_path),
        "properties": _make_properties(signal, severity),
    }


def _make_location(
    signal: Signal,
    internal_path: str,
    use_srcroot: bool,
) -> dict:
    """Build a single location dict from a signal.

    SARIF results may carry multiple locations. This
    function emits exactly one per finding because
    pydepgate signals are point-anchored. Decoded payload
    chains are represented as codeFlows alongside this
    primary location, not as multiple locations.
    """
    return {
        "physicalLocation": {
            "artifactLocation": make_artifact_location(
                internal_path, use_srcroot=use_srcroot
            ),
            "region": _make_region(signal),
        },
    }


def _make_region(signal: Signal) -> dict:
    """Build the region dict from a signal's location.

    SARIF requires startLine to be positive when present.
    Whole-file findings (line=0) fall back to startLine=1
    so GitHub annotates the first line of the file rather
    than rejecting the result.

    The startColumn conversion accounts for pydepgate's
    0-indexed columns (from ast.col_offset) versus SARIF's
    1-indexed columns. A column of 0 in pydepgate means
    'start of line' and converts to startColumn=1 in SARIF.
    """
    line = signal.location.line
    if line < 1:
        line = 1
    region = {"startLine": line}

    column = signal.location.column
    if column is not None and column >= 0:
        region["startColumn"] = column + 1
    return region


def _make_partial_fingerprints(
    signal: Signal,
    internal_path: str,
) -> dict:
    """Build the partialFingerprints dict for a ScanResult result.

    GitHub uses primaryLocationLineHash to deduplicate
    alerts across runs of the same scan. Two scans of the
    same artifact produce the same hash, which means GitHub
    treats them as the same alert. Two scans of different
    artifacts produce different hashes, which means each
    finding gets its own alert.
    """
    return {
        "primaryLocationLineHash": primary_location_line_hash(
            rule_id=signal.signal_id,
            internal_path=internal_path,
            line=signal.location.line,
            context=_fingerprint_context(signal),
        ),
    }


def _make_properties(signal: Signal, severity: Severity) -> dict:
    """Build the properties dict for a ScanResult result.

    The security-severity numeric drives GitHub's display
    badge (critical/high/medium/low). The pydepgate.*
    properties carry forensic detail useful for users who
    download the SARIF JSON for offline analysis but are
    not displayed prominently in GitHub's UI.
    """
    return {
        "security-severity": to_security_severity(severity),
        "pydepgate.analyzer": signal.analyzer,
        "pydepgate.confidence": signal.confidence.name,
        "pydepgate.scope": signal.scope.name,
    }


def _fingerprint_context(signal: Signal) -> str:
    """Pick the best content string for fingerprinting a Signal.

    Preference order:
      1. signal.context['_full_value'] when populated. This
         is the literal matched value the analyzer captured;
         it changes when the matched content changes, which
         is the right behavior for fingerprinting.
      2. signal.description as a fallback. This produces
         stable fingerprints when the analyzer did not
         populate _full_value, but those fingerprints do
         not differentiate between findings of the same
         signal_id at the same line with different content.

    Type handling: _full_value may be str, bytes, or other
    types. Bytes are decoded as UTF-8 with replacement for
    invalid sequences. Other types fall through to str().
    """
    full_value = signal.context.get("_full_value")
    if full_value is None:
        return signal.description
    if isinstance(full_value, bytes):
        return full_value.decode("utf-8", errors="replace")
    if isinstance(full_value, str):
        return full_value
    return str(full_value)


# ===========================================================================
# DecodedTree findings
# ===========================================================================
#
# Each ChildFinding observed inside a decoded payload becomes one SARIF
# result. The decode chain that led to the finding (one or more decode
# layers, possibly nested through ancestor DecodedNodes) is encoded as a
# codeFlow whose threadFlow walks step-by-step from the on-disk artifact
# location, through every decode layer, to the inner finding's synthetic
# location.
#
# Decode-only metadata (pickle warnings, DER classifications, indicators,
# stop reasons that did not produce a ChildFinding) are NOT surfaced as
# SARIF results. The rules engine has already decided what counts as a
# finding worth surfacing; SARIF carries those forward. Decode metadata
# without a corresponding ChildFinding is structural context, not an
# alert.


def make_results_for_decoded_node(
    node: DecodedNode,
    indices: dict[str, int],
    use_srcroot: bool = False,
) -> list[dict]:
    """Build SARIF results for a DecodedNode and all its descendants.

    Walks the tree depth-first and emits one SARIF result per
    ChildFinding reached. Nodes without ChildFindings produce no
    results directly but still contribute their decode chain to
    descendants' codeFlows.

    Args:
        node: the DecodedNode to walk. Top-level callers pass each
            entry of DecodedTree.nodes; recursion traverses
            node.children with the parent stack accumulated
            internally.
        indices: the signal_id-to-rule-index map produced by
            make_rules_array() in pydepgate.reporters.sarif.rules.
            Used to set result.ruleIndex on each emitted result.
            Raises KeyError if a ChildFinding's signal_id is not
            in the map; the catalog should always cover every
            signal that can fire, so a miss indicates a real bug.
        use_srcroot: when True, ancestor outer-finding steps in
            the codeFlow receive uriBaseId=PROJECTROOT for their
            real on-disk paths. Synthetic decoded URIs are never
            srcroot-rooted (they have no project-relative form).

    Returns:
        A list of SARIF result dicts. Empty when the node and its
        descendants contain no ChildFindings.
    """
    return _walk_decoded_node(
        node=node,
        indices=indices,
        use_srcroot=use_srcroot,
        ancestors=(),
    )


def _walk_decoded_node(
    *,
    node: DecodedNode,
    indices: dict[str, int],
    use_srcroot: bool,
    ancestors: tuple[DecodedNode, ...],
) -> list[dict]:
    """Recursive walker for DecodedNode trees.

    Emits results for this node's ChildFindings, then recurses
    into node.children with the ancestor stack extended.
    """
    results: list[dict] = []

    for child_finding in node.child_findings:
        results.append(
            _make_decoded_result(
                child_finding=child_finding,
                node=node,
                ancestors=ancestors,
                indices=indices,
                use_srcroot=use_srcroot,
            )
        )

    extended_ancestors = ancestors + (node,)
    for child_node in node.children:
        results.extend(
            _walk_decoded_node(
                node=child_node,
                indices=indices,
                use_srcroot=use_srcroot,
                ancestors=extended_ancestors,
            )
        )

    return results


def _make_decoded_result(
    *,
    child_finding: ChildFinding,
    node: DecodedNode,
    ancestors: tuple[DecodedNode, ...],
    indices: dict[str, int],
    use_srcroot: bool,
) -> dict:
    """Build one SARIF result dict for a ChildFinding.

    The primary location is a synthetic decoded URI carrying the
    chain depth, line, and column. The codeFlow encodes the full
    path from the on-disk artifact through every ancestor's chain
    and this node's chain to the inner finding location.
    """
    severity = Severity(child_finding.severity)
    parent_path, _, _ = _parse_outer_location(node.outer_location)

    inner_coords = _decoded_finding_coords(
        chain_depth=len(node.chain),
        child_finding=child_finding,
    )
    inner_artifact_location = make_artifact_location_for_decoded(
        parent_path=parent_path,
        coords=inner_coords,
    )

    return {
        "ruleId": child_finding.signal_id,
        "ruleIndex": indices[child_finding.signal_id],
        "level": to_sarif_level(severity),
        "message": {"text": child_finding.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": inner_artifact_location,
                    "region": _make_region_for_child_finding(child_finding),
                },
            }
        ],
        "partialFingerprints": _make_decoded_partial_fingerprints(
            child_finding=child_finding,
            node=node,
            ancestors=ancestors,
            inner_uri=inner_artifact_location["uri"],
        ),
        "properties": _make_decoded_properties(
            child_finding=child_finding,
            node=node,
            ancestors=ancestors,
            severity=severity,
        ),
        "codeFlows": [
            _make_decode_chain_code_flow(
                child_finding=child_finding,
                node=node,
                ancestors=ancestors,
                use_srcroot=use_srcroot,
            )
        ],
    }


def _parse_outer_location(location: str) -> tuple[str, int, int]:
    """Parse a 'path:line:column' string from DecodedNode.outer_location.

    Uses rpartition twice so paths containing colons (Windows drive
    letters, URI-like internal paths) survive intact. The two
    trailing components are always line and column; everything
    before is path.

    Returns (path, line, column). On a malformed location that does
    not parse cleanly, returns (location, 0, 0) as a defensive
    fallback rather than raising. The caller's region builder
    normalizes line=0 to startLine=1 anyway, so the fallback
    produces valid SARIF even on malformed input.
    """
    path_part, _, column_str = location.rpartition(":")
    path, _, line_str = path_part.rpartition(":")
    if not path or not line_str or not column_str:
        return location, 0, 0
    try:
        line = int(line_str)
        column = int(column_str)
    except ValueError:
        return location, 0, 0
    return path, line, column


def _decoded_finding_coords(
    *,
    chain_depth: int,
    child_finding: ChildFinding,
) -> dict:
    """Build the coords dict for a ChildFinding's synthetic URI.

    Always includes layer (the chain depth at which the inner
    finding fired) and line. column is included only when present
    and non-negative; the URI helper coerces values via str() and
    would emit 'column=None' otherwise.

    Key insertion order is fixed (layer, line, column) so the
    resulting URI query string is deterministic across runs, which
    matters for fingerprint stability.
    """
    coords: dict = {"layer": chain_depth, "line": child_finding.line}
    column = child_finding.column
    if column is not None and column >= 0:
        coords["column"] = column
    return coords


def _make_region_for_child_finding(child_finding: ChildFinding) -> dict:
    """Build the region dict for a ChildFinding's primary location.

    Mirrors _make_region's normalization: line < 1 falls back to 1
    for SARIF validity; column < 0 (or None) is omitted; column 0
    becomes startColumn 1 via the +1 conversion that aligns
    pydepgate's 0-indexed columns with SARIF's 1-indexed.
    """
    line = child_finding.line if child_finding.line >= 1 else 1
    region = {"startLine": line}
    column = child_finding.column
    if column is not None and column >= 0:
        region["startColumn"] = column + 1
    return region


def _make_decoded_partial_fingerprints(
    *,
    child_finding: ChildFinding,
    node: DecodedNode,
    ancestors: tuple[DecodedNode, ...],
    inner_uri: str,
) -> dict:
    """Build partialFingerprints for a ChildFinding-derived result.

    Hash inputs differ from the ScanResult path: the path component
    is the synthetic decoded URI of the inner finding, which is
    deterministic for the same artifact bytes. The context
    component captures the full chain from the artifact root
    (every ancestor's outer_signal_id and chain, plus this node's)
    so the same inner finding reached via a different decode path
    produces a different fingerprint. The description is included
    so two findings of the same signal_id at the same line with
    different matched content do not collide.
    """
    parts: list[str] = [child_finding.description]
    for ancestor in ancestors:
        parts.append(ancestor.outer_signal_id)
        parts.append(".".join(ancestor.chain))
    parts.append(node.outer_signal_id)
    parts.append(".".join(node.chain))
    context = "|".join(parts)

    return {
        "primaryLocationLineHash": primary_location_line_hash(
            rule_id=child_finding.signal_id,
            internal_path=inner_uri,
            line=child_finding.line,
            context=context,
        ),
    }


def _make_decoded_properties(
    *,
    child_finding: ChildFinding,
    node: DecodedNode,
    ancestors: tuple[DecodedNode, ...],
    severity: Severity,
) -> dict:
    """Build the properties dict for a ChildFinding-derived result.

    Properties differ from the ScanResult path:
      - pydepgate.analyzer is derived from the signal_id prefix
        rather than read from a Signal field (ChildFinding does
        not carry the analyzer name).
      - pydepgate.via_decode_chain is the full layer-kind sequence
        from the artifact root through every ancestor's chain into
        this node's chain.
      - pydepgate.outer_signal_id is the root outer_signal_id (the
        signal that triggered the outermost decode in this lineage).
      - pydepgate.decode_depth is the recursion depth at which this
        node sits; useful for distinguishing alerts that come from
        deeper-nested chains.

    pydepgate.confidence and pydepgate.scope are NOT emitted on
    decoded results because ChildFinding is a flattened shape that
    does not carry them. Reaching back to the original Signal
    would require plumbing changes to decode_payloads.py that are
    out of scope here.
    """
    full_chain: list[str] = []
    for ancestor in ancestors:
        full_chain.extend(ancestor.chain)
    full_chain.extend(node.chain)

    root_outer = ancestors[0] if ancestors else node

    return {
        "security-severity": to_security_severity(severity),
        "pydepgate.analyzer": analyzer_for_signal(child_finding.signal_id),
        "pydepgate.via_decode_chain": full_chain,
        "pydepgate.outer_signal_id": root_outer.outer_signal_id,
        "pydepgate.decode_depth": node.depth,
    }


def _make_decode_chain_code_flow(
    *,
    child_finding: ChildFinding,
    node: DecodedNode,
    ancestors: tuple[DecodedNode, ...],
    use_srcroot: bool,
) -> dict:
    """Build the codeFlows[0] entry for a ChildFinding-derived result.

    The threadFlow walks the entire decode lineage step by step:

      1. For each ancestor (oldest first):
           - one step at the ancestor's outer-finding location
             (real on-disk artifact path)
           - one step per layer in the ancestor's chain (synthetic
             decoded URI with layer-only coords)
      2. One step at this node's outer-finding location.
      3. One step per layer in this node's chain.
      4. One final step at the inner finding's synthetic location
         with layer, line, and column coords.

    executionOrder is monotonic across the entire walk. nestingLevel
    increments for each decode layer and stays at the deepest level
    for the inner finding step.
    """
    locations: list[dict] = []
    counters = _ChainCounters()

    for ancestor in ancestors:
        _emit_node_steps(
            locations=locations,
            counters=counters,
            walk_node=ancestor,
            use_srcroot=use_srcroot,
        )

    _emit_node_steps(
        locations=locations,
        counters=counters,
        walk_node=node,
        use_srcroot=use_srcroot,
    )

    locations.append(
        _thread_flow_inner_finding_step(
            parent_path=_parse_outer_location(node.outer_location)[0],
            chain_depth=len(node.chain),
            child_finding=child_finding,
            execution_order=counters.execution_order,
            nesting_level=counters.nesting_level,
        )
    )
    counters.execution_order += 1

    return {"threadFlows": [{"locations": locations}]}


class _ChainCounters:
    """Mutable counters for executionOrder and nestingLevel.

    Used internally during codeFlow construction so the recursive
    emission helpers can advance the counters as they go without
    threading return values.
    """

    def __init__(self) -> None:
        self.execution_order = 0
        self.nesting_level = 0


def _emit_node_steps(
    *,
    locations: list[dict],
    counters: _ChainCounters,
    walk_node: DecodedNode,
    use_srcroot: bool,
) -> None:
    """Append one outer-finding step plus one step per chain layer.

    Mutates locations and counters in place. The outer-finding step
    uses the on-disk artifact path; chain layer steps use the
    synthetic decoded URI scheme with layer-only coords.
    """
    path, line, column = _parse_outer_location(walk_node.outer_location)

    locations.append(
        _thread_flow_outer_step(
            path=path,
            line=line,
            column=column,
            signal_id=walk_node.outer_signal_id,
            outer_length=walk_node.outer_length,
            execution_order=counters.execution_order,
            nesting_level=counters.nesting_level,
            use_srcroot=use_srcroot,
        )
    )
    counters.execution_order += 1

    for layer_index, layer_kind in enumerate(walk_node.chain, start=1):
        counters.nesting_level += 1
        locations.append(
            _thread_flow_layer_step(
                parent_path=path,
                layer_number=layer_index,
                layer_kind=layer_kind,
                execution_order=counters.execution_order,
                nesting_level=counters.nesting_level,
            )
        )
        counters.execution_order += 1


def _thread_flow_outer_step(
    *,
    path: str,
    line: int,
    column: int,
    signal_id: str,
    outer_length: int,
    execution_order: int,
    nesting_level: int,
    use_srcroot: bool,
) -> dict:
    """One threadFlowLocation for an outer finding (real artifact path)."""
    region: dict = {"startLine": line if line >= 1 else 1}
    if column >= 0:
        region["startColumn"] = column + 1

    return {
        "location": {
            "physicalLocation": {
                "artifactLocation": make_artifact_location(
                    path, use_srcroot=use_srcroot
                ),
                "region": region,
            },
            "message": {
                "text": (f"outer finding: {signal_id} " f"({outer_length} bytes)"),
            },
        },
        "executionOrder": execution_order,
        "nestingLevel": nesting_level,
    }


def _thread_flow_layer_step(
    *,
    parent_path: str,
    layer_number: int,
    layer_kind: str,
    execution_order: int,
    nesting_level: int,
) -> dict:
    """One threadFlowLocation for a single decode layer.

    The artifactLocation uses the synthetic pydepgate-decoded:
    scheme with the parent path and a layer-only coords dict.
    These steps have no region; the layer represents a transform
    over the whole decoded blob, not a position within it.
    """
    return {
        "location": {
            "physicalLocation": {
                "artifactLocation": make_artifact_location_for_decoded(
                    parent_path=parent_path,
                    coords={"layer": layer_number},
                ),
            },
            "message": {
                "text": f"decode layer {layer_number}: {layer_kind}",
            },
        },
        "executionOrder": execution_order,
        "nestingLevel": nesting_level,
    }


def _thread_flow_inner_finding_step(
    *,
    parent_path: str,
    chain_depth: int,
    child_finding: ChildFinding,
    execution_order: int,
    nesting_level: int,
) -> dict:
    """One threadFlowLocation for the inner finding.

    The artifactLocation includes layer, line, and column coords
    so the URI uniquely identifies the inner finding's position
    inside the decoded payload. The region carries the same line
    and column for SARIF consumers that read region directly.
    """
    return {
        "location": {
            "physicalLocation": {
                "artifactLocation": make_artifact_location_for_decoded(
                    parent_path=parent_path,
                    coords=_decoded_finding_coords(
                        chain_depth=chain_depth,
                        child_finding=child_finding,
                    ),
                ),
                "region": _make_region_for_child_finding(child_finding),
            },
            "message": {
                "text": (
                    f"inner finding: {child_finding.signal_id} "
                    f"({child_finding.description})"
                ),
            },
        },
        "executionOrder": execution_order,
        "nestingLevel": nesting_level,
    }
