"""pydepgate.reporters.decoded_tree.json

JSON renderer for pydepgate DecodedTree.

Emits a structured JSON representation of the decoded tree for
downstream tooling. Schema version 1: includes top-level
artifact_sha256 and artifact_sha512, plus per-node
containing_file_sha256 and containing_file_sha512, plus the IOC
data block.

This module exposes a single public function: render(). Callers
import the module and dispatch via it:

    from pydepgate.reporters.decoded_tree import json as tree_json
    tree_json.render(tree, include_source=True)

The module name 'json' shadows the stdlib 'json' module in the
package's own namespace, but Python's absolute-import default
ensures that the local `import json` at the top of this file
resolves to the stdlib module.
"""

from __future__ import annotations

import json

from pydepgate.enrichers.decode_payloads import DecodedNode, DecodedTree


def render(tree: DecodedTree, *, include_source: bool = True) -> str:
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