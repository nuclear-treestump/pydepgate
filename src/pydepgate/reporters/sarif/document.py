"""pydepgate.reporters.sarif.document

Assembles a complete SARIF 2.1.0 document from a ScanResult
and an optional DecodedTree.

The public entry points are:

  assemble_document(result, decoded_tree, srcroot, scan_mode)
      Builds the real document. Called by the package's
      render() function on the happy path.

  assemble_fallback_document(error_message)
      Builds a minimal valid SARIF document with
      executionSuccessful=False and a notification carrying
      the failure reason. Called by render() when
      assemble_document raises.

Document shape (top-level keys, in emission order):

  $schema       JSON schema URI for SARIF 2.1.0
  version       SARIF spec version string
  runs[0]       single run per scan
    tool        driver identity plus the rule catalog
    results     ScanResult findings followed by
                DecodedTree findings
    invocations one entry recording executionSuccessful
                and any toolExecutionNotifications
    automationDetails  category for cross-run grouping
    originalUriBaseIds always emitted; PROJECTROOT entry
                       carries the srcroot URI when set
                       and an empty placeholder URI
                       otherwise

Result ordering: ScanResult findings appear first in the
order they appear in result.findings. DecodedTree results
follow, in the order produced by walking
decoded_tree.nodes. Within each DecodedNode walk,
ChildFindings appear in tree-traversal order.

Severity filtering and rule application happen upstream of
this module. Suppressed findings are excluded by passing
only result.findings (not result.suppressed_findings).
Diagnostics carried on the ScanResult are mapped into
toolExecutionNotifications with level 'warning'.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydepgate.cli.subcommands.version import get_version

from pydepgate.reporters.sarif._constants import (
    PROJECTROOT_PLACEHOLDER_URI,
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    TOOL_INFORMATION_URI,
    TOOL_NAME,
    TOOL_ORGANIZATION,
)
from pydepgate.reporters.sarif.results import (
    make_result,
    make_results_for_decoded_node,
)
from pydepgate.reporters.sarif.rules import make_rules_array
from pydepgate.reporters.sarif.uris import SRCROOT_BASE_ID

if TYPE_CHECKING:
    from pydepgate.engines.base import ScanResult
    from pydepgate.enrichers.decode_payloads import DecodedTree


def assemble_document(
    result: "ScanResult",
    decoded_tree: "DecodedTree | None",
    *,
    srcroot: str | None = None,
    scan_mode: str | None = None,
) -> dict:
    """Build a complete SARIF 2.1.0 document.

    Args:
        result: the ScanResult from the main scan pass.
            Findings are read from result.findings;
            suppressed findings are intentionally excluded
            (they have a separate audit channel).
            Diagnostics are mapped into the invocation's
            toolExecutionNotifications.
        decoded_tree: optional DecodedTree from the decode
            pass. None when decode is disabled. When
            provided, each top-level node is walked and one
            SARIF result is emitted per ChildFinding
            reached.
        srcroot: optional srcroot path. When provided,
            per-result artifactLocations on real on-disk
            paths receive uriBaseId=PROJECTROOT, and the
            originalUriBaseIds.PROJECTROOT entry carries
            this value as its URI. When None, results carry
            no uriBaseId and the PROJECTROOT entry receives
            an empty placeholder URI.
        scan_mode: optional override for the scan-mode
            segment of automationDetails.id. When None,
            defaults to result.artifact_kind.value (one of
            "wheel", "sdist", "installed_env", "loose_file"
            in the current ArtifactKind enum). Callers with
            additional context (deep mode, custom modes)
            pass an explicit value.

    Returns:
        A SARIF document as a dict, JSON-serializable and
        suitable for direct json.dump output.

    Raises:
        Any exception from the underlying helpers
        (make_rules_array, make_result,
        make_results_for_decoded_node, get_version). The
        package's render() function catches these and
        falls back to assemble_fallback_document.
    """
    use_srcroot = srcroot is not None
    rules, indices = make_rules_array()

    results: list[dict] = []
    for finding in result.findings:
        results.append(
            make_result(
                signal=finding.signal,
                severity=finding.severity,
                internal_path=finding.context.internal_path,
                indices=indices,
                use_srcroot=use_srcroot,
            )
        )

    if decoded_tree is not None:
        for node in decoded_tree.nodes:
            results.extend(
                make_results_for_decoded_node(
                    node=node,
                    indices=indices,
                    use_srcroot=use_srcroot,
                )
            )

    effective_scan_mode = scan_mode or result.artifact_kind.value

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": _build_tool(rules),
                "results": results,
                "invocations": [_build_invocation(result)],
                "automationDetails": {
                    "id": f"{TOOL_NAME}/{effective_scan_mode}/",
                    "runID": result.scan_id,
                },
                "originalUriBaseIds": _build_uri_base_ids(srcroot),
            },
        ],
    }


def assemble_fallback_document(error_message: str) -> dict:
    """Build a minimal SARIF document for assembly failures.

    Used by the package's render() function when
    assemble_document raises. The result is a valid SARIF
    2.1.0 document that consumers can parse without errors,
    but it carries executionSuccessful=False and a
    notification with the failure reason. CI consumers see
    that the SARIF generation itself failed and can
    investigate without a parse error blocking ingestion.

    The fallback intentionally omits the rules catalog,
    automationDetails, and originalUriBaseIds. The
    assumption is that whatever caused assemble_document to
    fail might also affect those subsystems, so the safest
    fallback is to emit only the bare minimum.

    Args:
        error_message: text describing what went wrong. The
            text appears as the notification message and
            should not include sensitive content; it is
            written into the SARIF document a consumer may
            display verbatim.

    Returns:
        A SARIF document as a dict, JSON-serializable.
    """
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_INFORMATION_URI,
                        "organization": TOOL_ORGANIZATION,
                        "RunID": "N/A",
                    },
                },
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": False,
                        "toolExecutionNotifications": [
                            {
                                "level": "error",
                                "message": {
                                    "text": (
                                        f"pydepgate SARIF assembly "
                                        f"failed: {error_message}"
                                    ),
                                },
                            },
                        ],
                    },
                ],
            },
        ],
    }


def _build_tool(rules: list[dict]) -> dict:
    """Build the runs[0].tool block.

    The driver carries identity (name, organization,
    informationUri), the running pydepgate version
    (semanticVersion), and the full rule catalog. Consumers
    use semanticVersion to track tool changes separately
    from code changes; the rules array gives them the
    metadata for every signal pydepgate can emit.
    """
    return {
        "driver": {
            "name": TOOL_NAME,
            "semanticVersion": get_version(),
            "informationUri": TOOL_INFORMATION_URI,
            "organization": TOOL_ORGANIZATION,
            "rules": rules,
        },
    }


def _build_invocation(result: "ScanResult") -> dict:
    """Build the single invocation entry.

    executionSuccessful is True on the happy path because
    a ScanResult was produced. Diagnostics carried on the
    result (parser failures, analyzer crashes that did not
    abort the scan) become toolExecutionNotifications with
    level 'warning'. The notifications array is omitted
    entirely when there are no diagnostics, per SARIF
    optionality.
    """
    invocation: dict = {"executionSuccessful": True}
    if result.diagnostics:
        invocation["toolExecutionNotifications"] = [
            {
                "level": "warning",
                "message": {"text": text},
            }
            for text in result.diagnostics
        ]
    return invocation


def _build_uri_base_ids(srcroot: str | None) -> dict:
    """Build the originalUriBaseIds entry.

    Always emitted so SARIF consumers can resolve any
    uriBaseId references on per-result artifactLocations.
    When srcroot is None, the PROJECTROOT entry carries the
    placeholder URI defined in _constants. When srcroot is
    provided, that value is the URI.

    The dict has exactly one key (PROJECTROOT) regardless
    of srcroot; future srcroot variants would add more
    keys here. SARIF allows tools to declare any number of
    URI base IDs; consumers reference them by name.
    """
    return {
        SRCROOT_BASE_ID: {
            "uri": srcroot if srcroot is not None else PROJECTROOT_PLACEHOLDER_URI,
        },
    }
