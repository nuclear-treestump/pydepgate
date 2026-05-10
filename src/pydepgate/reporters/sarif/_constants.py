"""pydepgate.reporters.sarif._constants

Shared constants for the SARIF reporter package.

These values surface in every emitted SARIF document. They
live in their own module so __init__.py and document.py can
both import from them without circular-import issues.

Tool-identity values (TOOL_NAME, TOOL_INFORMATION_URI,
TOOL_ORGANIZATION) appear in runs[0].tool.driver. Schema and
version constants drive consumer validation of the document
structure. Bumping any of these is a behavior change worth
calling out in the changelog because consumers may rely on
exact-match comparisons.
"""

from __future__ import annotations

# Tool identity. Surfaced as runs[0].tool.driver fields.
TOOL_NAME = "pydepgate"
TOOL_INFORMATION_URI = "https://github.com/nuclear-treestump/pydepgate"
TOOL_ORGANIZATION = "Nuclear Treestump"

# SARIF spec version and schema location. Updating either
# requires consumer-side coordination since some validators
# pin the schema URL.
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

# Placeholder URI used in originalUriBaseIds.PROJECTROOT
# when the caller has not provided a srcroot. Empty string
# is a valid URI reference per RFC 3986. Callers with a real
# srcroot value substitute it at document-assembly time.
PROJECTROOT_PLACEHOLDER_URI = ""
