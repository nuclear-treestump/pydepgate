"""pydepgate.reporters.sarif

SARIF renderer for pydepgate.

SARIF (Static Analysis Results Interchange Format) is a
standardized JSON format for static analysis tool output,
consumable by GitHub code scanning, GitLab vulnerability
reports, and many other security tools.

This renderer is unique in the reporters package: it consumes
both ScanResult AND DecodedTree subjects in a single output
document, because SARIF expects one document per analysis run
and pydepgate's two finding sources logically belong to the
same run. Every other renderer in this package consumes exactly
one subject.

Currently a stub. The actual SARIF 2.1.0 emission, the
finding-to-result translation, and the CLI flow restructuring
needed to compute the optional DecodedTree before format
dispatch are tracked as separate work for v0.4. See
ROADMAP.md.

This module exposes a single public function: render(). Callers
import the module and dispatch via it:

    from pydepgate.reporters import sarif
    sarif.render(result, decoded_tree, sys.stdout)

The decoded_tree argument is None when the user did not request
payload decoding (--decode-payload-depth was not set). The
current stub ignores both arguments; the production
implementation will use them.
"""

from __future__ import annotations

from typing import TextIO

from pydepgate.engines.base import ScanResult
from pydepgate.enrichers.decode_payloads import DecodedTree


def render(
    result: ScanResult,
    decoded_tree: DecodedTree | None,
    stream: TextIO,
) -> None:
    """SARIF output is under development. Emit a clear message.

    Signature accepts both subjects in anticipation of the
    production SARIF 2.1.0 implementation. The stub body
    ignores both arguments.

    Args:
        result: The ScanResult whose findings will populate
            the SARIF run's results array.
        decoded_tree: Optional DecodedTree carrying decoded-
            payload findings to merge into the same run.
            None when the user did not request decoding.
        stream: Output text stream to write SARIF document to.
    """
    stream.write(
        "SARIF output format is part of pydepgate's GitHub Advanced "
        "Security integration and is currently under development. It "
        "will produce SARIF 2.1.0 output suitable for GitHub code "
        "scanning, GitLab vulnerability reports, and other SARIF "
        "consumers.\n"
        "\n"
        "Planned for v0.4. Track progress in ROADMAP.md.\n"
        "\n"
        "For now, use --format json for machine-readable output.\n"
    )