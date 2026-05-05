"""pydepgate.cli.reporter

Output rendering: residual transitional stub.

Most rendering has moved into the dedicated reporters/ package.
The remaining function, render_sarif_stub, will move to
reporters.sarif as render() in Phase 5 of the refactor, at which
point this file is deleted.

Until Phase 5 lands:
- Human and JSON ScanResult rendering live in
  pydepgate.reporters.scan_result.{human,json}.
- Decoded-tree rendering lives in pydepgate.reporters.decoded_tree.
  (after Phase 4).
- SARIF dispatch in scan.py continues to import render_sarif_stub
  from this file.
"""

from __future__ import annotations

from typing import TextIO


def render_sarif_stub(stream: TextIO) -> None:
    """SARIF output is under development. Emit a clear message."""
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