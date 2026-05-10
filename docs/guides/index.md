---
title: Guides
nav_order: 3
has_children: true
---
# Guides

Task-oriented walkthroughs for specific use cases. Each guide covers one
topic end-to-end with working examples.

| Guide | Description |
|---|---|
| [CI Integration](ci-integration.md) | Wiring pydepgate into GitHub Actions, GitLab CI, Jenkins, Docker, and pre-commit |
| [Custom Rules](custom-rules.md) | Suppressing false positives, adjusting severities, and writing scoped rules with `pydepgate.gate` |
| [Decode Payloads](decode-payloads.md) | Using the recursive decode pipeline, IOC sidecar output, and encrypted archive generation |
| [SARIF Integration](sarif-integration.md) | Generating SARIF 2.1.0 output and ingesting it into GitHub Code Scanning |

For reference material (flag tables, JSON schema, exit code contract), see
the [Reference](../reference/index.md) section.