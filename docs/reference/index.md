---
title: Reference
nav_order: 4
has_children: true
---
# Reference

Authoritative specification for pydepgate's contracts, schemas, and
configuration surface. These pages describe what pydepgate guarantees, not
how to use it. For task-oriented walkthroughs, see the [Guides](../guides/index.md).

| Reference | Description |
|---|---|
| [Exit Codes](exit-codes.md) | The four exit codes, their stability contract, and CI implications |
| [Output Formats](output-formats.md) | Human output anatomy, JSON schema v3, SARIF 2.1.0 structure, decoded-tree JSON schema v1 |
| [Environment Variables](environment-variables.md) | Every `PYDEPGATE_*` variable, accepted values, and precedence |
| [Rules File](rules-file.md) | `pydepgate.gate` TOML/JSON format, field reference, and precedence model |
| [Signals](signals.md) | All signal IDs across all analyzer namespaces with default severities |