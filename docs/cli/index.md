---
title: CLI
nav_order: 2
has_children: true
---

# CLI Reference

pydepgate is invoked as:

```
pydepgate [global flags] <subcommand> [subcommand flags] [arguments]
```

Global flags work on either side of the subcommand. Both of the following
are equivalent:

```bash
pydepgate --format json scan package.whl
pydepgate scan package.whl --format json
```

## Subcommands

| Subcommand | Status | Description |
|---|---|---|
| [scan](scan.md) | Available | Scan a wheel, sdist, installed package, or single file |
| [cvedb](cvedb.md) | Available | Download the PyPI `all.zip` from OSV.dev and import it into a SQLite DB |
| [explain](explain.md) | Available | Look up signal and rule documentation |
| [preflight](preflight.md) | Under development | Walk an installed Python environment |
| [exec](exec.md) | Under development | Run a script with runtime interdiction |
| [version](version.md) | Available | Print pydepgate version |
| [completions](completions.md) | Available | Generate shell tab-completion scripts |
| `help` | Available | Show help for pydepgate or a specific subcommand |

## Global flags

Global flags apply to every subcommand. They can be placed before or after
the subcommand name.

### Output and formatting

| Flag | Values | Default | Env variable | Description |
|---|---|---|---|---|
| `--format` | `human`, `json`, `sarif` | `human` | `PYDEPGATE_FORMAT` | Output format |
| `--color` | `auto`, `always`, `never` | `auto` | `PYDEPGATE_COLOR` | ANSI color control. `auto` emits color when stdout is a TTY. `always` forces color through pipes. `never` disables color. |
| `--no-color` | | | `PYDEPGATE_NO_COLOR`, `NO_COLOR` | Alias for `--color=never`. Kept for compatibility. |
| `--no-map` | | `false` | `PYDEPGATE_NO_MAP` | Suppress the finding-distribution map in human output |

### Severity and exit behavior

| Flag | Values | Default | Env variable | Description |
|---|---|---|---|---|
| `--min-severity` | `info`, `low`, `medium`, `high`, `critical` | `info` | `PYDEPGATE_MIN_SEVERITY` | Suppress findings below this severity in output |
| `--ci` | | `false` | `PYDEPGATE_CI` | CI mode: if `--format` is not set, forces `json`; if `--color` is `auto`, forces `never`. Does not change `--min-severity`. |
| `--strict-exit` | | `false` | `PYDEPGATE_STRICT_EXIT` | Compute exit code from all findings regardless of `--min-severity`. Use when you want filtered display but unfiltered exit behavior. |

### Rules

| Flag | Values | Default | Env variable | Description |
|---|---|---|---|---|
| `--rules-file` | path | auto-discover | `PYDEPGATE_RULES_FILE` | Path to a `.gate` rules file. Auto-discovery checks `./pydepgate.gate` then `~/.config/pydepgate/pydepgate.gate`. |

### Payload peek

| Flag | Values | Default | Env variable | Description |
|---|---|---|---|---|
| `--peek` | | `false` | `PYDEPGATE_PEEK` | Enable the payload-peek enricher. Required for `--decode-payload-depth` to produce output. |
| `--peek-depth` | integer | `3` | `PYDEPGATE_PEEK_DEPTH` | Maximum decode depth in the enricher pass. Floor 1, ceiling 10. |
| `--peek-budget` | integer (bytes) | `524288` (512 KB) | `PYDEPGATE_PEEK_BUDGET` | Cumulative byte budget across all unwrap layers. Floor 1024. |
| `--peek-min-length` | integer | `1024` | `PYDEPGATE_PEEK_MIN_LENGTH` | Minimum literal length, in bytes, before the enricher attempts to decode it. Floor 16. |
| `--peek-chain` | | `false` | `PYDEPGATE_PEEK_CHAIN` | Print verbose per-layer hex dumps in the enricher output |

### Decode pipeline

| Flag | Values | Default | Env variable | Description |
|---|---|---|---|---|
| `--decode-payload-depth` | integer | unset (decode disabled) | `PYDEPGATE_DECODE_PAYLOAD_DEPTH` | Maximum recursion depth for the decode pipeline. Must be in `[1, 8]` when enabled. Requires `--peek`. |
| `--decode-location` | path | `./decoded/` | `PYDEPGATE_DECODE_LOCATION` | Output directory for decode reports, sidecars, and archives. Created if missing. |
| `--decode-format` | `text`, `json` | `text` | `PYDEPGATE_DECODE_FORMAT` | Format of the decode-pipeline report. `text` for a human-readable tree; `json` for structured downstream tooling. |
| `--decode-iocs` | `off`, `hashes`, `full` | `off` | `PYDEPGATE_DECODE_IOCS` | IOC sidecar mode. See [Decode Payloads](../guides/decode-payloads.md). |
| `--decode-archive-password` | string | `infected` | `PYDEPGATE_DECODE_ARCHIVE_PASSWORD` | Password for the `full` mode encrypted archive |
| `--decode-archive-stored` | | `false` | (none) | Use STORED compression instead of DEFLATE for the `full` mode archive. Slightly larger archive but bypasses zlib entirely. Useful when byte-verifiable archive contents matter. |

### SARIF

| Flag | Values | Default | Env variable | Description |
|---|---|---|---|---|
| `--sarif-srcroot` | path | | `PYDEPGATE_SARIF_SRCROOT` | Source root for SARIF `PROJECTROOT` URI base. Only meaningful with `--format sarif`. Emits a warning if set with other formats. |

## Precedence

When a flag is set via both an environment variable and the command line, the
command line wins. When a flag is set via both an environment variable and
the default, the environment variable wins.

```
explicit CLI flag  >  environment variable  >  built-in default
```

## Tab completion

Shell completion is available for bash, zsh, and fish. See
[completions](completions.md) for setup instructions.
