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
| `--ci` | | `false` | `PYDEPGATE_CI` | Implies `--min-severity high --no-color`. Shorthand for CI pipelines. |
| `--strict-exit` | | `false` | `PYDEPGATE_STRICT_EXIT` | Compute exit code from all findings regardless of `--min-severity`. Use when you want filtered display but unfiltered exit behavior. |

### Rules

| Flag | Values | Default | Env variable | Description |
|---|---|---|---|---|
| `--rules-file` | path | auto-discover | `PYDEPGATE_RULES_FILE` | Path to a `.gate` rules file. Auto-discovery checks `./pydepgate.gate` then `~/.config/pydepgate/pydepgate.gate`. |

### Payload peek

| Flag | Values | Default | Env variable | Description |
|---|---|---|---|---|
| `--peek` | | `false` | `PYDEPGATE_PEEK` | Enable the payload-peek enricher. Required for `--decode-payload-depth` to produce output. |
| `--peek-depth` | integer | `5` | `PYDEPGATE_PEEK_DEPTH` | Maximum decode depth in the enricher pass. Capped at 10. |
| `--peek-budget` | integer (bytes) | `10485760` | `PYDEPGATE_PEEK_BUDGET` | In-flight byte budget. Bounds decompression bomb exposure. |
| `--peek-min-length` | integer | `64` | `PYDEPGATE_PEEK_MIN_LENGTH` | Minimum literal length to attempt decoding |
| `--peek-chain` | | `false` | `PYDEPGATE_PEEK_CHAIN` | Print verbose per-layer hex dumps in the enricher output |

### Decode pipeline

| Flag | Values | Default | Env variable | Description |
|---|---|---|---|---|
| `--decode-payload-depth` | integer | `0` | `PYDEPGATE_DECODE_PAYLOAD_DEPTH` | Maximum recursion depth for the decode pipeline. `0` disables decoding. Requires `--peek`. |
| `--decode-iocs` | `off`, `hashes`, `full` | `off` | `PYDEPGATE_DECODE_IOCS` | IOC sidecar output mode. See [Decode Payloads](../guides/decode-payloads.md). |
| `--decode-location` | path | current dir | `PYDEPGATE_DECODE_LOCATION` | Directory for sidecar and archive output |
| `--decode-archive-password` | string | `infected` | `PYDEPGATE_DECODE_ARCHIVE_PASSWORD` | Password for the `full` mode encrypted archive |
| `--decode-archive-compression` | `deflated`, `stored` | `deflated` | `PYDEPGATE_DECODE_ARCHIVE_COMPRESSION` | Archive compression mode. Use `stored` for byte-verifiable forensic archives. |

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