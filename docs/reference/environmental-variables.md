---
title: Environmental Variables
parent: Reference
nav_order: 1
---
# Environment Variables

All pydepgate flags can be set via environment variables. When both a CLI flag
and an environment variable are set, the CLI flag wins. When only an
environment variable is set, it provides the default. When neither is set, the
built-in default applies.

```
explicit CLI flag  >  environment variable  >  built-in default
```

Boolean variables accept `1`, `true`, `yes`, or `on` (case-insensitive) as
truthy. Any other value, including empty string and unset, is falsy.

Integer variables are parsed strictly. A non-integer value falls back to the
built-in default and emits a warning to stderr.

---

## Output and format

### `PYDEPGATE_FORMAT`

Equivalent flag: `--format`

Sets the output format. Accepted values: `human`, `json`, `sarif`. Built-in
default: `human`.

```bash
PYDEPGATE_FORMAT=json pydepgate scan package.whl
```

### `PYDEPGATE_COLOR`

Equivalent flag: `--color`

Controls ANSI color output. Accepted values: `auto`, `always`, `never`.
Built-in default: `auto` (color when stdout is a TTY).

A value not in the accepted set is ignored and falls through to the
`NO_COLOR` check. It does not produce a warning.

```bash
PYDEPGATE_COLOR=always pydepgate scan package.whl | less -R
```

### `PYDEPGATE_NO_COLOR`

Equivalent flag: `--no-color`

Any truthy value sets color mode to `never`. Mirrors the behavior of the
standard `NO_COLOR` variable. The distinction: `PYDEPGATE_NO_COLOR` applies
only to pydepgate; `NO_COLOR` is a system-wide convention that many tools
respect.

```bash
PYDEPGATE_NO_COLOR=1 pydepgate scan package.whl
```

### `NO_COLOR`

Equivalent flag: `--no-color`

The [no-color.org](https://no-color.org) standard variable. Any truthy value
disables color output. Checked after `PYDEPGATE_COLOR`; an explicit
`PYDEPGATE_COLOR=always` overrides a system-wide `NO_COLOR=1`.

### `PYDEPGATE_NO_MAP`

Equivalent flag: `--no-map`

Any truthy value suppresses the finding-distribution map in human output.

```bash
PYDEPGATE_NO_MAP=1 pydepgate scan package.whl
```

---

## Severity and exit behavior

### `PYDEPGATE_MIN_SEVERITY`

Equivalent flag: `--min-severity`

Suppresses findings below this severity. Accepted values: `info`, `low`,
`medium`, `high`, `critical`. Built-in default: `info` (all findings shown).

```bash
PYDEPGATE_MIN_SEVERITY=high pydepgate scan package.whl
```

### `PYDEPGATE_CI`

Equivalent flag: `--ci`

Any truthy value enables CI mode. CI mode does two things:

1. If `--format` has not been explicitly set, sets it to `json`.
2. If `--color` is currently `auto`, sets it to `never`.

It does not change `--min-severity` or any other flag. Use
`PYDEPGATE_MIN_SEVERITY` separately if you want a severity threshold for CI.

Built-in default: `false`.

```bash
PYDEPGATE_CI=1 PYDEPGATE_MIN_SEVERITY=high pydepgate scan package.whl
```

### `PYDEPGATE_STRICT_EXIT`

Equivalent flag: `--strict-exit`

Any truthy value computes the exit code from all findings regardless of
`--min-severity`. Built-in default: `false`.

```bash
PYDEPGATE_STRICT_EXIT=1 pydepgate scan --min-severity high package.whl
```

---

## Rules

### `PYDEPGATE_RULES_FILE`

Equivalent flag: `--rules-file`

Path to a `.gate` rules file. When set, auto-discovery is skipped and only
this path is loaded. Built-in default: auto-discover `./pydepgate.gate` then
`~/.config/pydepgate/pydepgate.gate`.

```bash
PYDEPGATE_RULES_FILE=/etc/pydepgate/company.gate pydepgate scan package.whl
```

---

## Payload peek

### `PYDEPGATE_PEEK`

Equivalent flag: `--peek`

Any truthy value enables the payload-peek enricher. Required for
`PYDEPGATE_DECODE_PAYLOAD_DEPTH` to have any effect. Built-in default: `false`.

### `PYDEPGATE_PEEK_DEPTH`

Equivalent flag: `--peek-depth`

Maximum number of decode transformations the enricher applies to one literal.
Integer. Built-in default: `3`. Floor: `1`. Ceiling (CLI only): `10`.

A non-integer value falls back to `3` with a stderr warning.

### `PYDEPGATE_PEEK_BUDGET`

Equivalent flag: `--peek-budget`

Cumulative byte budget across all unwrap layers in the enricher. Bounds
decompression bomb exposure. Integer (bytes). Built-in default: `524288`
(512 KB). Floor: `1024`.

A non-integer value falls back to `524288` with a stderr warning.

### `PYDEPGATE_PEEK_MIN_LENGTH`

Equivalent flag: `--peek-min-length`

Minimum literal size in bytes before the enricher attempts to decode it.
Literals shorter than this are skipped. Integer. Built-in default: `1024`.
Floor: `16`.

Below 16 bytes the enricher cannot reliably detect magic-byte signatures.
A non-integer value falls back to `1024` with a stderr warning.

### `PYDEPGATE_PEEK_CHAIN`

Equivalent flag: `--peek-chain`

Any truthy value enables verbose per-layer hex dumps in human output. Built-in
default: `false`. JSON output always includes the full chain regardless of
this setting.

---

## Decode pipeline

### `PYDEPGATE_DECODE_PAYLOAD_DEPTH`

Equivalent flag: `--decode-payload-depth`

Maximum recursion depth for the decoded-payload pipeline. Setting this without
also setting `PYDEPGATE_PEEK=1` is a validation error. Integer. Must be in
`[1, 8]`. When unset, the decode pipeline is disabled. When the variable is
set to a non-integer value, the built-in default of `3` is used with a warning.

```bash
PYDEPGATE_PEEK=1 PYDEPGATE_DECODE_PAYLOAD_DEPTH=4 pydepgate scan package.whl
```

### `PYDEPGATE_DECODE_FORMAT`

Equivalent flag: `--decode-format`

Output format for the decode report written to the decode location. Accepted
values: `text`, `json`. Built-in default: `text`.

### `PYDEPGATE_DECODE_IOCS`

Equivalent flag: `--decode-iocs`

IOC sidecar output mode. Accepted values: `off`, `hashes`, `full`. Built-in
default: `off`. Setting this without `PYDEPGATE_PEEK=1` is a validation error.

### `PYDEPGATE_DECODE_LOCATION`

Equivalent flag: `--decode-location`

Directory for sidecar and archive output. When unset, output lands under
`./decoded/`. The directory is created if it does not exist.

### `PYDEPGATE_DECODE_ARCHIVE_PASSWORD`

Equivalent flag: `--decode-archive-password`

Password for the ZipCrypto-encrypted archive produced by `--decode-iocs=full`.
Built-in default: `infected` (the malware-research community convention).

Note: `--decode-archive-stored` (which switches the archive from DEFLATE to
STORED compression) deliberately has no corresponding environment variable. It
is a per-investigation flag, not a persistent configuration preference.

---

## SARIF

### `PYDEPGATE_SARIF_SRCROOT`

Equivalent flag: `--sarif-srcroot`

Source root path for SARIF `originalUriBaseIds.PROJECTROOT`. Empty string is
treated as unset. Only meaningful with `PYDEPGATE_FORMAT=sarif`; setting it
with other formats produces a soft warning to stderr but does not fail the run.

```bash
PYDEPGATE_FORMAT=sarif \
PYDEPGATE_SARIF_SRCROOT="$(pwd)" \
pydepgate scan package.whl > results.sarif
```

---

## Precedence notes

`PYDEPGATE_COLOR` takes precedence over `PYDEPGATE_NO_COLOR` and `NO_COLOR`
when its value is one of the accepted choices (`auto`, `always`, `never`).
If `PYDEPGATE_COLOR=always` and `NO_COLOR=1` are both set, color is enabled
because `PYDEPGATE_COLOR` is checked first.

`PYDEPGATE_NO_COLOR` and `NO_COLOR` are equivalent in effect. Both map to
`--color=never`. `PYDEPGATE_NO_COLOR` exists for cases where you want to
suppress color for pydepgate without affecting other tools that read `NO_COLOR`.

`PYDEPGATE_CI` is processed after argument parsing. Its effects on format and
color do not override explicit CLI flags or explicit values of those same
environment variables. The auto-flip of color to `never` only fires when the
effective color value at that point is `auto`.