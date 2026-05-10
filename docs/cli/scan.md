# pydepgate scan

Scan a Python package or file for supply-chain malware patterns in startup vectors.

```
pydepgate scan [flags] <target>
pydepgate scan [flags] --single <path> [--as <kind>]
```

## Target dispatch

The positional `<target>` argument accepts three forms:

**Wheel or sdist path**: a path to a `.whl` or `.tar.gz` file on disk.

```bash
pydepgate scan some-package-1.0.0-py3-none-any.whl
pydepgate scan some-package-1.0.0.tar.gz
```

**Installed package name**: the name of a package currently installed in the
active Python environment, resolved via `importlib.metadata`.

```bash
pydepgate scan litellm
pydepgate scan requests
```

**Single file** (via `--single`): a single loose file, bypassing all
wheel/sdist/package dispatch. See [Single file mode](#single-file-mode) below.

## Scan-specific flags

### `--single <path>`

Analyze a single file directly instead of dispatching through the wheel,
sdist, or installed-package path. The file kind is inferred from the filename.
See [Single file mode](#single-file-mode) for full details.

Cannot be combined with a positional `<target>`.

### `--as <kind>`

Override the inferred file kind when using `--single`. Only valid with
`--single`.

Valid kinds:

| Kind | Description |
|---|---|
| `setup_py` | `setup.py` context. Most permissive: density rules promote to HIGH/CRITICAL. |
| `init_py` | `__init__.py` context |
| `pth` | `.pth` startup file |
| `sitecustomize` | `sitecustomize.py` context |
| `usercustomize` | `usercustomize.py` context |
| `library_py` | Ordinary library file. Used for deep-mode calibration. Density analyzer only. |

### `--deep`

Also analyze ordinary library `.py` files in the artifact, not just startup
vectors. Only the density analyzer runs on library files; the other analyzers
would produce unacceptable false-positive rates outside startup-vector context.

Files in excluded directories (`tests/`, `docs/`, and similar) are still
skipped regardless of `--deep`.

Cannot be combined with `--single`.

### `--no-bar`

Suppress the per-file progress bar during artifact scans. The bar is
automatically suppressed when stderr is not a TTY (piped output, CI runs,
redirected logs), so this flag is mainly for interactive terminals where
you want clean output. No effect in `--single` mode.

## Single file mode

`--single` bypasses dispatch and runs the analyzer directly on one file.
File kind is inferred from the filename by these rules:

- Files named `setup.py` are classified as `setup_py`.
- Files named `__init__.py` are classified as `init_py`.
- Files named `sitecustomize.py` are classified as `sitecustomize`.
- Files named `usercustomize.py` are classified as `usercustomize`.
- Files with a `.pth` extension are classified as `pth`.
- Any other `.py` file defaults to `setup_py` (the most permissive context,
  which surfaces every signal at realistic attack-shape severity).

Override with `--as` when the inferred kind is wrong:

```bash
# Analyze as __init__.py context even though the filename is ambiguous
pydepgate scan --single payload.py --as init_py

# Analyze with library rules to test density signals specifically
pydepgate scan --single generated_parser.py --as library_py
```

`setup_py` is the recommended `--as` value when iterating on new signals or
test fixtures, because it enables the highest severity promotions and
produces the most complete signal output.

## Global flags

All [global flags](index.md) apply to `scan`. The most commonly used ones
are summarized here.

### `--format`

```bash
pydepgate scan --format json package.whl
pydepgate scan --format sarif package.whl > results.sarif
```

`human` (default) renders ANSI-formatted output to stdout with the
finding-distribution map. `json` emits a structured JSON document. `sarif`
emits a SARIF 2.1.0 document. See
[Output Formats](../reference/output-formats.md) for schema details and
[SARIF Integration](../guides/sarif-integration.md) for GitHub Code Scanning
ingestion.

### `--min-severity`

```bash
pydepgate scan --min-severity high package.whl
```

Suppress findings below this severity in output and in the exit code
computation. Accepted values: `info`, `low`, `medium`, `high`, `critical`.

### `--ci`

```bash
pydepgate scan --ci package.whl
```

Implies `--min-severity high --no-color`. Standard shorthand for CI
pipelines. Suppresses informational signals that are too noisy for
automated blocking while preserving everything HIGH and CRITICAL.

### `--strict-exit`

When set, the exit code is computed from all findings regardless of
`--min-severity`. Useful when you want filtered display (showing only HIGH
and above) but want the exit code to reflect the full finding set.

```bash
# Display only HIGH+, but exit 2 if any finding exists at any severity
pydepgate scan --min-severity high --strict-exit package.whl
```

### `--rules-file`

```bash
pydepgate scan --rules-file ./company-rules.gate package.whl
```

Load a custom rules file. Auto-discovery checks `./pydepgate.gate` then
`~/.config/pydepgate/pydepgate.gate` when this flag is not set. See
[Custom Rules](../guides/custom-rules.md).

### `--peek` and decode flags

```bash
pydepgate scan --peek --decode-payload-depth 4 package.whl
```

`--peek` enables the payload-peek enricher. `--decode-payload-depth N`
enables the recursive decode pipeline. See the
[full global flags table](index.md#decode-pipeline) for all decode-related
flags and [Decode Payloads](../guides/decode-payloads.md) for a walkthrough.

### `--sarif-srcroot`

```bash
pydepgate scan --format sarif --sarif-srcroot /path/to/repo package.whl
```

Populate `originalUriBaseIds.PROJECTROOT` in SARIF output. Required for
correct path resolution in GitHub Code Scanning. Only meaningful with
`--format sarif`. See [SARIF Integration](../guides/sarif-integration.md).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean. No findings at or above `--min-severity`. |
| `1` | Findings present, none HIGH or CRITICAL. |
| `2` | At least one HIGH or CRITICAL finding. |
| `3` | Tool error. Scan could not complete. |

These are stable as of v0.1. See [Exit Codes](../reference/exit-codes.md).

## Examples

Scan a wheel with default settings:

```bash
pydepgate scan package-1.0.0-py3-none-any.whl
```

Scan a wheel in CI, fail on HIGH or CRITICAL:

```bash
pydepgate scan --ci package-1.0.0-py3-none-any.whl
```

Scan and emit JSON for downstream processing:

```bash
pydepgate scan --format json package.whl > results.json
```

Scan with payload decoding and IOC archive output:

```bash
pydepgate scan \
    --peek \
    --decode-payload-depth 4 \
    --decode-iocs full \
    --decode-location ./iocs \
    package.whl
```

Scan a single file and see all signals:

```bash
pydepgate scan --single suspicious.py
```

Scan a single file and force a specific analysis context:

```bash
pydepgate scan --single ambiguous.py --as setup_py
```

Scan an installed package:

```bash
pydepgate scan litellm
```

Emit SARIF for GitHub Code Scanning:

```bash
pydepgate scan \
    --format sarif \
    --sarif-srcroot "$PWD" \
    --peek \
    --decode-payload-depth 4 \
    package.whl > pydepgate.sarif
```