# Getting Started

This page walks through installing pydepgate, running a first scan, and
understanding the output. It assumes no prior familiarity with the tool.

## Install

```bash
pip install pydepgate
```

Verify the install:

```bash
pydepgate version
```

```
pydepgate 0.4.0
```

Requirements: Python 3.11 or later. No third-party dependencies are installed.

## Your first scan

The primary subcommand is `scan`. Give it a wheel, a source distribution, or
an installed package name.

### Scanning a wheel

```bash
pydepgate scan some-package-1.0.0-py3-none-any.whl
```

pydepgate unpacks the wheel in memory, routes each file through triage, runs
the analyzer pipeline on in-scope files, applies the rules engine to produce
severity-rated findings, and prints a human-readable report to stdout.

### Scanning an installed package

```bash
pydepgate scan requests
```

pydepgate locates the package via `importlib.metadata`, finds the installed
files, and scans them in place. Useful for auditing an existing environment.

### Scanning a single file

```bash
pydepgate scan --single suspicious_module.py
pydepgate scan --single something.pth
```

`--single` bypasses the wheel/sdist/package dispatch and analyzes one file
directly. Useful when iterating on a suspicious file without wrapping it in a
distribution. File kind is inferred from the filename; use `--as` to override:

```bash
pydepgate scan --single ambiguous.py --as init_py
```

Valid kinds: `setup_py`, `init_py`, `pth`, `sitecustomize`, `usercustomize`,
`library_py`.

## Reading the output

A clean scan produces no output and exits with code `0`.

A scan with findings produces a report that looks like this (abbreviated):

```
some-package-1.0.0-py3-none-any.whl

  setup.py [CRITICAL]

    [CRITICAL] DYN002 dynamic_execution — exec() called with a non-literal argument
      Line 14: exec(base64.b64decode(PAYLOAD))
      Rule: DYN_EXEC_NOLITERAL

    [HIGH] ENC001 encoding_abuse — high-entropy base64-encoded literal detected
      Line 12: PAYLOAD = "SGVsbG8gV29ybGQ..."
      Rule: ENC_HIGHENTROPYB64

  ▓▓▓▓▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  ████ 2 findings  (1 CRITICAL, 1 HIGH)

Artifact SHA256: a3f1...
Artifact SHA512: 9b2c...
```

The report contains:

- The artifact name and path
- Per-file sections, each with the highest severity in the file
- Per-finding entries showing signal ID, signal name, human description, source
  line, and the rule that promoted the signal to a finding
- The finding-distribution map: an SSH-randomart-style rendering that shows
  where findings cluster across the file at what severity
- Summary counts by severity
- Artifact-level SHA256 and SHA512 for forensic chaining

### Severity levels

From highest to lowest: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.

The default scan reports all severities. Use `--min-severity` to filter:

```bash
pydepgate scan --min-severity high some-package.whl
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean. No findings at or above `--min-severity`. |
| `1` | Findings present, none HIGH or CRITICAL. |
| `2` | At least one HIGH or CRITICAL finding. |
| `3` | Tool error. Scan could not complete. |

In CI, fail the build on exit code `2`:

```bash
pydepgate scan some-package.whl
if [ $? -eq 2 ]; then
    echo "Blocking findings detected."
    exit 1
fi
```

Or use `--ci`, which sets `--min-severity high` and `--no-color` and exits `2`
on any finding (since `--min-severity high` filters everything below HIGH before
the exit code is computed):

```bash
pydepgate scan --ci some-package.whl
```

## Using explain

`pydepgate explain` looks up the documentation for a signal ID or rule.

```bash
pydepgate explain DYN002
```

Output includes the signal description, why it matters, common evasion shapes,
and the default rule that applies to it. This is the fastest way to understand
why a finding fired and whether it warrants investigation.

List every signal pydepgate knows about:

```bash
pydepgate explain --list
```

This outputs every signal ID across all analyzers with a one-line description.
The full reference is also in [Signals Reference](reference/signals.md).

## Enabling payload decoding

By default, pydepgate reports high-entropy encoded literals as findings but
does not attempt to decode them. Enable the decode pipeline with
`--decode-payload-depth`:

```bash
pydepgate scan --peek --decode-payload-depth 4 some-package.whl
```

`--peek` enables the payload-peek enricher, which safely partial-decodes
encoded literals in the analyzer pass. `--decode-payload-depth` enables the
separate recursive decode pipeline, which follows chains of encoded payloads up
to the specified depth and reports what it finds at each layer.

The decode pipeline never executes content. It runs base64, hex, zlib, gzip,
bzip2, and lzma decoding only. Pickle data is detected but never deserialized.
Decompression bombs are bounded by an in-flight byte budget.

For a full walkthrough of the decode pipeline, including IOC sidecar output and
encrypted archive generation, see [Decode Payloads](guides/decode-payloads.md).

## Next steps

- [CLI Reference: scan](cli/scan.md) for the complete flag reference
- [Output Formats](reference/output-formats.md) for JSON and SARIF output
- [CI Integration](guides/ci-integration.md) for GitHub Actions, GitLab CI, and pre-commit
- [Custom Rules](guides/custom-rules.md) for suppressing false positives or adjusting severities