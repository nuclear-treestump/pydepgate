---
title: Decode Payloads
parent: Guides
nav_order: 3
---
# Decode Payloads

pydepgate's decode pipeline recursively unwraps encoded payloads found during
a scan, reports what is inside each layer, and optionally produces an IOC
sidecar or encrypted archive for incident response workflows.

The pipeline never executes any content. It applies base64, hex, zlib, gzip,
bzip2, and lzma decoding only. Pickle data is detected and classified but
never deserialized. Decompression bombs are bounded by a configurable
in-flight byte budget.

## Enabling decoding

Two flags work together to enable the full decode path:

```bash
pydepgate scan --peek --decode-payload-depth 4 some-package.whl
```

`--peek` enables the payload-peek enricher in the analyzer pass. Without it,
the decoder has no payload-bearing findings to start from. The enricher
safely partial-decodes encoded literals, classifies the terminal content,
and emits `ENC002` when an unwrap chain is nested.

`--decode-payload-depth N` enables the recursive decode pipeline with a
maximum recursion depth of N. N must be in `[1, 8]`. When the flag is
unset (the default), the decode pipeline is disabled. A depth of 4 is
sufficient for most real-world attacks; the LiteLLM 1.82.8 attack chain
terminates at depth 3.

### Peek-only mode

You can use `--peek` without `--decode-payload-depth`. In this mode the
enricher runs during the analyzer pass and produces a decoded context block
in the human report showing what the literal decodes to, but the recursive
pipeline does not run and no sidecar or archive is produced.

```bash
pydepgate scan --peek some-package.whl
```

## The decoded-payload tree

When `--decode-payload-depth` is set, the report includes a tree-shaped
section showing each decode step. Each node shows the decode transform
applied, the classified terminal type, the size of the decoded content, and
any signals found inside it. The tree preserves the full chain from the outer
literal down to the innermost payload.

### Severity filter on the decoded tree

`--min-severity` applies to the decoded tree as a presentation filter.
Decoding itself runs over every payload-bearing finding regardless of
severity. A low-severity outer finding that decodes to a critical inner one
is still captured. The filter preserves chain context with a "keep for
context" rule: a node stays if its own severity meets the threshold OR if
any of its descendants do, so chains are not broken when only the inner
finding is severe. Leaf child findings (the non-recursive ones at the bottom
of a chain) are filtered strictly, dropped if their own severity is below
threshold.

## IOC output modes

`--decode-iocs` controls whether pydepgate writes sidecar files alongside the
report. It accepts three values:

**`off`** (default). A single plaintext file containing only the tree report.
When the decoded tree is empty, no file is written; a stderr note is written
instead.

**`hashes`**. Two plaintext files: the tree report plus a `.iocs.txt`
sidecar containing SHA256 and SHA512 hashes of every decoded payload, with
the chain summary and location for each. Hash records use a fixed two-token
line shape (`decoded_sha256  <hex>`) so a one-liner like
`grep '^decoded_sha256' iocs.txt | awk '{print $2}'` extracts every hash for
batch lookup. Skipped on empty trees, same as `off` mode.

**`full`**. A ZipCrypto-encrypted `.zip` archive plus a plaintext `.iocs.txt`
sidecar. The archive contains three files inside a subdirectory matching the
sanitized target name:

```
<target>/report.txt    Tree report (same shape as off-mode output)
<target>/sources.txt   Per-layer decoded source dumps with header
                       blocks and line-numbered bodies
<target>/iocs.txt      Hash records (same content as the sidecar)
```

The sidecar lives next to the archive, not inside it, so you can batch-process
IOC hashes without unzipping. Unlike `off` and `hashes`, `full` mode always
produces output: an empty tree results in a `NOFINDINGS_` stub archive with
the same structure but stub markers inside. This consistency lets downstream
triage tooling rely on archive presence as a signal that the scan completed.

```bash
pydepgate scan --peek --decode-payload-depth 4 \
    --decode-iocs full \
    some-package.whl
```

### Output filename convention

All decode output files use a consistent naming pattern:

```
{STATUS}_{timestamp}_{target}{extension}
```

`STATUS` is `FINDINGS` when the decoded tree contains nodes, `NOFINDINGS`
when it does not. `timestamp` is UTC, formatted `YYYY-MM-DD_HH-MM-SS` (no
`Z` suffix). `target` is the basename of the artifact identity, sanitized
to `[A-Za-z0-9._-]` with leading separators stripped. `extension` is `.txt`
for text output, `.json` for JSON, `.zip` for the encrypted archive, or
`.iocs.txt` for the plaintext IOC sidecar.

Example:

```
FINDINGS_2026-04-29_21-57-15_litellm-1.82.8-py3-none-any.whl.zip
FINDINGS_2026-04-29_21-57-15_litellm-1.82.8-py3-none-any.whl.iocs.txt
```

Re-running the same command produces a new file with a new timestamp; the
previous file is left untouched.

### Archive password

The archive uses ZipCrypto encryption with the default password `infected`,
following the malware research community convention. AV vendors recognize
archives with that password as do-not-scan and will not quarantine them
mid-investigation. ZipCrypto is cryptographically broken; this is an
AV-friendliness measure, not a confidentiality mechanism.

Override the password:

```bash
pydepgate scan --peek --decode-payload-depth 4 \
    --decode-iocs full \
    --decode-archive-password "my-password" \
    some-package.whl
```

Or via environment variable:

```bash
PYDEPGATE_DECODE_ARCHIVE_PASSWORD="my-password" \
    pydepgate scan --peek --decode-payload-depth 4 --decode-iocs full some-package.whl
```

### Archive compression

Archives use DEFLATE compression by default. The `--decode-archive-stored`
boolean flag switches the archive to STORED compression instead (no zlib
involvement). The archive is slightly larger but byte-verifiable, which is
useful when forensic preservation matters:

```bash
pydepgate scan --peek --decode-payload-depth 4 \
    --decode-iocs full \
    --decode-archive-stored \
    some-package.whl
```

`--decode-archive-stored` deliberately has no environment-variable
equivalent. It is a per-investigation choice, not a persistent preference.

### Output location

By default, sidecar files and archives land in `./decoded/` relative to the
current working directory. The directory is created if it does not exist.
Specify a different directory with `--decode-location`:

```bash
pydepgate scan --peek --decode-payload-depth 4 \
    --decode-iocs full \
    --decode-location /var/log/pydepgate/iocs \
    some-package.whl
```

The filename within the directory follows the `{STATUS}_{timestamp}_{target}`
pattern described above.

## All decode flags

| Flag | Env variable | Default | Description |
|---|---|---|---|
| `--peek` | `PYDEPGATE_PEEK` | off | Enable the payload-peek enricher |
| `--peek-depth` | `PYDEPGATE_PEEK_DEPTH` | `3` | Max decode depth in the enricher pass. Floor 1, ceiling 10. |
| `--peek-budget` | `PYDEPGATE_PEEK_BUDGET` | `524288` (512 KB) | Cumulative byte budget across unwrap layers. Floor 1024. |
| `--peek-min-length` | `PYDEPGATE_PEEK_MIN_LENGTH` | `1024` | Minimum literal length to attempt decoding. Floor 16. |
| `--peek-chain` | `PYDEPGATE_PEEK_CHAIN` | off | Verbose per-layer hex dumps in the enricher output |
| `--decode-payload-depth` | `PYDEPGATE_DECODE_PAYLOAD_DEPTH` | unset (decode disabled) | Max recursion depth for the decode pipeline. Must be in `[1, 8]` when enabled. Requires `--peek`. |
| `--decode-location` | `PYDEPGATE_DECODE_LOCATION` | `./decoded/` | Output directory. Created if missing. |
| `--decode-format` | `PYDEPGATE_DECODE_FORMAT` | `text` | `text` for the human-readable tree report; `json` for structured downstream tooling. |
| `--decode-iocs` | `PYDEPGATE_DECODE_IOCS` | `off` | IOC output mode: `off`, `hashes`, `full` |
| `--decode-archive-password` | `PYDEPGATE_DECODE_ARCHIVE_PASSWORD` | `infected` | Archive password |
| `--decode-archive-stored` | (none) | off | Use STORED compression instead of DEFLATE for the `full` mode archive |

CLI flags take precedence over environment variables when both are set.

## SARIF integration

When `--format sarif` and `--decode-payload-depth` are both set, the decoded
tree is threaded into the SARIF renderer. Findings reached through the decode
pipeline appear as SARIF results with `codeFlows` encoding the attack chain.
The scan computes the decoded tree once and reuses it for both the SARIF
output and the file-writing decode pass; you do not pay the cost of running
the decode driver twice.

See [SARIF Integration](sarif-integration.md) for the consumer side.