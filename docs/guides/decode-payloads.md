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
maximum recursion depth of N. A depth of 0 (the default) disables decoding
entirely. A depth of 4 is sufficient for most real-world attacks; the LiteLLM
1.82.8 attack chain terminates at depth 3.

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
section below the main findings showing each decode step:

```
Decoded payload tree

  setup.py :: ENC001 @ line 12
  └── [layer 0] base64 -> python_source (1.2 KB)
      └── [layer 1] base64 -> python_source (980 B)
          └── [layer 2] python_source
              ├── DYN002  exec() called with a non-literal argument
              └── STDLIB001  subprocess.Popen() called
```

Each node shows the decode transform applied, the classified terminal type,
the size of the decoded content, and any signals found inside it. The tree
preserves the full chain from the outer literal down to the innermost payload.

### Severity filter on the decoded tree

`--min-severity` applies to the decoded tree as a presentation filter.
Decoding itself runs over every payload-bearing finding regardless of severity.
A low-severity outer finding that decodes to a critical inner one is still
captured. The filter preserves chain context: a low-severity ancestor with a
high-severity descendant is kept so the chain remains readable.

## IOC output modes

`--decode-iocs` controls whether pydepgate writes sidecar files alongside the
report. It accepts three values:

**`off`** (default): No sidecar files. The decoded tree appears in the report
only.

**`hashes`**: Writes a plaintext `.iocs.txt` sidecar file next to the scanned
artifact (or at the path given to `--decode-location`). The sidecar contains
hash records: SHA256 and SHA512 of each decoded payload layer, with the
containing file hash and artifact hash for forensic chaining.

**`full`**: Writes a ZipCrypto-encrypted `.zip` archive containing three files:
`report.txt`, `sources.txt`, and `iocs.txt`. Also writes a plaintext `.iocs.txt`
sidecar adjacent to the archive. The archive is always produced, including a
`NOFINDINGS_` stub when no payloads are found, so downstream tooling can rely
on archive presence as a signal.

```bash
pydepgate scan --peek --decode-payload-depth 4 \
    --decode-iocs full \
    some-package.whl
```

### Archive naming

Archives are named using the artifact identity, a UTC timestamp, and a status
prefix:

```
FINDINGS_some-package-1.0.0-py3-none-any_20260510T143022Z.zip
NOFINDINGS_some-package-1.0.0-py3-none-any_20260510T143022Z.zip
```

The `FINDINGS_` / `NOFINDINGS_` prefix makes downstream filtering trivial.

### Archive password

The archive uses ZipCrypto encryption with the default password `infected`,
following the malware research community convention. This is an
AV-friendliness measure, not a confidentiality mechanism. ZipCrypto is
cryptographically broken; the archive is not a secure container.

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

### Compression mode

Archives use DEFLATE compression by default. Use `STORED` for forensic-grade
preservation (no compression, exact byte-for-byte representation):

```bash
pydepgate scan --peek --decode-payload-depth 4 \
    --decode-iocs full \
    --decode-archive-compression stored \
    some-package.whl
```

### Output location

By default, sidecar files and archives land in the current directory. Specify
a different directory with `--decode-location`:

```bash
pydepgate scan --peek --decode-payload-depth 4 \
    --decode-iocs full \
    --decode-location /var/log/pydepgate/iocs \
    some-package.whl
```

The directory must exist. The filename within it is generated automatically.

## All decode flags

| Flag | Env variable | Default | Description |
|---|---|---|---|
| `--peek` | `PYDEPGATE_PEEK` | off | Enable the payload-peek enricher |
| `--peek-depth` | `PYDEPGATE_PEEK_DEPTH` | 5 | Max decode depth in the enricher pass |
| `--peek-budget` | `PYDEPGATE_PEEK_BUDGET` | 10 MB | In-flight byte budget; bounds decompression |
| `--peek-min-length` | `PYDEPGATE_PEEK_MIN_LENGTH` | 64 | Minimum literal length to attempt decoding |
| `--peek-chain` | `PYDEPGATE_PEEK_CHAIN` | off | Verbose per-layer hex dumps in the enricher output |
| `--decode-payload-depth` | `PYDEPGATE_DECODE_PAYLOAD_DEPTH` | 3 (disabled when unset) | Max recursion depth for the decode pipeline |
| `--decode-iocs` | `PYDEPGATE_DECODE_IOCS` | `off` | IOC output mode: `off`, `hashes`, `full` |
| `--decode-location` | `PYDEPGATE_DECODE_LOCATION` | current dir | Directory for sidecar and archive output |
| `--decode-archive-password` | `PYDEPGATE_DECODE_ARCHIVE_PASSWORD` | `infected` | Archive password |
| `--decode-archive-stored` | (none) | `False` | Applies Stored compression instead of Deflate |

CLI flags take precedence over environment variables when both are set.

## SARIF integration

When `--format sarif` and `--decode-payload-depth` are both set, the decoded
tree is threaded into the SARIF renderer. Findings reached through the decode
pipeline appear as SARIF results with `codeFlows` encoding the attack chain.
The scan computes the decoded tree once and reuses it for both the SARIF output
and the file-writing decode pass; you do not pay the cost of running the decode
driver twice.

See [SARIF Integration](sarif-integration.md) for the consumer side.