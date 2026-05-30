---
title: db
parent: CLI
nav_order: 4
---
# pydepgate db

Inspect and query the pydepgate evidence database.

```
pydepgate db init
pydepgate db path
pydepgate db status
pydepgate db list-runs [--limit N]
pydepgate db query --package NAME [--version VER] [--limit N]
pydepgate db query --artifact-sha512 SHA512 [--limit N]
pydepgate db explain --run-id UUID [--format human|json]
```

The evidence database is pydepgate's persistent memory layer. It stores
records of scan runs, scanned artifacts, static findings, decoded payload
trees, and CVE findings. It is populated by
[`pydepgate scan --save-to-db`](scan.md) and
[`pydepgate cvescan --save-to-db`](cvescan.md).

The evidence database is separate from the CVE database managed by
[`pydepgate cvedb`](cvedb.md). The CVE database is a derived cache that
can be rebuilt at any time from upstream OSV data. The evidence database
contains your own scan history and should not be deleted casually.

## Before using

If you have not run a scan with `--save-to-db` yet, the database does not
exist. You can create it explicitly:

```bash
pydepgate db init
```

Or let the first `--save-to-db` scan create it automatically.

## Actions

### `init`

Create the evidence database at the default location. If the database
already exists, `init` reports its path and last-modified timestamp and
exits cleanly without modifying anything.

```bash
pydepgate db init
```

On first run:

```
Evidence database created: /home/codespace/.local/share/pydepgate/pdgdb/evidence.db
```

If the database already exists:

```
Evidence database already exists: /home/codespace/.local/share/pydepgate/pdgdb/evidence.db
Last modified: 2026-05-30T05:08:09.857237+00:00
```

### `path`

Print the database file path and exit. The database does not need to exist
for `path` to succeed.

```bash
pydepgate db path
```

```
/home/codespace/.local/share/pydepgate/pdgdb/evidence.db
```

Useful for scripting:

```bash
sqlite3 "$(pydepgate db path)" ".tables"
```

### `status`

Show record counts and metadata for the evidence database.

```bash
pydepgate db status
```

```
Evidence database: /home/codespace/.local/share/pydepgate/pdgdb/evidence.db
  Schema version:     1
  Created by:         0.5.0
  Created at:         2026-05-30T04:58:16.939436+00:00
  Last modified:      2026-05-30T05:08:09.857237+00:00
  Scan runs:          3
  Scanned artifacts:  3
  Static findings:    46
  Decoded nodes:      12
  CVE findings:       10
```

**Fields:**

- **Schema version**: the database schema version. Used to detect
  incompatibilities when pydepgate is upgraded.
- **Created by**: the pydepgate version that created this database.
- **Created at**: ISO 8601 UTC timestamp of database creation.
- **Last modified**: ISO 8601 UTC timestamp of the most recent write. Updated
  after every `scan --save-to-db` and `cvescan --save-to-db` invocation.
- **Scan runs**: total number of scan invocations stored.
- **Scanned artifacts**: total number of artifact records. Each scan run
  produces one artifact record.
- **Static findings**: total number of static analysis findings across all
  runs. Suppressed findings are not counted.
- **Decoded nodes**: total number of decoded payload tree nodes across all
  runs. Only populated when `--decode-payload-depth` was used with
  `--save-to-db`.
- **CVE findings**: total number of CVE findings across all `cvescan` runs.

`status` exits with code 3 if the database does not exist or has an
incompatible schema, and prints a directive to run `pydepgate db init` or
`pydepgate scan --save-to-db`.

### `list-runs`

List scan runs in reverse chronological order.

```bash
pydepgate db list-runs
```

```
RUN ID                                CMD       VER         ARTS  STATIC    CVE  STARTED
--------------------------------------------------------------------------------------
019e7748-4f5e-7510-b047-f93b66184720  cvescan   0.5.0          1       0     10  2026-05-30T05:08:08.938858+00:00
019e7740-2fb8-7aee-9a53-51489b41b201  scan      0.5.0          1      43      0  2026-05-30T04:59:33.007703+00:00
019e773f-79e2-76a9-a545-2e350430737e  scan      0.5.0          1       3      0  2026-05-30T04:58:31.133902+00:00
```

**Columns:**

- **RUN ID**: the UUID4 of the scan run. Pass this to `db explain` to see the
  full record.
- **CMD**: `scan` or `cvescan`.
- **VER**: the pydepgate version that produced the run.
- **ARTS**: number of artifact records for the run. Currently always 1.
- **STATIC**: number of static findings. Always 0 for `cvescan` runs.
- **CVE**: number of CVE findings. Always 0 for `scan` runs.
- **STARTED**: ISO 8601 UTC timestamp of the scan.

The Run ID printed at the end of a `pydepgate scan` or `pydepgate cvescan`
invocation under `Your Run ID:` is the same UUID shown here.

#### `--limit N`

Maximum number of runs to show. Default is 50. Pass `0` to show all runs.

```bash
pydepgate db list-runs --limit 10
pydepgate db list-runs --limit 0
```

### `query`

Query artifact records by package name or artifact hash. Returns one row
per matching artifact, newest first.

#### By package name

```bash
pydepgate db query --package litellm
```

```
019e7748-...  wheel         litellm==1.82.8                     0 static     10 CVE  4d3b3ea1b93b8714...  2026-05-30T05:08:08...
019e7740-...  wheel         litellm==1.82.8                    43 static      0 CVE  4d3b3ea1b93b8714...  2026-05-30T04:59:33...
019e773f-...  wheel         litellm==1.82.8                     3 static      0 CVE  4d3b3ea1b93b8714...  2026-05-30T04:58:31...
```

Package name matching is case-insensitive and normalizes hyphens to
underscores, so `litellm`, `LiteLLM`, and `lite-llm` all match the same
stored records.

Add `--version` to filter by a specific version string:

```bash
pydepgate db query --package litellm --version 1.82.8
```

#### By artifact SHA-512

```bash
pydepgate db query --artifact-sha512 4d3b3ea1b93b8714d9a900b9d63d9657...
```

The full 128-character hex SHA-512 is required. Matching is
case-insensitive.

#### `--limit N`

Maximum number of results to show. Default is 50. Pass `0` for all.

```bash
pydepgate db query --package requests --limit 5
```

### `explain`

Show the full stored record for a single scan run.

```bash
pydepgate db explain --run-id 019e7740-2fb8-7aee-9a53-51489b41b201
```

```
Run ID:      019e7740-2fb8-7aee-9a53-51489b41b201
Command:     scan
Producer:    cli0
Version:     0.5.0
Started:     2026-05-30T04:59:33.007703+00:00

Artifact:    litellm-1.82.8-py3-none-any.whl
Kind:        wheel
Package:     litellm==1.82.8
SHA-512:     4d3b3ea1b93b8714d9a900b9d63d9657...
Scanned at:  2026-05-30T04:59:33.007703+00:00

Findings (43):
  [CRITICAL]  STDLIB001     litellm_init.pth:1:28  call to subprocess.Popen() ...
  [CRITICAL]  DENS010       litellm_init.pth:1:68  string literal at line 1 ...
  ...

Decoded nodes (12):
  depth=0  DENS010  litellm_init.pth:1:68  chain=[(none)]  final=python_source(34501b)  stop=leaf_terminal
    [CRITICAL]  DYN002        line 1:15  exec() at module scope with non-literal argument
  ...
```

For a `cvescan` run:

```
Run ID:      019e7748-4f5e-7510-b047-f93b66184720
Command:     cvescan
Producer:    cli0
Version:     0.5.0
Started:     2026-05-30T05:08:08.938858+00:00

Artifact:    litellm-1.82.8-py3-none-any.whl
Kind:        wheel
Package:     litellm==1.82.8
SHA-512:     4d3b3ea1b93b8714d9a900b9d63d9657...
Scanned at:  2026-05-30T05:08:08.938858+00:00

Findings (0):
  (none)

CVE findings (10):
  [CRITICAL]  CVE-2026-35030        range-fixed  LiteLLM: Authentication bypass via OIDC ...
  [CRITICAL]  CVE-2026-42208        range-fixed  LiteLLM has SQL Injection in Proxy API key ...
  ...
```

`explain` exits with code 3 if the run ID is not found.

#### `--run-id UUID`

Required. The UUID4 of the run to explain. Copy this from `db list-runs`
output or from the `Your Run ID:` line printed at the end of a scan.

#### `--format human|json`

Output format. Default is `human`. Use `json` for structured output suitable
for downstream processing:

```bash
pydepgate db explain --run-id UUID --format json
```

JSON output includes all stored fields: run metadata, artifact identity,
static findings, decoded nodes with their child findings, and CVE findings.

## Database location

The evidence database lives at
`$XDG_DATA_HOME/pydepgate/pdgdb/evidence.db`, following the XDG Base
Directory Specification. On most Linux systems this resolves to
`~/.local/share/pydepgate/pdgdb/evidence.db`.

Unlike the CVE database (which lives under `$XDG_CACHE_HOME` because it can
be rebuilt from upstream data), the evidence database lives under
`$XDG_DATA_HOME` because it contains your own scan history.

Override the base directory via the standard XDG environment variable:

```bash
XDG_DATA_HOME=/data pydepgate db status
# resolves to /data/pydepgate/pdgdb/evidence.db
```

There is no `PYDEPGATE_DB_PATH` variable. Use `XDG_DATA_HOME` to relocate
the entire data directory.

## Schema versioning and migration

The evidence database schema is versioned. Unlike the CVE database, which is
always rebuilt from upstream data on schema changes, the evidence database is
migrated in place. When pydepgate detects a schema version older than the
current build expects, it applies pending migrations automatically at the
start of any `--save-to-db` write.

When a mismatch is detected by a read-only command like `db status`, it exits
with code 3 and prints a directive:

```
pdgdb schema version mismatch: database has version 1, this build expects version 2.
Run 'pydepgate db migrate' to upgrade.
```

The `db migrate` command will be added in a future release. In v0.5.0,
migrations are applied automatically on the first write after an upgrade.

## Relationship to other commands

The evidence database records are produced by two commands:

| Command | What it stores |
|---|---|
| `pydepgate scan --save-to-db` | Static findings, file identities, decoded payload trees |
| `pydepgate cvescan --save-to-db` | CVE findings |

The `db` subcommand is read-only (except for `init`). It queries what those
two commands have written. There is no way to add or edit records through
`db` directly.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `3` | Database does not exist, schema mismatch, or run ID not found. |
