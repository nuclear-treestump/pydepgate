---
title: cvedb
parent: CLI
nav_order: 2
---
# pydepgate cvedb
Manage the local CVE database built from the OSV PyPI vulnerability feed.
```
pydepgate cvedb update
pydepgate cvedb status
pydepgate cvedb path
```

## Usage

Download and import the latest OSV PyPI snapshot:
```bash
pydepgate cvedb update
```

Show local database stats and metadata:
```bash
pydepgate cvedb status
```

Print the on-disk path of the local database:
```bash
pydepgate cvedb path
```

Run an update without progress bars (useful in CI or non-TTY contexts):
```bash
pydepgate cvedb update --no-bar
```

## Output

### `update`

`update` downloads the OSV PyPI snapshot, imports it, and prints a summary
to stderr:

```
Checking https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
  ok (22.1 MB)
Downloading 100% [█████████████████████████████████████████] 23214391/23214391  0.1s
Reading     100% [██████████████████████████████████████████████████] 19563/19563  3.2s
Parsing     100% [██████████████████████████████████████████████████] 19563/19563  1.2s
Writing     100% [██████████████████████████████████████████████████] 598426/598426  4.1s

Imported 16669 vulnerabilities in 21.0s
  Exact version rows:    535674
  Range rows:            20130
  Aliases:               25951
  Parse errors:          0
  No usable data:        2
  Total:                 581755

Database: /home/codespace/.cache/pydepgate/cvedb/pypi_osv.db
Snapshot SHA256: 6f978d0d66e5c99bb8363b62b2175576e2e027be83186b97b9b543e1262391d2

Vulnerability data: Open Source Vulnerability (OSV) Database (https://osv.dev), CC-BY 4.0.
Your Run ID: de65221a-b86f-4d4e-8998-6eb931db4524
```

**Summary fields:**

- **Exact version rows**: rows in the `affected_versions` table representing a specific vulnerable version string (e.g. `requests==2.6.0`). Sourced from each OSV record's explicit `versions` list. Also includes `ALL` sentinel rows for packages where every version is affected.
- **Range rows**: rows in the `affected_ranges` table representing a version constraint (e.g. `introduced=0, fixed=2.28.2`). Sourced from each OSV record's `ranges` events. Used by the PEP 440 range evaluator when an exact version match is not present.
- **Aliases**: rows in the `aliases` table. Each vulnerability may be known by multiple IDs (CVE, GHSA, PYSEC, MAL, and others). All aliases resolve to a single canonical ID.
- **Parse errors**: OSV records that could not be parsed (invalid JSON, missing ID field, or other structural problem). Nonzero here means some records were not imported; check `pydepgate cvedb status` for details.
- **No usable data**: records that referenced a PyPI package but contained neither an explicit versions list nor any version ranges. These are rare and represent gaps in upstream OSV data rather than pydepgate limitations.
- **Total**: sum of exact version rows, range rows, aliases, and parse errors.
- **Run ID**: UUID4 identifying this specific import invocation. Recorded in the database and surfaced by `pydepgate cvedb status`. Referenced in SARIF `automationDetails.id` when the CVE pass emits findings.

The download zip is deleted after a successful import. The database is
atomic: a failed import leaves the previous database intact.

### `status`

```
CVE database: /home/codespace/.cache/pydepgate/cvedb/pypi_osv.db
  Schema version:     2
  Records imported:   16669
  Range rows:         20130
  Last update:        2026-05-16T15:05:09.307856+00:00
  Last import run:    de65221a-b86f-4d4e-8998-6eb931db4524
  Snapshot SHA256:    6f978d0d66e5c99b...

Data source: Open Source Vulnerability (OSV) Database
License:     CC-BY 4.0
```

`Records imported` is the count of distinct canonical vulnerabilities (after
multi-contributor deduplication). `Range rows` is a live count from the table,
not a cached value, so it always reflects the current database state.
`Last import run` matches the Run ID printed at the end of `update`.

`status` exits with code 3 if the database does not exist or has an
incompatible schema version, and prints a directive to run `cvedb update`.

### `path`

```
/home/codespace/.cache/pydepgate/cvedb/pypi_osv.db
```

Prints the database path and exits. The database does not need to exist for
`path` to succeed. Useful for scripting:

```bash
sqlite3 "$(pydepgate cvedb path)" ".tables"
```

## Database location

The database lives at `$XDG_CACHE_HOME/pydepgate/cvedb/pypi_osv.db`,
following the XDG Base Directory Specification. On most Linux systems this
resolves to `~/.cache/pydepgate/cvedb/pypi_osv.db`. On macOS, if
`XDG_CACHE_HOME` is unset, the path falls back to
`~/.cache/pydepgate/cvedb/pypi_osv.db` (not `~/Library/Caches`).

Set `XDG_CACHE_HOME` to override the base:
```bash
XDG_CACHE_HOME=/data/cache pydepgate cvedb update
```

## Data source and attribution

Vulnerability data is sourced from the [OSV database](https://osv.dev) PyPI
feed, licensed [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Attribution is written into the database at import time and displayed by
`cvedb status`. pydepgate does not modify OSV data; it normalizes record
identifiers and deduplicates multi-contributor entries for the same CVE.

## Flags

### `--no-bar`

Suppress progress bars. Progress bars are also suppressed automatically
when stderr is not a TTY (e.g. in CI pipelines or when output is
redirected).

```bash
pydepgate cvedb update --no-bar
```

## Schema versioning

The database schema is versioned. A database created by an older version of
pydepgate may be incompatible with a newer one. When a mismatch is detected,
`cvedb status` and `cvedb update` both exit with an error and a directive to
rebuild:

```
CVE database has incompatible schema: expected version 2, found version 1
Run 'pydepgate cvedb update' to rebuild.
```

Schema version 2 adds the `affected_ranges` table. There is no in-place
migration; `update` always rebuilds the database atomically from the latest
snapshot.
