---
title: cvescan
parent: CLI
nav_order: 3
---
# pydepgate cvescan
Scan a Python package artifact against the local CVE database built from the
OSV PyPI vulnerability feed.

```
pydepgate cvescan package.whl
pydepgate cvescan package.whl --format json
pydepgate cvescan package.whl --min-severity high
```

`cvescan` is a package-level scanner. It reads artifact metadata to identify
the package name and version, then queries the local `cvedb` database for known
vulnerability matches.

It does not replace `pydepgate scan`. The normal `scan` command inspects files
inside an artifact for startup vectors and suspicious code. `cvescan` checks the
artifact identity against known vulnerability data.

## Before scanning

Build the local CVE database first:

```bash
pydepgate cvedb update
```

You can check the database with:

```bash
pydepgate cvedb status
```

`cvescan` uses the same database managed by [`pydepgate cvedb`](cvedb.html).

## Usage

Scan a wheel:

```bash
pydepgate cvescan litellm-1.82.8-py3-none-any.whl
```

Emit machine-readable JSON:

```bash
pydepgate cvescan litellm-1.82.8-py3-none-any.whl --format json
```

Only display high and critical findings:

```bash
pydepgate cvescan litellm-1.82.8-py3-none-any.whl --min-severity high
```

Use a specific database path:

```bash
pydepgate cvescan package.whl --db-path /path/to/pypi_osv.db
```

Continue without failing if the database is missing or incompatible:

```bash
pydepgate cvescan package.whl --ignore-missing-db
```

## Supported artifacts

`cvescan` currently supports Python wheel artifacts (`.whl`).

The scanner reads package identity from wheel metadata, preferring the
`.dist-info/METADATA` `Name` and `Version` fields. Filename-derived identity is
used only as a fallback when metadata is missing or incomplete.

## Output

### Human output

Human output is the default:

```text
CVE scan: litellm 1.82.8
Database: /home/codespace/.cache/pydepgate/cvedb/pypi_osv.db

Findings: 10

  CVE-2026-35030 [CRITICAL]
    Aliases: CVE-2026-35030, GHSA-jjhc-v7c2-5hh6
    Match: range-fixed
    Summary: LiteLLM: Authentication bypass via OIDC userinfo cache key collision
    CVSS v4: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N
    Range: ECOSYSTEM introduced=0 fixed=1.83.0 last_affected=<empty>

  PYSEC-2026-2 [UNKNOWN]
    Aliases: MAL-2026-2144, PYSEC-2026-2
    Match: exact-version
    Summary: Malicious code in litellm (PyPI)

Vulnerability data: Open Source Vulnerability (OSV) Database (https://osv.dev), CC-BY 4.0.
```

The report starts with the package identity and database path, then lists
matching vulnerabilities.

### JSON output

Use `--format json` for automation:

```bash
pydepgate cvescan package.whl --format json
```

JSON output uses schema identifier `pydepgate.cvescan.v1` and includes:

- `package_name`
- `normalized_package_name`
- `package_version`
- `database_path`
- `findings`
- `total_findings`
- `displayed_findings`
- `unevaluated_ranges`
- `warnings`
- `attribution`
- `artifact_metadata`

Example shape:

```json
{
  "schema": "pydepgate.cvescan.v1",
  "package_name": "litellm",
  "normalized_package_name": "litellm",
  "package_version": "1.82.8",
  "database_path": "/home/codespace/.cache/pydepgate/cvedb/pypi_osv.db",
  "total_findings": 10,
  "displayed_findings": 10,
  "findings": [
    {
      "canonical_id": "CVE-2026-35030",
      "aliases": [
        "CVE-2026-35030",
        "GHSA-jjhc-v7c2-5hh6"
      ],
      "match_type": "range-fixed",
      "severity": "CRITICAL",
      "raw_severity": "CRITICAL",
      "package_name": "litellm",
      "package_version": "1.82.8",
      "range_type": "ECOSYSTEM",
      "introduced": "0",
      "fixed": "1.83.0",
      "last_affected": ""
    }
  ],
  "unevaluated_ranges": [],
  "warnings": [],
  "attribution": "Vulnerability data: Open Source Vulnerability (OSV) Database (https://osv.dev), CC-BY 4.0."
}
```

### SARIF

`cvescan` does not emit SARIF yet.

CVE results are package-level findings, not source-line findings. SARIF support
will need a package-level mapping that does not pretend the vulnerability lives
inside a specific source file.

```bash
pydepgate cvescan package.whl --format sarif
```

returns an error.

## Match types

`cvescan` reports how each vulnerability matched the package identity.

### `exact-version`

The package version exactly matched an `affected_versions` row in the local
database.

```text
Match: exact-version
```

This is common for malicious package records and advisories with explicit
affected version lists.

### `all-versions`

The advisory marks all known versions of a package as affected.

```text
Match: all-versions
```

### `range-fixed`

The package version matched an ecosystem range with a fixed upper bound.

```text
Range: ECOSYSTEM introduced=1.81.8 fixed=1.83.10 last_affected=<empty>
```

This means the queried package version is greater than or equal to
`introduced` and less than `fixed`.

### `range-last-affected`

The package version matched an ecosystem range with an inclusive
`last_affected` bound.

```text
Range: ECOSYSTEM introduced=1.82.7 fixed=<empty> last_affected=1.82.8
```

This means the queried package version is greater than or equal to
`introduced` and less than or equal to `last_affected`.

### `range-open`

The package version matched an open-ended ecosystem range.

```text
Range: ECOSYSTEM introduced=0 fixed=<empty> last_affected=<empty>
```

This means the queried package version is greater than or equal to
`introduced`, and the upstream advisory does not provide a fixed or
last-affected boundary.

## Unevaluated advisory ranges

Some OSV records contain range data that cannot be safely compared to a Python
package version.

For example, `GIT` ranges may use commit hashes instead of package versions.
Those rows are preserved as unevaluated advisory evidence instead of being
treated as findings.

Human output shows these separately:

```text
Unevaluated advisory ranges: 1
  - CVE-2024-21542 [GIT] introduced=0 fixed=b5d1b965... last_affected=<empty> reason=unsupported-range-type
```

JSON output includes them under `unevaluated_ranges`.

## Flags

### `--db-path PATH`

Use a specific cvedb SQLite database instead of the default cache location.

```bash
pydepgate cvescan package.whl --db-path /tmp/pypi_osv.db
```

### `--ignore-missing-db`

Downgrade missing, unreadable, or incompatible database state into warnings.

```bash
pydepgate cvescan package.whl --ignore-missing-db
```

This is useful for composite scan workflows where a CVE pass should not prevent
other scan routines from running.

For standalone `cvescan`, the default behavior is stricter: a missing or
incompatible database exits with code 3 and prints a directive to run
`pydepgate cvedb update`.

### `--format human|json`

Select the output format.

```bash
pydepgate cvescan package.whl --format human
pydepgate cvescan package.whl --format json
```

`human` is the default unless global CI mode selects JSON.

### `--min-severity LEVEL`

Display only findings at or above a severity threshold.

```bash
pydepgate cvescan package.whl --min-severity high
```

Accepted values:

- `info`
- `low`
- `medium`
- `high`
- `critical`

`MODERATE` findings from OSV are treated as `medium` for threshold behavior.
`UNKNOWN` findings are treated as informational for filtering.

### `--strict-exit`

By default, `--min-severity` affects both displayed findings and exit-code
calculation.

With `--strict-exit`, `--min-severity` affects display only. The process exit
code is computed from all findings, including findings hidden by the severity
filter.

```bash
pydepgate cvescan package.whl --min-severity high --strict-exit
```

### `--save-to-db`

Persist the CVE scan result to the pydepgate evidence database.

```bash
pydepgate cvescan package.whl --save-to-db
```

When `--save-to-db` is set, pydepgate writes the following to the evidence
database after the scan completes:

- A scan run record with the run UUID, pydepgate version, and timestamp.
- A scanned artifact record with the artifact identity, kind, and resolved
  package name and version. Artifact hashes are computed from the wheel file
  if available.
- A CVE scan run record linking the scan run to the scanned artifact.
- A CVE finding record for each matched vulnerability.

The database is created automatically if it does not exist. You can also
create it explicitly with `pydepgate db init` before the first scan.

DB write failures emit a warning to stderr but do not affect the scan exit
code or output:

```
warning: could not save CVE scan result to DB: OperationalError: database is locked
```

Running both `scan --save-to-db` and `cvescan --save-to-db` against the same
artifact produces two separate scan run records in the database. They share
the same artifact SHA-512 and can be correlated by artifact hash using
`pydepgate db query --artifact-sha512`.

See [`pydepgate db`](db.md) for how to inspect stored results.

## Exit codes

`cvescan` uses the same exit-code model as other pydepgate commands:

| Code | Meaning |
|---:|---|
| `0` | No findings after filtering, or no CVE findings for the package identity. |
| `1` | Findings were found, but none were high or critical. |
| `2` | At least one high or critical finding was found. |
| `3` | Tool error, such as missing database, incompatible schema, invalid artifact, or unsupported output format. |

When `--strict-exit` is not set, `--min-severity` can hide lower-severity
findings and produce exit code `0`.

When `--strict-exit` is set, hidden findings still count for exit-code
calculation.

## Database behavior

`cvescan` requires a local CVE database unless `--ignore-missing-db` is used.

If the database does not exist:

```text
CVE database not found at /home/codespace/.cache/pydepgate/cvedb/pypi_osv.db
Run 'pydepgate cvedb update' to download and import.
```

If the database schema is incompatible:

```text
CVE database has incompatible schema: expected version 2, found version 1
Run 'pydepgate cvedb update' to rebuild.
```

Run:

```bash
pydepgate cvedb update
```

to rebuild the local database from the latest OSV PyPI snapshot.

## Data source and attribution

Vulnerability data is sourced from the [OSV database](https://osv.dev) PyPI
feed, licensed [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/).

`cvescan` displays the attribution line when vulnerability data is present in
output. JSON output includes the same text under `attribution`.

## Relationship to `scan`

`pydepgate scan` and `pydepgate cvescan` answer different questions.

| Command | Question |
|---|---|
| `pydepgate scan` | Does this artifact contain suspicious startup vectors or code patterns? |
| `pydepgate cvescan` | Is this package name and version known to be vulnerable? |

A package can have no suspicious files and still be vulnerable because its
published version appears in OSV.

A package can have no known CVEs and still be dangerous because it contains
suspicious code.

Use both checks when you need broader artifact coverage.
