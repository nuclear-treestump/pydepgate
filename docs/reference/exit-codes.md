# Exit Codes

pydepgate returns one of four exit codes on every invocation. These codes are
part of the public interface. CI pipelines and shell scripts depend on them;
changing them is a breaking change and will not happen before v1.0 without an
explicit migration note.

## The four codes

| Code | Constant | Meaning |
|---|---|---|
| `0` | `CLEAN` | No findings, or no findings at or above `--min-severity`. |
| `1` | `FINDINGS_BELOW_BLOCKING` | Findings present, but none are HIGH or CRITICAL. |
| `2` | `FINDINGS_BLOCKING` | At least one HIGH or CRITICAL finding is present. |
| `3` | `TOOL_ERROR` | pydepgate could not complete the scan. |

## Code 0: CLEAN

The scan completed and produced no findings at or above the active
`--min-severity` threshold. This is the expected result for a clean package.

Note that `--min-severity` affects what is considered a finding for exit code
purposes by default. A package with only LOW findings exits `0` when
`--min-severity high` is set, because no findings met the threshold.

## Code 1: FINDINGS_BELOW_BLOCKING

Findings were produced, but none are HIGH or CRITICAL. The package is
suspicious but does not meet the blocking threshold.

In most CI configurations this is a non-failing result. The findings are still
present in the output and warrant review.

## Code 2: FINDINGS_BLOCKING

At least one HIGH or CRITICAL finding is present. This is the primary signal
that a CI pipeline should act on. The standard pattern:

```bash
pydepgate scan package.whl
# Exit 2 means blocking findings; exit 1 means findings below threshold;
# exit 0 means clean.
```

`--ci` is shorthand for `--min-severity high --no-color`. When `--min-severity
high` is set, any finding in the output is HIGH or CRITICAL by definition, so
exit code 1 cannot occur and the only non-zero result is 2.

## Code 3: TOOL_ERROR

pydepgate could not complete the scan. Common causes:

- The artifact file does not exist or is unreadable.
- The package name is not installed in the active environment.
- The wheel or sdist is malformed and cannot be unpacked.
- An internal error prevented the scan from running.

Diagnostic messages describing the failure are written to stderr. A tool error
does not mean the package is clean; it means pydepgate cannot evaluate it.

## Interaction with `--strict-exit`

By default, `--min-severity` filters findings for both display and exit code
computation. `--strict-exit` decouples these: the display is filtered by
`--min-severity`, but the exit code is computed from all findings regardless
of severity.

```bash
# Display only HIGH+, but exit 2 if any finding exists at any severity.
pydepgate scan --min-severity high --strict-exit package.whl
```

This is useful when you want clean terminal output in a log but need the exit
code to reflect the complete finding set for downstream decision logic.

## Stability contract

These codes have been stable since v0.1 and are documented as a public
contract. The specific rules:

- Existing code values (`0`, `1`, `2`, `3`) will not be repurposed.
- New exit codes, if ever added, will use numbers above `3`.
- Any change to exit code semantics is a major-version event and requires an
  explicit migration note in the changelog.

Do not test for exit code `1` meaning "tool error" or exit code `3` meaning
"findings". The constants are defined exactly as above and will remain so.