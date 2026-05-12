# pre-commit integration

pydepgate ships with a pre-commit hooks config so it can run as part
of the standard pre-commit workflow used by most Python projects.

## What's included

The repo's `.pre-commit-hooks.yaml` exposes two hook ids:

`pydepgate` runs `pydepgate scan --single` against every staged
`.py` file. It defaults to `--min-severity high` so commits aren't
blocked by purely-informational findings like confusable single-
character identifiers or low-vowel-ratio names. The blocking
findings are the ones that warrant a human look anyway.

`pydepgate-pth` runs the same scanner against staged `.pth` files
with no severity filter. Anything pydepgate fires on a `.pth` is
worth a human look. `.pth` files are an interpreter-startup
mechanism with no legitimate use case for any of the patterns
pydepgate detects, so even an INFO finding there is unusual.

## Adding pydepgate to your repo

In your project's `.pre-commit-config.yaml`:

    repos:
      - repo: https://github.com/nuclear-treestump/pydepgate
        rev: v0.4.0
        hooks:
          - id: pydepgate
          - id: pydepgate-pth

Then run `pre-commit install` once to install the git hook, and
`pre-commit run --all-files` to scan the existing tree on first use.

## Tuning

To change the severity threshold (for example, fail the commit on
any MEDIUM or above):

    - id: pydepgate
      args: [--min-severity, medium, --no-color]

To enable payload-peek decoding during the hook run:

    - id: pydepgate
      args: [--min-severity, high, --no-color, --peek]

To exclude generated files or vendored directories:

    - id: pydepgate
      exclude: ^(generated/|vendor/|third_party/)

The full set of pydepgate flags is honored. See the main README for
the complete flag reference.

## Performance

Each invocation scans one file, so the per-file cost is whatever
pydepgate takes on that file, typically well under a second for
ordinary source files. Pre-commit batches invocations efficiently
and only runs against changed files, so the hook adds negligible
overhead to a normal commit.

The `pre-commit run --all-files` initial scan against an established
project may take longer because it scans every file in the tree. A
project with a few hundred Python files completes in tens of
seconds; larger codebases scale linearly. If first-run time is a
concern, run with `--min-severity critical` once to surface any
high-severity hits, fix or suppress them, then enable the hook with
the normal threshold for ongoing commits.

## CI integration

The hook config also works under `pre-commit run --all-files` in CI
pipelines. GitHub Actions example:

    - uses: pre-commit/action@v3.0.1

GitLab CI example:

    pre-commit:
      image: python:3.12-slim
      script:
        - pip install pre-commit
        - pre-commit run --all-files

For pure-pydepgate CI workflows that don't use pre-commit, see the
Docker image documentation instead. It's the more direct path for
artifact scanning.
