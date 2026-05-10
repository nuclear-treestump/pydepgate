# pydepgate preflight

Walk an installed Python environment and scan every package for startup-vector
malware patterns.

**This subcommand is under development and not yet functional.** Running it
produces an informational message and exits with code 3. Progress is tracked
in [ROADMAP.md](https://github.com/nuclear-treestump/pydepgate/blob/main/ROADMAP.md).

## Intended behavior

When complete, `preflight` will:

- Enumerate every installed package in a Python environment via
  `importlib.metadata`
- Run the same startup-vector analysis that `pydepgate scan` runs on
  individual artifacts
- Report findings across the entire environment in a single pass
- Support `--min-severity`, `--format`, and the other global flags

This is the "am I already compromised?" companion to `scan`, which answers
"is this artifact safe to install?"

## Flags

### `--python <path>`

Path to a Python interpreter whose environment to scan. When not set,
`preflight` will default to the active interpreter.

```bash
pydepgate preflight --python /usr/bin/python3
pydepgate preflight --python /home/user/.venvs/myproject/bin/python
```

## Current status

Invoking `preflight` today prints a status message and returns exit code 3
(`TOOL_ERROR`). No scanning occurs.

In the meantime, you can approximate environment auditing by scanning
individual installed packages with `pydepgate scan <package-name>`.