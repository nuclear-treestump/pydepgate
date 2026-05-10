# pydepgate exec

Run a Python script with runtime interdiction active, blocking suspicious
startup behavior before it executes.

**This subcommand is under development and not yet functional.** Running it
produces an informational message and exits with code 3. Progress is tracked
in [ROADMAP.md](https://github.com/nuclear-treestump/pydepgate/blob/main/ROADMAP.md).

## Intended behavior

When complete, `exec` will:

- Install Python audit hooks before running the target script
- Intercept the startup vectors pydepgate's static analyzer detects
  (`.pth` exec chains, `sitecustomize.py` imports, console-script hooks)
- Block or warn on suspicious behavior according to the configured
  severity threshold and rules
- Pass arguments through to the target script unchanged

This is the runtime enforcement complement to the static analysis in `scan`.
`scan` tells you a package is suspicious before you install it. `exec` catches
behavior that slips through static analysis or arrives through dynamic means.

## Flags

### `<script>`

The Python script to run. Passed to the runtime engine as the entry point.

```bash
pydepgate exec myscript.py
pydepgate exec myscript.py -- --script-arg1 --script-arg2
```

Arguments after `--` are forwarded to the script.

## Current status

Invoking `exec` today prints a status message and returns exit code 3
(`TOOL_ERROR`). No script execution or interdiction occurs.