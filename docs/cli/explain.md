---
title: Explain
parent: CLI
nav_order: 2
---
# pydepgate explain

Look up documentation for a signal ID or rule ID.

```
pydepgate explain [--rule] <topic>
pydepgate explain --list
```

## Usage

Look up a signal by ID:

```bash
pydepgate explain DYN002
```

Look up a rule by ID:

```bash
pydepgate explain default_dyn002_in_setup_py
```

`explain` tries the topic as a signal ID first. Pass `--rule` to force
rule lookup:

```bash
pydepgate explain --rule default_dyn002_in_setup_py
```

List all known signal IDs and rule IDs:

```bash
pydepgate explain --list
```

## Output

For a signal, `explain` prints:

- Signal ID and description
- Why it matters: the threat model reasoning for the signal
- Common evasions: variants and obfuscation shapes the signal is designed to
  catch (only present for signals that ship with documented evasions)
- Default rules that may apply to this signal
- User rules that may apply (when a rules file is loaded)

The output format is determined by `_print_signal` in
`src/pydepgate/cli/subcommands/explain.py`. A real invocation looks like:

```
Signal: DYN002
============================================================

exec/eval/compile called at module scope with a non-literal argument.

Why it matters:
  Module-level dynamic code execution where the argument is computed at
  runtime is the canonical 'arbitrary code execution' vulnerability. The
  code being executed is not visible in the source, and the execution
  happens automatically when the module loads.

Common evasions:
  - Computing the exec argument via string concatenation
  - Loading the argument from a config file or environment
  - Using f-strings to assemble code dynamically

Default rules that may apply:
  default_dyn002_in_setup_py
  default_dyn002_in_pth
```

Default rule IDs follow the pattern `default_<signal>_<context>`, for
example `default_dyn002_in_pth`, `default_enc001_in_setup_py`, or
`default_dens050_huge_anywhere`.

For a rule, `explain` prints:

- Rule ID and description
- Why it matters
- What the rule applies to (signal ID, file kind, scope, predicates)
- The effect: severity level, suppression, or description override

## Flags

### `--list`

List all signal IDs and rule IDs known to pydepgate, including any
user-defined rules from the loaded rules file. Output is formatted as two
sections: signal IDs with one-line descriptions, then rule IDs with their
source (`[default]` or `[user]`).

```bash
pydepgate explain --list
```

### `--rule`

Force `explain` to treat the topic as a rule ID rather than trying signal
lookup first. Useful when an ID could be ambiguous and you want rule
lookup specifically.

```bash
pydepgate explain --rule default_dens020_anywhere
```

## Tab completion

`pydepgate explain <TAB>` completes signal IDs and rule IDs, including any
user-defined rules from a loaded rules file. See
[completions](completions.md).