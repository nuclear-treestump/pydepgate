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
pydepgate explain DYN_EXEC_NOLITERAL
```

`explain` tries the topic as a signal ID first. Pass `--rule` to force
rule lookup:

```bash
pydepgate explain --rule DYN_EXEC_NOLITERAL
```

List all known signal IDs and rule IDs:

```bash
pydepgate explain --list
```

## Output

For a signal, `explain` prints:

- Signal ID and description
- Why it matters: the threat model reasoning for the signal
- Common evasions: variants and obfuscation shapes the signal is designed to catch
- Default rules that apply to the signal
- User rules that apply (if a rules file is loaded)

```
Signal: DYN002
============================================================

exec() called with a non-literal argument.

Why it matters:
  exec() is the direct primitive for runtime code execution.
  Calling it with a non-literal argument means the executed
  code is not visible in static analysis; it is computed,
  decoded, or retrieved at runtime. This is the core
  mechanism in the LiteLLM 1.82.8 attack and most other
  .pth-based supply chain attacks.

Common evasions:
  - exec(base64.b64decode(PAYLOAD)) where PAYLOAD is defined elsewhere
  - exec(compile(...))
  - exec(getattr(__builtins__, 'exec')(...)

Default rules that may apply:
  DYN_EXEC_NOLITERAL
  DYN_EXEC_NOLITERAL_SETUP
```

For a rule, `explain` prints:

- Rule ID and description
- Why it matters
- What file kinds or scopes the rule applies to (if scoped)
- The effect: severity level, suppression, or description override

## Flags

### `--list`

List all signal IDs and rule IDs known to pydepgate, including any user-defined
rules from the loaded rules file. Output is formatted as two sections: signal
IDs with one-line descriptions, then rule IDs with their source (`[default]`
or `[user]`).

```bash
pydepgate explain --list
```

### `--rule`

Force `explain` to treat the topic as a rule ID rather than trying signal
lookup first. Useful when a rule ID and signal ID share a prefix and you know
which one you want.

```bash
pydepgate explain --rule DENS_LOW_VOWEL_RATIO
```

## Tab completion

`pydepgate explain <TAB>` completes signal IDs and rule IDs, including any
user-defined rules from a loaded rules file. See
[completions](completions.md).