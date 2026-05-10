---
title: Tab Completions
parent: CLI
nav_order: 1
---
# pydepgate completions

Generate shell tab-completion scripts for bash, zsh, or fish.

```
pydepgate completions <shell>
```

Supported shells: `bash`, `zsh`, `fish`.

Running this command alone does not install completion; you have to do
something with its output. When run interactively (stdout is a TTY), the
command writes install instructions to stderr after the script so you see
guidance alongside the script content.

## Setup

### bash

For the current shell only (forgotten when you close it):

```bash
eval "$(pydepgate completions bash)"
```

For all future bash sessions:

```bash
pydepgate completions bash >> ~/.bashrc
```

Reload your shell or run `source ~/.bashrc`.

### zsh

For the current shell only:

```zsh
eval "$(pydepgate completions zsh)"
```

For all future zsh sessions:

```zsh
pydepgate completions zsh >> ~/.zshrc
```

The zsh script uses `bashcompinit` to bridge bash-style completion into
zsh's completion system. If you use `compinit`, ensure it runs before
sourcing the completions output.

### fish

```fish
pydepgate completions fish > ~/.config/fish/completions/pydepgate.fish
```

Fish sources completions automatically from that directory. No further
configuration needed.

Alternatively, for the current session only:

```fish
pydepgate completions fish | source
```

## What completes

- Subcommand names
- Flag names (global flags and subcommand-specific flags)
- Flag values for flags with a fixed set of choices (`--format`,
  `--color`, `--min-severity`, `--as`, and others)
- Signal IDs and rule IDs as positional arguments to `pydepgate explain`,
  including user-defined rules from a loaded rules file
- Shell filesystem completion as a fallback for path-type flags
  (`--single`, `--rules-file`, `--decode-location`, and others)

## How it works

The shell glue emitted by `pydepgate completions <shell>` calls back into
`pydepgate _complete` on every TAB press. `_complete` is a hidden
subcommand whose job is to receive the current command-line state from the
shell and write candidate completions to stdout, one per line. The shell
turns that list into completion suggestions.

The candidate-computation engine lives in `pydepgate.cli.completion` (a
plain Python module with no argparse dependency). The argparse glue for
`completions` and `_complete` lives in
`pydepgate.cli.subcommands.completion`. Both keep the completion logic in
sync with the CLI without requiring shell-side maintenance.

When `_complete` returns no candidates (for example, a path argument), the
shell glue falls through to ordinary filesystem completion.