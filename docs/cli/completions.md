# pydepgate completions

Generate shell tab-completion scripts for bash, zsh, or fish.

```
pydepgate completions <shell>
```

Supported shells: `bash`, `zsh`, `fish`.

## Setup

### bash

Add to your `~/.bashrc`:

```bash
eval "$(pydepgate completions bash)"
```

Or source it from a file:

```bash
pydepgate completions bash > ~/.config/pydepgate/completions.bash
echo 'source ~/.config/pydepgate/completions.bash' >> ~/.bashrc
```

Reload your shell or run `source ~/.bashrc`.

### zsh

Add to your `~/.zshrc`:

```zsh
eval "$(pydepgate completions zsh)"
```

Or source it from a file:

```zsh
pydepgate completions zsh > ~/.config/pydepgate/completions.zsh
echo 'source ~/.config/pydepgate/completions.zsh' >> ~/.zshrc
```

If you use `compinit`, ensure it runs before sourcing the completions file.

### fish

```fish
pydepgate completions fish > ~/.config/fish/completions/pydepgate.fish
```

Fish sources completions automatically from that directory. No further
configuration needed.

## What completes

- Subcommand names
- Flag names (global flags and subcommand-specific flags)
- Flag values for flags with a fixed set of choices (`--format`,
  `--color`, `--min-severity`, `--as`, and others)
- Signal IDs and rule IDs as positional arguments to `pydepgate explain`,
  including user-defined rules from a loaded rules file
- Shell filesystem completion for path-type flags (`--single`,
  `--rules-file`, `--decode-location`, and others)

The completion engine is implemented in `pydepgate._complete` and delegates
all candidate computation to Python, so the completions stay in sync with
the CLI without requiring shell-side maintenance.