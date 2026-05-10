# Custom Rules

pydepgate's behavior is driven by a rules engine that maps analyzer signals to
severity-rated findings. The default rule set covers the patterns most
indicative of supply-chain malware, but you will encounter false positives on
legitimate code and cases where you want stricter or looser thresholds for
specific signals or file kinds.

Custom rules let you override the defaults without modifying pydepgate itself.

## The rules file

pydepgate loads a rules file named `pydepgate.gate` from the following
locations, in order of preference:

1. The path given to `--rules-file`
2. `./pydepgate.gate` (current directory)
3. `~/.config/pydepgate/pydepgate.gate` (user config directory)

When a rules file is loaded, pydepgate reports which file it used and whether
it found any others that it did not load:

```
note: using rules file ./pydepgate.gate
note: also found /home/user/.config/pydepgate/pydepgate.gate (not loaded; ./pydepgate.gate takes precedence)
```

The rules file is TOML or JSON. TOML is recommended for hand-authored files.

## Rules file format

A rules file contains a list of rule entries under the `rules` key:

```toml
[[rules]]
id = "MY_SUPPRESSION"
signal_id = "DENS020"
action = "suppress"

[[rules]]
id = "RAISE_DYN002_SETUP"
signal_id = "DYN002"
file_kind = "setup_py"
action = "set_severity"
severity = "critical"
```

Each rule entry supports the following fields:

| Field | Required | Description |
|---|---|---|
| `id` | Yes | Unique identifier for this rule. Prefixed with `USER_` in output. |
| `signal_id` | Yes | The signal this rule matches, e.g. `DYN002`, `ENC001`, `DENS020`. |
| `action` | Yes | What to do when the rule matches. See below. |
| `severity` | For `set_severity` | Target severity level. |
| `description` | For `set_description` | Replacement description text. |
| `file_kind` | No | Restrict the rule to a specific file kind. |
| `scope` | No | Restrict the rule to a specific scope. |

### Actions

| Action | Effect |
|---|---|
| `suppress` | Removes the finding from output. The signal still fires; the rule prevents it from becoming a finding. |
| `set_severity` | Changes the severity of the finding. Requires the `severity` field. |
| `set_description` | Replaces the finding's description text. Requires the `description` field. |

### Severity values

`info`, `low`, `medium`, `high`, `critical`

### File kind values

`setup_py`, `init_py`, `pth`, `sitecustomize`, `usercustomize`, `library_py`

### Precedence

Rules apply in this order: user rules win over system rules win over defaults.
Within the same source, a rule with more match fields wins over a more generic
rule. Within the same source and specificity, load order wins.

This means your rules file can suppress or override a default rule without
knowing anything about how the default is structured. A `suppress` on
`DYN002` in your rules file wins over any default rule for `DYN002`,
regardless of how specific the default is.

## Common patterns

### Suppress a false positive on a specific signal

A project uses `eval()` to implement a configuration DSL. The `DYN001` signal
fires on every config file. Add to `pydepgate.gate`:

```toml
[[rules]]
id = "SUPPRESS_EVAL_CONFIG"
signal_id = "DYN001"
action = "suppress"
```

This suppresses the signal globally. If you only want to suppress it in
`__init__.py` files and not in `setup.py`:

```toml
[[rules]]
id = "SUPPRESS_EVAL_INIT"
signal_id = "DYN001"
file_kind = "init_py"
action = "suppress"
```

### Lower a severity for noisy density signals

The `DENS020` (low-vowel-ratio identifiers) signal fires on generated code and
parser tables at LOW severity. If your project includes a parser table that
triggers it and you want to drop it to INFO:

```toml
[[rules]]
id = "LOWER_DENS020"
signal_id = "DENS020"
action = "set_severity"
severity = "info"
```

### Raise a severity for a specific file kind

Your organization treats any `subprocess` use in a `setup.py` as
unconditionally blocking, regardless of context:

```toml
[[rules]]
id = "CRITICAL_STDLIB_SUBPROCESS_SETUP"
signal_id = "STDLIB001"
file_kind = "setup_py"
action = "set_severity"
severity = "critical"
```

### Suppress a signal entirely in a known safe package

You are scanning a package you maintain and trust, and it legitimately uses
a pattern that fires at LOW. Rather than suppressing the signal globally, you
can combine a CI `--min-severity medium` threshold with a rules file entry:

```toml
[[rules]]
id = "LOWER_STR003_TRUSTED"
signal_id = "STR003"
action = "set_severity"
severity = "info"
```

Because `--min-severity medium` filters everything below MEDIUM, setting the
signal to INFO removes it from CI output without suppressing it entirely.

## Testing rules

The fastest way to verify a rule is to use `--single` on a fixture file that
reproduces the pattern, then confirm the signal disappears (or changes
severity) with your rules file active.

Without a rules file:

```bash
pydepgate scan --single my_fixture.py
```

With your rules file:

```bash
pydepgate scan --rules-file ./pydepgate.gate --single my_fixture.py
```

Compare the output. The signal should no longer appear as a finding, or should
appear at the new severity.

To verify the rules file was loaded and no competing file was silently ignored:

```bash
pydepgate scan --rules-file ./pydepgate.gate --single my_fixture.py 2>&1 | head -5
```

The `note:` lines on stderr confirm which file was loaded.

## Typo detection

The rules loader performs fuzzy matching on field values. If you write
`singal_id` instead of `signal_id`, or `supresss` instead of `suppress`, the
loader emits a warning with the likely intended value rather than silently
ignoring the rule:

```
warning: rule MY_RULE: unknown field 'singal_id'. Did you mean 'signal_id'?
```

Rules with unknown required fields are not loaded. The warning appears on
stderr before the scan begins.