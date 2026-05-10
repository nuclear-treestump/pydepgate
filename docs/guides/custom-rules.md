---
title: Custom Rules
parent: Guides
nav_order: 2
---
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

1. The path given to `--rules-file` (or `PYDEPGATE_RULES_FILE`)
2. `./pydepgate.gate` (current directory)
3. `<sys.prefix>/pydepgate.gate` (when running in a virtual environment)

When a rules file is loaded, pydepgate reports which file it used and whether
it found any others that it did not load. The loader also surfaces any
warnings emitted during parse (missing format declaration, deprecated fields,
etc.).

The rules file is TOML or JSON. The loader auto-detects from content; TOML is
recommended for hand-authored files.

## Rules file format

### TOML

In a TOML file, each rule is an array-of-tables entry under the key `rule`
(singular, not `rules`):

```toml
[[rule]]
id = "MY_SUPPRESSION"
signal_id = "DENS020"
action = "suppress"

[[rule]]
id = "RAISE_DYN002_SETUP"
signal_id = "DYN002"
file_kind = "setup_py"
action = "set_severity"
severity = "critical"
```

### JSON

In a JSON file, rules go in a top-level `rules` array (plural, with an `s`).
JSON files should also declare the format version explicitly:

```json
{
  "_pydepgate_format": "json",
  "_pydepgate_version": 1,
  "rules": [
    {
      "id": "MY_SUPPRESSION",
      "signal_id": "DENS020",
      "action": "suppress"
    },
    {
      "id": "RAISE_DYN002_SETUP",
      "signal_id": "DYN002",
      "file_kind": "setup_py",
      "action": "set_severity",
      "severity": "critical"
    }
  ]
}
```

The format-declaration keys are not required (the loader emits a warning if
they are missing) but they document intent.

### Rule fields

Each rule entry supports these fields. The complete valid-field set is in
`_VALID_RULE_FIELDS` in `src/pydepgate/rules/loader.py`.

| Field | Required | Description |
|---|---|---|
| `id` | Yes | Identifier for this rule. The loader prefixes it with `USER_` in output, so `id = "MY_RULE"` appears as `USER_MY_RULE`. |
| `action` | Yes | What to do when the rule matches. See below. |
| `signal_id` | Match | The signal this rule matches, for example `DYN002`, `ENC001`, `DENS020`. |
| `analyzer` | Match | The analyzer name. Useful for matching all signals from one analyzer. |
| `file_kind` | Match | Restrict to a specific file kind. See values below. |
| `scope` | Match | Restrict to a specific scope. See values below. |
| `path_glob` | Match | Restrict to paths matching a glob (e.g. `tests/**`). |
| `context_contains` | Match | Restrict to signals whose context dict contains specific key/value pairs. Legacy form; prefer `context_predicates`. |
| `context_predicates` | Match | Structured predicates against context fields. See below. |
| `severity` | For `set_severity` | Target severity level. |
| `description` | For `set_description` | Replacement description text. |
| `explain` | No | Human-readable rationale. Surfaced via `pydepgate explain`. |

Fields under the "Match" category are all optional. A rule with no match
fields matches every signal (a catch-all rule). Each additional match field
narrows the set of signals the rule applies to.

### Actions

| Action | Effect |
|---|---|
| `suppress` | Removes the finding from the active output. The signal still fires and is recorded in `suppressed_findings` for audit visibility. |
| `set_severity` | Changes the severity of the finding. Requires `severity`. |
| `set_description` | Replaces the finding's description text. Requires `description`. |

### Severity values

`info`, `low`, `medium`, `high`, `critical`

### File kind values

`setup_py`, `init_py`, `pth`, `sitecustomize`, `usercustomize`, `library_py`

### Scope values

`module`, `class_body`, `function`, `nested_function`, `unknown`

### Context predicates

Use `context_predicates` to match against specific fields in a signal's
context dictionary. Each predicate is a one-key mapping where the key is an
operator and the value is the comparand:

```toml
[[rule]]
id = "ESCALATE_LARGE_DENS010"
signal_id = "DENS010"
action = "set_severity"
severity = "critical"

[rule.context_predicates.length]
gte = 4096
```

This rule fires only when the matched DENS010 signal has a `context.length`
of 4096 or more. The supported operators are defined in `VALID_OPERATORS`
in `src/pydepgate/rules/base.py`.

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
[[rule]]
id = "SUPPRESS_EVAL_CONFIG"
signal_id = "DYN001"
action = "suppress"
```

This suppresses the signal globally. If you only want to suppress it in
`__init__.py` files and not in `setup.py`:

```toml
[[rule]]
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
[[rule]]
id = "LOWER_DENS020"
signal_id = "DENS020"
action = "set_severity"
severity = "info"
```

### Raise a severity for a specific file kind

Your organization treats any `subprocess` use in a `setup.py` as
unconditionally blocking, regardless of context:

```toml
[[rule]]
id = "CRITICAL_STDLIB_SUBPROCESS_SETUP"
signal_id = "STDLIB001"
file_kind = "setup_py"
action = "set_severity"
severity = "critical"
```

### Restrict to a path prefix

Suppress a signal only when it fires in vendored or generated code:

```toml
[[rule]]
id = "SUPPRESS_DENS_VENDORED"
signal_id = "DENS040"
path_glob = "vendor/**"
action = "suppress"
```

### Suppress a signal entirely in a known safe package

You are scanning a package you maintain and trust, and it legitimately uses
a pattern that fires at LOW. Rather than suppressing the signal globally, you
can combine a CI `--min-severity medium` threshold with a rules file entry:

```toml
[[rule]]
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

## Typo detection

The rules loader performs fuzzy matching on field names and field values
using `difflib.get_close_matches`. If you write `singal_id` instead of
`signal_id`, or `supresss` instead of `suppress`, the loader emits a warning
with the likely intended value:

```
warning: rule MY_RULE: unknown field 'singal_id'. Did you mean 'signal_id'?
```

The loader is strict: any validation error rejects the entire file. This
prevents a partial rule set from silently changing scan behavior.