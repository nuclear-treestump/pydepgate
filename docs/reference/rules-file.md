---
   title: Rules File
   parent: Reference
   nav_order: 4
---
# Rules File

The `.gate` file format is the on-disk representation of pydepgate's rules
engine. This page is the formal specification: discovery, parsing, schema,
validation, and precedence. For task-oriented walkthroughs (suppressing a
specific signal, lowering a severity, restricting to a path), see
[Custom Rules](../guides/custom-rules.md).

## File discovery

When `pydepgate scan` runs, it walks four locations in order and loads the
first match. Locations later in the order are reported as `also_found` but
not loaded. The walk is implemented in `discover_rules_files` in
`src/pydepgate/rules/loader.py`.

1. The explicit path passed via `--rules-file PATH`.
2. The path in the `PYDEPGATE_RULES_FILE` environment variable.
3. `./pydepgate.gate` (the current working directory).
4. `<sys.prefix>/pydepgate.gate` (the active virtual environment root).

A file must end with the suffix `.gate` to be loadable. Passing a path with
a different extension raises a load error rather than silently failing.

## Format detection

pydepgate auto-detects whether the file is JSON or TOML by attempting JSON
first and falling back to TOML on parse failure. The file extension does
not determine the format; the content does.

JSON files should declare their format and version explicitly with two
top-level keys:

```json
{
  "_pydepgate_format": "json",
  "_pydepgate_version": 1,
  "rules": [ ... ]
}
```

Both declaration keys are optional. The loader emits a warning when either
is missing but loads the file anyway. If `_pydepgate_format` is set to a
value other than `"json"`, or `_pydepgate_version` is set to a value other
than `1`, the load fails.

TOML files have no format-declaration keys. TOML's comment-only top-level
grammar cannot host them. Any valid TOML file is treated as version 1.

## File structure

### JSON

Rules live in a top-level `rules` array (plural):

```json
{
  "_pydepgate_format": "json",
  "_pydepgate_version": 1,
  "rules": [
    {
      "id": "example",
      "signal_id": "DYN002",
      "action": "set_severity",
      "severity": "critical"
    }
  ]
}
```

### TOML

Rules use the array-of-tables syntax under the key `rule` (singular, not
`rules`):

```toml
[[rule]]
id = "example"
signal_id = "DYN002"
action = "set_severity"
severity = "critical"
```

A common mistake is writing `[[rules]]` in a TOML file. The loader reads
`data.get("rule", [])` for TOML format; a file with `[[rules]]` parses
successfully but contributes zero rules to the engine.

## Rule schema

Every rule is an object with these fields. The complete valid-field set is
defined as `_VALID_RULE_FIELDS` in `src/pydepgate/rules/loader.py`.

### Identity

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | recommended | A short stable identifier for the rule. The loader prefixes it with the source name in uppercase, so `id = "MY_RULE"` from a user file becomes `USER_MY_RULE` in output. If omitted, an auto-generated identifier is used. |
| `explain` | string | no | Human-readable rationale for the rule, displayed by `pydepgate explain <rule-id>`. |

### Match fields

A rule matches a signal when every non-null match field matches. A rule
with no match fields is a catch-all that matches every signal (rare but
sometimes useful).

| Field | Type | Description |
|---|---|---|
| `signal_id` | string | Exact match against `Signal.signal_id`. For example, `"DYN002"`, `"ENC001"`, `"DENS010"`. |
| `analyzer` | string | Exact match against `Signal.analyzer`. Matches every signal from one analyzer. Values are the analyzer module names: `encoding_abuse`, `dynamic_execution`, `string_ops`, `suspicious_stdlib`, `code_density`. |
| `file_kind` | string | Match against the triage decision's `FileKind`. Allowed values listed below. |
| `scope` | string | Match against `Signal.scope`. Allowed values listed below. |
| `path_glob` | string | Match against the file's internal path within the artifact using `fnmatch` glob syntax. For example, `"tests/**"` or `"vendor/*.py"`. |
| `context_contains` | object | Legacy match against entries in `Signal.context`. Each `{key: value}` is shimmed at construction time into an `eq` predicate. Prefer `context_predicates` for new rules. |
| `context_predicates` | object | Structured predicates over `Signal.context` fields. See [Context predicates](#context-predicates) below. |

### Effect fields

Every rule must specify an action and may carry effect-specific fields.

| Field | Type | Required | Description |
|---|---|---|---|
| `action` | string | yes | One of `suppress`, `set_severity`, `set_description`. |
| `severity` | string | when `action = "set_severity"` | Target severity. Allowed values listed below. |
| `description` | string | when `action = "set_description"` | Replacement description text for the finding. |

## Allowed values

### `action`

| Value | Effect |
|---|---|
| `suppress` | The signal still fires but does not produce an active finding. The suppression is recorded in `suppressed_findings` for audit visibility. |
| `set_severity` | The finding is produced at the severity given in the `severity` field. Overrides the mechanical confidence-to-severity fallback. |
| `set_description` | The finding's description text is replaced with the `description` field. Severity falls back to the mechanical confidence-to-severity mapping unless another matching rule sets it. |

### `severity`

`info`, `low`, `medium`, `high`, `critical`.

### `file_kind`

`pth`, `setup_py`, `init_py`, `sitecustomize`, `usercustomize`,
`library_py`, `entry_points`.

The `skip` value also exists in the `FileKind` enum but represents files
the triage layer decided not to analyze. A rule with `file_kind = "skip"`
will never match any signal in practice.

### `scope`

`module`, `class_body`, `function`, `nested_function`, `unknown`.

Lowercased. Case-insensitive on input but always reported lowercase in the
loaded rule.

## Context predicates

`context_predicates` matches against specific fields of the signal's
`context` dictionary. Each predicate is a one-key mapping where the key is
an operator and the value is the comparand.

```toml
[[rule]]
id = "escalate-huge-base64"
signal_id = "DENS010"
action = "set_severity"
severity = "critical"
context_predicates = { length = { gte = 10240 } }
```

This matches DENS010 signals whose `context.length` is 10240 or greater.

### Operators

The complete operator set is defined as `VALID_OPERATORS` in
`src/pydepgate/rules/base.py`.

| Category | Operators | Value type |
|---|---|---|
| Numeric and comparable | `eq`, `ne`, `gt`, `gte`, `lt`, `lte` | int or float (any orderable, in practice) |
| String | `eq`, `ne`, `contains`, `startswith`, `endswith` | string |
| Collection | `in`, `not_in` | list, tuple, or set |

`eq` and `ne` work for any type. `contains` works on strings (substring
match) and on lists or tuples (membership). `in` and `not_in` test whether
the actual value appears in the predicate's collection.

### Predicate evaluation

Each predicate dict must contain exactly one operator key. Loaders reject:

- An empty predicate dict.
- A predicate dict with multiple operator keys.
- A non-dict predicate value.
- An unknown operator name (with a typo suggestion via `difflib`).

To AND multiple conditions on the same field, write multiple rules. The
engine has no OR primitive; OR is expressed by writing two rules with the
same effect.

Type mismatches at evaluation time return False rather than raising. For
example, `{ length = { gte = 1024 } }` evaluated against a signal whose
`context.length` is a string silently fails to match. This means a single
mistyped predicate cannot crash a scan.

### Predicates with multiple fields

Multiple predicates on different fields are AND-ed:

```toml
[[rule]]
id = "huge-base64-in-init"
signal_id = "DENS010"
file_kind = "init_py"
action = "set_severity"
severity = "critical"

[rule.context_predicates]
length = { gte = 10240 }
alphabet = { eq = "base64" }
```

This matches only when both predicates pass: `length` is at least 10240
and `alphabet` equals `"base64"`.

### `context_contains` shim

`context_contains` is the legacy match field, preserved for backward
compatibility. At rule-construction time, each entry is converted to an
`eq` predicate and merged into `context_predicates`. The original
`context_contains` dict remains readable on the loaded `Rule` for
inspection but is not consulted during matching; only `context_predicates`
is.

When both fields are provided for the same key, the explicit predicate
wins on key collision and non-colliding keys merge.

## Precedence

When multiple rules match a signal, the winner is chosen by this
three-level comparison:

1. **Source priority.** User rules win over system rules win over defaults,
   regardless of specificity. `RuleSource` values: `default = 0`,
   `system = 1`, `user = 2`.
2. **Specificity.** Among rules of the same source, the rule with more
   match fields wins. Each non-null match field counts as one. Each
   `context_predicates` entry counts as one.
3. **Load order.** Among ties on source and specificity, the rule loaded
   first wins.

This contract means a user rule with the same shape as a default rule
always wins. To let your rule lose to a more-specific default, write
fewer match fields than the rule you want to override.

When the winning rule's action is `suppress`, the engine still computes
what the finding would have been if only default rules had been considered
and records that as `would_have_been` on the suppression entry. This is
how the suppression audit trail surfaces what was hidden and why.

When no rule matches a signal at all, the engine falls back to the
mechanical confidence-to-severity mapping in
`src/pydepgate/engines/base.py`. See
[Signals](signals.md#how-severity-is-assigned) for the mapping table.

## Validation

The loader is strict: any validation error rejects the entire file. A
partial rule set cannot silently change scan behavior. Errors are
accumulated across all rules in the file and reported together so a
hand-authored file with several mistakes surfaces them all in one pass
rather than one at a time.

### Typo suggestions

Unknown field names and unknown enum values trigger a `difflib`-based
similarity suggestion with a cutoff of 0.6:

```
warning: rule MY_RULE: unknown field 'singal_id'. Did you mean 'signal_id'?
```

The suggestion mechanism is implemented in `_suggest_field` and is applied
to field names, action names, severity values, file kind values, scope
values, and operator names.

### Error categories

| Category | Example | Behavior |
|---|---|---|
| Unknown field | `singal_id = "DYN002"` | Suggestion offered, file rejected |
| Unknown action | `action = "supresss"` | Suggestion offered, file rejected |
| Unknown severity | `severity = "criticla"` | Suggestion offered, file rejected |
| Unknown file_kind | `file_kind = "setyp_py"` | Suggestion offered, file rejected |
| Unknown scope | `scope = "modul"` | Suggestion offered, file rejected |
| Missing required field | `action = "set_severity"` without `severity` | File rejected |
| Empty predicate dict | `context_predicates = { length = {} }` | File rejected |
| Multiple operators in predicate | `context_predicates = { length = { gte = 1, lte = 2 } }` | File rejected |
| Non-dict predicate value | `context_predicates = { length = 1024 }` | File rejected |
| Invalid encoding | not valid UTF-8 | File rejected |
| Neither valid JSON nor valid TOML | malformed syntax | File rejected with TOML parser error |
| Wrong file extension | path does not end in `.gate` | File rejected before parse |

### Warnings (non-fatal)

| Category | Example | Behavior |
|---|---|---|
| JSON missing format declaration | no `_pydepgate_format` key | File loads, warning written to stderr |
| JSON missing version declaration | no `_pydepgate_version` key | File loads, warning written to stderr |
| Also-found file not loaded | second `.gate` found during discovery | File loads, note written to stderr |

## Identity prefixing

The loader prefixes every rule's user-provided `id` with the source's
uppercase name. The transformation is in `_build_rule` in the loader:

```python
prefix = source.value.upper()
rule_id = f"{prefix}_{explicit_id}"
```

So a rule with `id = "MY_RULE"` loaded from a user file appears in output
as `USER_MY_RULE`. A rule with `id = "MY_RULE"` loaded as a system rule
would appear as `SYSTEM_MY_RULE`. Default rules use rule_ids assigned by
the engine and follow the convention `default_<signal>_<context>` (for
example, `default_dyn002_in_setup_py`).

When the `id` field is omitted entirely, the loader assigns an
auto-generated identifier in its place.

## Complete examples

### Minimal suppression (TOML)

```toml
[[rule]]
id = "ignore_dens020"
signal_id = "DENS020"
action = "suppress"
```

### Severity escalation with predicate (TOML)

```toml
[[rule]]
id = "block_large_high_entropy_strings"
signal_id = "DENS010"
action = "set_severity"
severity = "critical"
context_predicates = { length = { gte = 10240 } }
explain = "Anything with 10 KB+ of high-entropy content is shellcode-shaped."
```

### Path-restricted suppression (TOML)

```toml
[[rule]]
id = "vendored_dens040_ok"
signal_id = "DENS040"
path_glob = "vendor/**"
action = "suppress"
```

### Description override (TOML)

```toml
[[rule]]
id = "clarify_dyn001"
signal_id = "DYN001"
action = "set_description"
description = "exec() called with literal argument; review for intent."
```

### Equivalent JSON

```json
{
  "_pydepgate_format": "json",
  "_pydepgate_version": 1,
  "rules": [
    {
      "id": "block_large_high_entropy_strings",
      "signal_id": "DENS010",
      "action": "set_severity",
      "severity": "critical",
      "context_predicates": {
        "length": { "gte": 10240 }
      },
      "explain": "Anything with 10 KB+ of high-entropy content is shellcode-shaped."
    }
  ]
}
```

## Implementation references

| Component | Location |
|---|---|
| File discovery | `discover_rules_files` in `src/pydepgate/rules/loader.py` |
| Format detection | `_detect_format_and_parse` in `src/pydepgate/rules/loader.py` |
| Rule construction | `_build_rule` in `src/pydepgate/rules/loader.py` |
| Field validation | `_validate_rule_dict` in `src/pydepgate/rules/loader.py` |
| Predicate validation | `_validate_context_predicates` in `src/pydepgate/rules/loader.py` |
| Operator set | `VALID_OPERATORS` in `src/pydepgate/rules/base.py` |
| Predicate evaluation | `ContextPredicate.evaluate` in `src/pydepgate/rules/base.py` |
| Match logic | `matches` in `src/pydepgate/rules/base.py` |
| Precedence resolution | `_select_winning_rule` in `src/pydepgate/rules/base.py` |
| Confidence fallback | `confidence_to_severity_v01` in `src/pydepgate/engines/base.py` |