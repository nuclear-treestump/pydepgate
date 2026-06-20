# Agents.md

Guidelines for AI coding agents working on the pydepgate codebase.

## Before you write code

1. Read CLAUDE.md for project overview, build commands, and critical constraints.
2. Read CONTRIBUTING.md for the full contributor workflow and load-bearing constraint explanations.
3. Understand which pipeline layer your change belongs in (parsers, analyzers, enrichers, rules, reporters, CLI). Putting work in the wrong layer is the most common mistake.

## Safety-critical rules

These are non-negotiable. Violating any of them creates security vulnerabilities or silent correctness bugs.

### The no-execution discipline

The static analyzer never executes user input. The safe partial evaluator in `src/pydepgate/analyzers/_resolver.py` reimplements operations from scratch. When extending the resolver:
- Model the operation. Do not delegate to the runtime.
- Never call `.replace()`, `.split()`, `getattr()`, or any method on resolved values.
- Write a function that takes the resolved string and literal arguments and produces the result by hand.

If you are uncertain whether a change preserves this property, stop and flag it.

### The picklability contract

Everything that passes through `_scan_one_file` must survive a pickle round-trip: `FileScanInput`, `FileScanOutput`, every analyzer, enricher, and rule instance. After adding any new component:
- Run `python -m unittest tests/engines/test_deploy_the_pickle.py -v`
- If something won't pickle (compiled regex, open file handle, thread-local), construct it at use time inside the logic, not as stored state.

### Zero runtime dependencies

The project has zero third-party runtime dependencies by design. Do not add any. If your approach requires a dependency, redesign the approach.

## Working on specific areas

### New analyzer

1. Subclass the visitor base in `analyzers/_visitor.py`
2. Emit signals with a stable, new signal_id in an unused number range under a new prefix
3. Populate `signal.context` with information rules will match on
4. Add `enrichment_hints` if the signal benefits from peek processing
5. Tests: happy-path + 3 evasion variants + 3 benign-pattern fixtures
6. Picklability test must pass
7. Update README "What pydepgate detects" section

### New rule

1. Rule goes in `src/pydepgate/rules/defaults.py`
2. Explanation goes in `src/pydepgate/rules/explanations.py`
3. Tests: matching case + at least one non-matching case

### New CLI flag

Global flags must use the dual-registration pattern:
- Add inside `_add_global_flags` in `cli/main.py`, not in the top-level parser body
- Use `argparse.SUPPRESS` as default when `is_subparser` is True
- Use the real default when `is_subparser` is False
- See `cli/command_handlers/peek_args.py` for prior art

### New context key on signals

- If it should appear in human output: update the allowlist in the human reporter's `_render_finding`
- Underscore prefix (`_key`) = suppressed from JSON output (pipeline-internal only)
- No underscore = included in JSON output

### Changes to JSON output shape

Any change to the shape of JSON output (new keys, renames, type changes, removals) requires bumping `schema_version`. Additive changes are minor bumps; breaking changes need a deprecation cycle.

### Changes to triage coverage

If touching `traffic_control/triage.py`, you must:
- Document whether coverage is expanding or shrinking and for which file kinds
- Add tests asserting both the positive (files that should be analyzed are) and negative (files that should be skipped are)

## Testing requirements

Run the full suite before considering any change complete:
```bash
python -m unittest discover tests -v
```

Test categories to contribute to when relevant:
- Happy-path: the pattern fires
- Evasion battery: obfuscated variants still fire
- False-positive battery: benign patterns don't fire
- Robustness: adversarial inputs don't crash the analyzer
- Integration: synthetic wheels/sdists through the engine
- CLI: subprocess invocation with output assertions
- Picklability: round-trip survival

A happy-path test alone is insufficient. An analyzer that catches the obvious case but fires on every benign use of similar syntax is worse than no analyzer.

## Commit discipline

- Sign off all commits (`git commit -s`) under the Developer Certificate of Origin
- Commits without sign-off cannot be merged
- Do not include working malware in test fixtures. Use benign structural shapes only.

## Common mistakes to avoid

1. **Wrong pipeline layer.** Parsers don't make security decisions. Analyzers don't assign severity. Enrichers don't emit new finding types. Rules map signals to severity. Check the pipeline diagram in CLAUDE.md.
2. **Calling runtime methods on resolved values.** The resolver models operations; it does not delegate. `value.replace(...)` is wrong; a hand-written replacement function is correct.
3. **Storing unpicklable state.** Compiled regexes, file handles, and thread-locals on analyzer/enricher/rule instances break the parallelism contract. Construct at use time.
4. **Breaking signal ID stability.** Existing IDs are stable forever. New signals get new IDs. Never rename for consistency.
5. **Missing the dual-registration pattern for CLI flags.** Global flags that only work in one position produce confusing user-facing behavior.
6. **Adding context keys without updating reporters.** Human reporter won't show keys not in its allowlist. Underscore prefix suppresses keys from JSON output.
7. **Changing triage coverage without tests.** Expanding risks false positives; shrinking silently drops detection. Both need explicit test coverage.
8. **Tests that pass when code is right but don't fail when code is wrong.** Verify your tests actually exercise the code path they claim to test.
