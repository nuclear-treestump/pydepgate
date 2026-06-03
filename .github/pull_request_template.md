# Pull Request

## Summary

<!--
Briefly describe what this PR changes.

Examples:
- Adds a new analyzer for suspicious import-time subprocess use.
- Fixes SARIF output for decoded payload code flows.
- Updates documentation for custom rules.
- Adds regression fixtures for encoded startup payload chains.
-->

## Type of change

<!-- Check all that apply. -->

* [ ] Analyzer / detection logic
* [ ] Rules engine / policy behavior
* [ ] Output format: text / JSON / SARIF
* [ ] CLI behavior
* [ ] Parser / artifact handling
* [ ] CVE / dependency-resolution behavior
* [ ] Evidence database / persistence
* [ ] Docker / release engineering
* [ ] Documentation
* [ ] Tests / fixtures only
* [ ] Refactor with no intended behavior change
* [ ] Other:

## Related issue or discussion

<!--
Link the issue, discussion, or context for this PR if one exists.

For larger architectural changes, please open an issue or discussion before
submitting the PR.
-->

Closes #

## Threat model and safety impact

<!--
pydepgate is run against potentially malicious package artifacts by design.
If this PR touches parsing, unpacking, decoding, partial evaluation, file IO,
subprocess handling, output generation, or package installation behavior,
explain the safety impact here.
-->

* Does this PR process untrusted package content in a new way?

  * [ ] No
  * [ ] Yes, explanation:

* Does this PR execute, import, compile, evaluate, deserialize, or otherwise
  run user-provided package content?

  * [ ] No
  * [ ] Yes

If you checked **Yes** above, stop. pydepgate static analysis must not execute
untrusted package content. This PR will need redesign before review.

## Runtime dependencies

pydepgate core is zero-runtime-dependency by design.

* [ ] This PR adds no new runtime dependencies.
* [ ] This PR adds no new optional dependency path.
* [ ] This PR changes only documentation, tests, or packaging metadata.

If this PR adds or requires a dependency, explain why the change cannot be
implemented with the Python standard library:

<!-- Explanation required if applicable. -->

## Static-analysis safety checklist

<!-- Check all that apply. Leave unchecked items explained below. -->

* [ ] No scanned artifact is imported.
* [ ] No scanned artifact is executed.
* [ ] No scanned artifact is compiled with `compile()`.
* [ ] No pickle or marshal data from scanned artifacts is loaded.
* [ ] Archive extraction paths are normalized and guarded against traversal.
* [ ] Decode/decompression behavior is bounded by depth and/or byte limits.
* [ ] New parsing behavior fails closed or emits a controlled error.
* [ ] No secrets, tokens, local paths, or payload bytes are leaked into output
  unless the relevant mode explicitly allows it.

Explanation for unchecked items:

<!-- If any item above is unchecked, explain why. -->

## Partial evaluator / resolver safety

<!--
Required if this PR touches safe partial evaluation, string resolution,
obfuscation handling, AST walking, or resolver behavior.
-->

* [ ] Not applicable.
* [ ] This PR does not delegate attacker-controlled values to runtime methods.
* [ ] This PR models operations using pydepgate-controlled values only.
* [ ] This PR does not rely on `__getattr__`, `__class__`, overloaded operators,
  or other attacker-controlled Python behavior.
* [ ] Resolver changes include tests for hostile or weird input shapes.

Notes:

<!-- Optional details. -->

## Multiprocessing / picklability contract

<!--
Required if this PR touches scan input/output objects, analyzers, engines,
traffic control, parsed representations, findings, signals, or evidence
objects.
-->

* [ ] Not applicable.
* [ ] New or changed scan input/output objects are picklable.
* [ ] No new module-level mutable state is required for scan correctness.
* [ ] No file-scoped side effects are introduced during scan execution.
* [ ] Objects crossing worker/process boundaries use stable, serializable data.

Notes:

<!-- Optional details. -->

## User-facing contracts

Check any user-facing contract this PR changes:

* [ ] Signal IDs
* [ ] Finding IDs
* [ ] Severity mapping
* [ ] Exit codes
* [ ] JSON schema
* [ ] SARIF structure
* [ ] CLI flags or defaults
* [ ] Rule file syntax
* [ ] Evidence DB schema
* [ ] Docker image behavior
* [ ] Documentation URLs or anchors
* [ ] None of the above

If any are checked, explain compatibility impact:

<!--
Signal IDs, exit codes, and machine-readable output are user-facing contracts.
Breaking changes need strong justification and migration notes.
-->

## Output and content-safety impact

<!-- Required if this PR touches text, JSON, SARIF, decoded payload output,
peek behavior, reports, or logging. -->

* [ ] Not applicable.
* [ ] Text output remains human-readable.
* [ ] JSON output remains schema-versioned and machine-consumable.
* [ ] SARIF output remains valid SARIF 2.1.0.
* [ ] Content-blind output remains content-blind.
* [ ] Payload bytes are not re-leaked through descriptions, logs, or SARIF
  messages.
* [ ] Any new output fields are documented or intentionally internal.

Notes:

<!-- Optional details. -->

## Tests

<!--
Describe the tests added or changed. If no tests were added, explain why.
-->

* [ ] Unit tests added or updated.
* [ ] CLI/subprocess tests added or updated.
* [ ] Regression fixture added or updated.
* [ ] SARIF/JSON snapshot or schema expectations updated.
* [ ] Docker/release workflow tested or reason provided.
* [ ] Documentation-only change; tests not required.

Commands run:

```bash
# paste commands here
```

Result:

<!-- Example: 1523 passed in 27.31s -->

## Fixtures and sample data

<!--
Do not commit live malware. Fixtures should model malicious structure with
inert payloads.
-->

* [ ] No fixtures added.
* [ ] Fixtures are synthetic/inert.
* [ ] Fixtures do not contain live malware, working credentials, real tokens,
  private URLs, or sensitive customer data.
* [ ] Fixture intent is documented in test names or comments.

Notes:

<!-- Optional details. -->

## Documentation

* [ ] README updated if user-facing behavior changed.
* [ ] Docs site updated if CLI/rules/output behavior changed.
* [ ] `SECURITY.md` updated if vulnerability handling or threat model changed.
* [ ] `CONTRIBUTING.md` updated if contributor requirements changed.
* [ ] Changelog/release notes update needed.
* [ ] Documentation not required.

Notes:

<!-- Optional details. -->

## Security-sensitive change notice

Does this PR introduce, fix, or materially affect a security-sensitive behavior?

* [ ] No
* [ ] Yes

If yes, describe the impact:

<!--
Examples:
- Fixes path traversal during sdist inspection.
- Changes decoded payload handling.
- Changes report redaction behavior.
- Changes how untrusted archives are unpacked.
-->

If this is a vulnerability fix that should not be public yet, do not continue
in a public PR. Follow `SECURITY.md` instead.

## AI-assisted contribution disclosure

<!--
AI assistance is allowed, but contributors are responsible for every line.
-->

* [ ] I did not use AI assistance for this PR.
* [ ] I used AI assistance, and I have reviewed, tested, and understand the
  resulting changes.

If AI assistance was used, briefly describe where:

<!-- Optional but encouraged. -->

## Contributor certification

By submitting this PR, I certify that:

* [ ] I have read `CONTRIBUTING.md`.
* [ ] I agree that this contribution is licensed under the project license.
* [ ] My commits are signed off under the Developer Certificate of Origin
  using `Signed-off-by: Name <email>`.
* [ ] I understand that pydepgate must not execute untrusted package content
  during static analysis.
* [ ] I understand that zero runtime dependencies are a core project constraint.
* [ ] I understand that signal IDs, exit codes, schemas, and machine-readable
  outputs are user-facing contracts.

## Reviewer notes

<!--
Anything reviewers should pay special attention to?
-->
