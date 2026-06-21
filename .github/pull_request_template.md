# Pull Request

## Summary

<!-- Briefly describe what changed and why. -->

## Type of change

Check all that apply:

* [ ] Detection / analyzer logic
* [ ] Rules / policy behavior
* [ ] CLI behavior
* [ ] Output format: text / JSON / SARIF / events
* [ ] CVE / dependency scanning
* [ ] Parser / artifact handling
* [ ] Evidence database / persistence
* [ ] Documentation
* [ ] Tests / fixtures
* [ ] Refactor / internal cleanup
* [ ] Docker / release engineering
* [ ] Other:

## Related issue or discussion

<!-- Link issue, discussion, or context if applicable. -->

Closes #

## Safety impact

pydepgate analyzes potentially malicious package artifacts. This PR must not execute untrusted package content.

* Does this PR change how package artifacts, archives, decoded payloads, metadata, or untrusted input are parsed or processed?

  * [ ] No
  * [ ] Yes, explain:

* Does this PR import, execute, compile, evaluate, deserialize, or otherwise run user-provided package content?

  * [ ] No
  * [ ] Yes, this requires redesign before review.

* Does this PR add any runtime dependency?

  * [ ] No
  * [ ] Yes, explain why the standard library is insufficient:

Safety notes:

<!--
Mention relevant guardrails here, such as bounded decoding, path traversal protection,
content-blind output, parser failure behavior, resolver safety, or why this is not applicable.
-->

## User-facing compatibility

Check any user-facing contract this PR changes:

* [ ] CLI flags or defaults
* [ ] Exit codes
* [ ] Signal IDs
* [ ] Finding IDs
* [ ] Severity mapping
* [ ] JSON output
* [ ] SARIF output
* [ ] Event JSONL payloads
* [ ] Rule file syntax
* [ ] Evidence DB schema
* [ ] Documentation URLs or anchors
* [ ] None of the above

Compatibility notes:

<!--
Explain whether the change is breaking, additive, internal-only, or backward compatible.
For additive event/JSON fields, say whether existing fields are preserved.
-->

## Tests

Tests added or updated:

* [ ] Unit tests
* [ ] CLI/subprocess tests
* [ ] Regression fixtures
* [ ] JSON/SARIF/event expectations
* [ ] Documentation-only change; tests not required
* [ ] Not tested, explain:

Commands run:

```bash
# paste commands here
```

Result:

<!-- Example: 1523 passed in 27.31s -->

## Fixtures and test data

* [ ] No fixtures added
* [ ] Fixtures are synthetic/inert
* [ ] Fixtures contain no live malware, credentials, tokens, private URLs, or sensitive data

Notes:

<!-- Optional. -->

## Documentation and release notes

* [ ] Docs updated
* [ ] Changelog/release notes needed
* [ ] Documentation not required

Notes:

<!-- Optional. -->

## Reviewer notes

<!-- Anything reviewers should pay special attention to? -->

## Contributor checklist

* [ ] I have read `CONTRIBUTING.md`.
