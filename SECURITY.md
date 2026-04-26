# Security Policy

pydepgate is a security tool, which means the bar for its own security
is higher than for ordinary software. A vulnerability in pydepgate is
worse than a vulnerability in most projects of comparable size because
the tool is run against potentially malicious input by design.

This document describes how to report vulnerabilities in pydepgate,
what counts as a vulnerability, and what to expect after reporting.

## Reporting a vulnerability

The preferred channel is GitHub's private vulnerability reporting:

1. Go to https://github.com/nuclear-treestump/pydep-vector-runner/security
2. Click "Report a vulnerability"
3. Fill out the form

This creates a private thread visible only to you and the maintainers.
GitHub will help coordinate disclosure and CVE assignment if applicable.

If you prefer email, you can reach the maintainer at
`ikari@nuclear-treestump.com`. Email reports may take longer to
acknowledge than GHSA reports.

Do not file security issues on the public issue tracker.

## What's in scope

Vulnerabilities in pydepgate itself, including:

- Code execution in the pydepgate process triggered by scanning a
  crafted artifact. The static analyzer is designed never to execute
  user input; any path that does is a vulnerability.
- Path traversal or arbitrary file write during wheel or sdist
  extraction.
- Resource exhaustion (memory, CPU, file descriptors) triggered by
  a small crafted artifact, where the resource use is disproportionate
  to the input size.
- Output injection: a finding's content escaping the JSON or human
  reporter and producing misleading or malicious output.
- Credential or secret leakage through error messages, logs, or
  output formats.
- Vulnerabilities in pydepgate's installation path that would let an
  attacker tamper with the tool itself.

## What's out of scope

These are bugs, not security vulnerabilities. File them on the public
issue tracker using the bug report template:

- pydepgate failed to detect a known piece of malware. The threat
  model is that pydepgate does not itself become a vector, not that
  it detects every possible attack. Detection gaps are bugs and
  feature requests.
- pydepgate flagged a benign artifact as malicious. False positives
  are bugs.
- pydepgate produced wrong severity, wrong line numbers, or other
  incorrect output for a non-security-impacting reason.
- Documentation errors, even ones that could mislead a user about
  what pydepgate detects.

If you're unsure whether something is in scope, err on the side of
reporting it through the security channel. We would rather review a
bug report through the security path than miss a real vulnerability
because someone wasn't sure.

## What to expect

pydepgate is currently maintained by one person on a side-project
schedule. The commitments below reflect that reality.

- **Acknowledgment.** I will acknowledge receipt within five business
  days. If you don't hear back in that window, the report didn't get
  to me, please send a follow-up.
- **Triage.** I will tell you whether the report is in scope and
  approximately what severity I'm assigning within two weeks.
- **Fix.** Timeline depends on severity:
  - Critical (remote code execution, sandbox escape): emergency
    release, target one week.
  - High: next scheduled release, target one month.
  - Medium and low: prioritized in the normal backlog.
- **Disclosure.** I will coordinate disclosure with you. The default
  is to publish a security advisory after a fix is released, crediting
  the reporter unless they prefer to remain anonymous.

## Credit

Reporters who follow this process and find legitimate vulnerabilities
will be credited in the GitHub Security Advisory and the release notes
for the version that contains the fix, unless they prefer otherwise.

pydepgate is a side project and does not offer monetary bug bounties.

## Out-of-band

If you discover something so severe that even private GHSA reporting
feels too slow (active exploitation in the wild, etc.), email
`ikari@nuclear-treestump.com` with `BUGCHECK` in the subject. I
check email more often than GitHub notifications and will respond
faster.

## Vulnerabilities in dependencies

pydepgate has no third-party runtime dependencies by design. If a
vulnerability is reported against the Python standard library or
CPython itself, that's not a pydepgate issue, but if pydepgate's use
of the affected stdlib feature has security implications, that is in
scope and we want to know.

## A note on testing

If you're testing for vulnerabilities, please do so against your own
local copy of pydepgate. Do not test against any service or
infrastructure that hosts pydepgate (PyPI, GitHub Actions, etc.).
Local testing on artifacts you control is welcome and encouraged.
