# Security Policy
v1.1

> What changed:
* Added ZipCrypto to out of scope bucket

> Last Updated: 2026-05-03 

pydepgate is a security tool, which means the bar for its own security
is higher than for ordinary software. A vulnerability in pydepgate is
worse than a vulnerability in most projects of comparable size because
the tool is run against potentially malicious input by design.

This document describes how to report vulnerabilities in pydepgate,
what counts as a vulnerability, and what to expect after reporting.

## Reporting a vulnerability

The preferred channel is GitHub's private vulnerability reporting:

1. Go to https://github.com/nuclear-treestump/pydepgate/security
2. Click "Report a vulnerability"
3. Fill out the form

This creates a private thread visible only to you and the maintainers.
GitHub will help coordinate disclosure and CVE assignment if applicable.

If you prefer email, you can reach the maintainer at
`ikari@nuclear-treestump.com`. Email reports may take longer to
acknowledge than GHSA reports.

Please, do NOT file security issues on the public issue tracker.

If you require E2EE communication, please contact me via email so I 
can coordinate with you. I have Signal and PGP.

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
- Third party interactions with pydepgate. I cannot anticipate how
 other software will interact with pydepgate. I've done my best to adhere
to a standard, but if you find interesting interactions, please raise it. 
- Purely AI sourced reports without user input. I am one person, not
 a corporation and I don't have unlimited time. Please respect my time
and I will respect yours.
  - This is NOT meant to say "No AI assistance", just please verify your
   findings first.
- Malicious detections in test fixtures or tests/ directory. The tests are
benign but look scary for the tool to test detection without detonating malware
 on my only computer.
- Cryptographic weaknesses in the encrypted-archive feature beyond
  what's already documented. The README states ZipCrypto is broken
  by design (AV-friendliness, not confidentiality); a vulnerability
  in scope here would be one that lets an attacker tamper with
  archive contents in a way the documented threat model doesn't
  account for, or that leaks plaintext under conditions that
  contradict the documentation.

If you're unsure whether something is in scope, err on the side of
reporting it through the security channel. We would rather review a
bug report through the security path than miss a real vulnerability
because someone wasn't sure.

## Not in either scope but appreciated

These are items I would prefer raised as feature requests or PRs. The Vulnerability Report workflow 
is the wrong tool for the job here. Please raise an Issue.

- New detection methods for pydepgate. 
- Expanded documentation on the existing API.
- New operational modes.
- Other ideas that I haven't thought of.

Even if its just a conceptual idea, I will do my best to analyze and see if it is possible.

You will get credit if I make the improvement, unless you request otherwise.

## Submission Requirements

1. Version of pydepgate in use
   > `pydepgate --version`
2. OS in use
3. Version of Python in use
   > Only 3.11, 3.12, 3.13, and beyond are in scope
5. Working proof of concept (a reproducer artifact, a command line, and the observed output)
   > Reports that consist primarily of AI-generated analysis without a verified reproducer will be closed with a request for verification.
5. Explanation of how this vulnerability could be used or if applicable potential killchains.
6. Please confirm if you'd like credit or prefer to be anonymous.
7. (optional) If you have found a way to fix this, please share the fix so I can validate it. This is not required, but greatly appreciated.

## What to expect

pydepgate is currently maintained by one person on a side-project
schedule. I check my email daily. The commitments below reflect that reality.

- **Acknowledgment.** I will acknowledge receipt within five business
  days. If you don't hear back in that window, the report didn't get
  to me, please send a follow-up.
  - The five days is the ceiling, not the floor.
  I will do my best to get back to you as fast as I am able. 
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
- **CVEs.** CVEs will be requested through GitHub's CNA process. I haven't had to
 use that path yet, but the workflow is documented and I'll execute it when needed.
- **Lack of Response.** If I have not responded with a fix or a coordinated extension
within 90 days, the reporter is free to disclose publicly.
  - Please reach out to me before it gets to this point. I do not want you to feel stuck and
 I don't want to blindside my users.

## Credit

Reporters who follow this process and find legitimate vulnerabilities
will be credited in the GitHub Security Advisory and the release notes
for the version that contains the fix, unless they prefer otherwise.

pydepgate is a side project and does not offer monetary bug bounties. I 
do not have the money to pay you and currently build radiators for a living.

If you ARE a corporation looking for a security engineer, I am available.

If my living situation changes, a paid bug bounty may be enacted.

## Safe Harbor

I will not pursue legal action against researchers who follow this policy 
in good faith, including testing against artifacts you control and reporting 
through the channels described in this document. 

## Out-of-band

If you discover something so severe that even private GHSA reporting
feels too slow (active exploitation in the wild, etc.), email
`ikari@nuclear-treestump.com` with `BUGCHECK` (or `GURUMEDITATION`, if you prefer) 
in the subject. I check email more often than GitHub notifications and will respond
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
