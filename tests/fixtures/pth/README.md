# .pth Parser Test Fixtures

These fixtures exercise pydepgate's `.pth` file parser against the structural
patterns of real Python supply-chain attacks.

## Safety

**All fixtures are synthetic and contain only inert payloads.** No executable
malicious code is present in this directory. Fixtures that reproduce the
*shape* of attacks (base64+exec, subprocess spawning, network calls, etc.)
use payloads that print, echo, or target RFC 2606 reserved domains
(`example.invalid`), so even if a fixture were accidentally executed, no
harm would occur.

Fixtures are prefixed for clarity:

- `benign_*` — patterns that must NOT be flagged by any rule.
- `synthetic_*` — structural patterns of known attacks, with inert payloads.
- `malformed_*` — encoding or formatting edge cases.
- `empty` / `only_whitespace` — degenerate inputs.

## Attack Patterns Represented

The `synthetic_*` fixtures model techniques catalogued under
[MITRE ATT&CK T1546.018 — Python Startup Hooks](https://attack.mitre.org/techniques/T1546/018/),
including the LiteLLM 1.82.8 supply-chain attack (March 2026, see
BerriAI/litellm#24512). The parser and rule engine are validated against
these structural patterns rather than against live malware.

## Regenerating Generated Fixtures

Some fixtures are produced programmatically because they contain bytes
or structures that editors mangle. See `scripts/generate_fixtures.py`
(to be added) to regenerate:

- `malformed_encoding.pth`
- `malformed_bare_cr.pth`
- `synthetic_oversized.pth`
- `only_whitespace.pth`
- `empty.pth`

## Testing Against Real Samples

For regression testing against real malicious packages from the OSSF
malicious-packages or Datadog datasets, use a disposable VM or container.
Do not commit real malicious samples to this repository. I will be very sad.