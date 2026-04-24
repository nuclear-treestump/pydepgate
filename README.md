# pydepgate

**A lightweight Python runner that interdicts suspicious startup behavior.**

pydepgate inspects Python packages and environments for code that executes
silently at interpreter startup. This was the attack class used by the March 2026
LiteLLM supply-chain compromise and catalogued as
[MITRE ATT&CK T1546.018](https://attack.mitre.org/techniques/T1546/018/).

## Update

We are now on PyPI. See it here now! [PyDepGate](https://pypi.org/project/pydepgate/).

v0.0.2 coming very soon. :)

## Status

**Early development (v0.0.1).** The `.pth` parser and its test harness are
complete. Rules, engines, CLI, and runtime interdiction are not yet implemented.
See [ROADMAP.md](ROADMAP.md) for the build plan.

This project is not yet usable as a security tool. It will be marked v0.1.0
when the static-analysis mode is functional end-to-end.

## The problem

Python's interpreter runs several kinds of code automatically at startup,
before any user script executes:

- `.pth` files in `site-packages/`. Any line beginning with `import` is
  passed to `exec()` by `site.py` during interpreter initialization.
- `sitecustomize.py` and `usercustomize.py`. Imported automatically if present.
- `__init__.py` top-level code in any imported package.
- `setup.py`. Executed during `pip install` for source distributions.
- Console-script entry points. Generated and executed by `pip install`.

Each of these is a legitimate Python feature. Each has been used in
real-world supply-chain attacks. Existing Python security tooling
(`pip-audit`, `safety`, `bandit`) does not inspect these startup vectors.
The `.pth` vector in particular has been acknowledged as a security gap in
[CPython issue #113659](https://github.com/python/cpython/issues/113659) but
has no patch.

## The approach

pydepgate is designed as a Python runner rather than a scanner. It operates
in three modes:

- **`static`**. Unpack a wheel or sdist and analyze its startup vectors
  without installing or executing anything.
- **`preflight`**. Walk an already-installed environment and report on what
  would execute at the next interpreter startup.
- **`exec`**. Wrap `python` itself, intercepting startup-vector code before
  it runs and blocking, warning, or auditing according to policy.

All three modes share a single heuristic engine. The `exec` mode is the
differentiator: it operates at the interpreter boundary, using PEP 578 audit
hooks and a shim on `site.addpackage`, to prevent execution rather than
retroactively flag it.

## Design constraints

- **Zero runtime dependencies.** Standard library only.
- **Block monkeypatching of pydepgate itself.** Self-integrity verification
  at bootstrap; critical stdlib references captured into locals before any
  untrusted code runs.
- **Lightweight.** Target overhead for `exec` mode is under 100ms on a clean
  startup. Static and preflight modes are one-shot and have no hard budget.
- **Safe by construction.** Parsers never execute, compile, or import input
  content. Rules operate on parsed representations, never on live code.

## Relationship to PyDepGuard

pydepgate is a narrow, single-purpose tool focused on startup-vector
interdiction. [PyDepGuard](https://github.com/nuclear-treestump/pylock-dependency-lockfile) is a
broader Python security framework covering runtime sandboxing, cryptographic
IPC, secure memory, and dependency management. The startup-vector engine
developed in pydepgate is intended to eventually integrate with PyDepGuard
as a subsystem; until then, the two projects are developed independently.

Users who need only startup-vector protection should use pydepgate. Users
who need the full runtime security model should use PyDepGuard directly.

## What exists today

- `pydepgate.parsers.pth`. A safe, non-executing parser for `.pth` files.
- Fourteen test fixtures covering benign patterns, attack shapes, encoding
  edge cases, and malformed inputs.
- A fixture-generator script for reproducible test data.

Everything else is planned. See [ROADMAP.md](ROADMAP.md).

## Development

Requires Python 3.11 or later.

```bash
git clone https://github.com/nuclear-treestump/pydep-vector-runner
cd pydepgate
pip install -e .
python -m unittest discover tests -v
```

To regenerate the binary test fixtures after editing them:

```bash
python scripts/generate_fixtures.py
```

## Safety notes

This project builds tooling to defend against Python supply-chain attacks.
The test fixtures in `tests/fixtures/` are synthetic. They model the
*structural shape* of known attacks (LiteLLM 1.82.8, others catalogued under
T1546.018) but contain only inert payloads. No actual malicious code is
present in this repository.

For regression testing against real malicious samples, use the
[OSSF malicious-packages](https://github.com/ossf/malicious-packages),
[Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset),
or [lxyeternal/pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry)
datasets. Do so in disposable VMs or containers, and do not commit samples
to this repository.

## Author

Ikari ([@0xIkari](https://github.com/0xIkari))
