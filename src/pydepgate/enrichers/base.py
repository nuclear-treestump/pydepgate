"""
Base class and protocol for pydepgate enrichers.

An enricher operates on the raw signal stream produced by analyzers,
adding context and (optionally) emitting new signals. Enrichers do
not:

  - execute, compile, or import the input
  - replace or remove signals from upstream analyzers
  - know about rules (rule evaluation happens after enrichment)
  - make severity judgments

They do:

  - read the existing signals and the file's source bytes
  - compute additional context (decoded payload previews, structural
    fingerprints, cross-signal relationships) too expensive to do
    inside the analyzer pass
  - emit new signals when the additional context warrants it
  - augment existing signals' context dicts via dataclass replacement

Architectural placement
-----------------------
The per-file pipeline is:

    bytes -> parser -> analyzers -> [enrichers] -> rules -> findings

Enrichers run inside `StaticEngine._scan_one_file`, after analyzers
and before rule evaluation. They run per-file, in the same worker
process as analyzers and rules. This means enrichment cost is
parallelized for free when the engine adopts a process pool: the
same picklability and statelessness contracts that protect the
analyzer pass apply equally to enrichment.

The hint-driven dispatch
------------------------
Enrichers do not maintain a hardcoded allow-list of signal IDs they
care about. Instead, the analyzer that produced a signal *flags* it
for enrichment by populating `Signal.enrichment_hints` with one or
more enricher names. The enricher checks each incoming signal for
its own name in that set; signals without the matching hint are
passed through untouched.

Why this shape: the analyzer is the only component that actually
saw the data when it fired. It knows the literal length, alphabet,
location, file kind, and surrounding scope. The decision of
"is this signal worth enriching" lives most naturally with the
analyzer, where the relevant facts are local. Putting the request
on the signal also means a new analyzer added later can opt into
enrichment by tagging its signals; no change to the enricher needed.

The enricher retains its own threshold logic (size limits, budget
constraints, format predicates) and applies those in addition to
the hint check. The hint says "the analyzer thinks this is worth
looking at"; the enricher decides "and yes, it meets my criteria
to actually do the work."

Statelessness contract
----------------------
Implementations MUST NOT retain mutable state across `enrich`
invocations. Two reasons:

1. The engine reserves the right to invoke `enrich` concurrently
   from worker processes (currently serial; the pipeline is shaped
   to make parallelism a one-line change). Mutable per-instance
   state would be invisible across worker boundaries and produce
   silent inconsistencies between serial and parallel scans.

2. A single `StaticEngine` instance handles many scans across its
   lifetime. State retained between calls would make scan N depend
   on scans 1..N-1, which is the wrong contract.

Enrichers may hold immutable configuration in `__init__` (size
limits, magic-byte tables, depth caps); they may not accumulate
signals, caches, or counters across calls. Construct any per-call
accumulators inside `enrich` and discard them on return.

Picklability contract
---------------------
Enricher instances must be picklable. The engine pickles itself
(including its enrichers) when handing work to a worker process, so
any enricher instance attribute that is not picklable will break
parallelism the day it is added. This is invisible to integration
tests until parallelism lands; the picklability test suite at
`tests/enrichers/test_enricher_pickle.py` makes it visible.

Mutation contract
-----------------
Enrichers may NOT:

  - remove signals from the stream (downstream layers expect every
    analyzer signal to reach rule evaluation; suppression happens
    in the rules layer, not here)
  - change a signal's signal_id, analyzer, location, scope,
    confidence, description, or enrichment_hints (these are
    analyzer-determined properties and must remain identifiable
    across the pipeline)

Enrichers MAY:

  - augment a signal's context dict by replacing the signal with
    a new instance via `dataclasses.replace(sig, context={...})`
  - emit additional signals (with their own signal_id and analyzer
    name) that ride alongside the originals through rule evaluation

Both kinds of augmentation must produce frozen-dataclass-safe
output: never mutate `signal.context` in place, even though the
underlying dict is technically mutable. Replace the Signal whole.

Source-bytes meaning
--------------------
The `content` argument to `enrich` is the raw file content as the
analyzer received it. For Python source files, that is the .py
bytes. For .pth files, that is the .pth content (mostly path-like
text with occasional `import` / `exec` lines), and `signal.location`
refers to a line within the .pth, not within a synthetic Python
snippet.

Enrichers that need direct access to a literal value should prefer
reading `signal.context['_full_value']` (set by analyzers that
support enrichment) over re-extracting from `content`. The stashed
value handles the .pth-vs-.py distinction at the analyzer side, is
already-resolved at the AST level, and is bounded in size.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from pydepgate.analyzers.base import Signal
from pydepgate.engines.base import ScanContext


class Enricher(ABC):
    """Base class for enrichers.

    An enricher is a stateless object that receives the raw signal
    stream from analyzers and returns a possibly-augmented stream.
    Subclasses implement the `enrich` method.

    Enrichers are dispatched per-signal via the `enrichment_hints`
    field on Signal: an enricher whose `name` appears in a signal's
    hints is expected to consider that signal for enrichment.
    Signals without the hint pass through unchanged.

    See the module docstring for the full statelessness,
    picklability, and mutation contracts.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for diagnostics and hint matching.

        Must be stable across runs. Analyzers that flag signals for
        this enricher embed this exact string in `Signal.enrichment_hints`.
        """

    @abstractmethod
    def enrich(
        self,
        signals: tuple[Signal, ...],
        content: bytes,
        context: ScanContext,
    ) -> Iterable[Signal]:
        """Process the signal stream and return the augmented stream.

        Args:
            signals: The current signal stream, as produced by
                analyzers and any earlier enrichers in the chain.
                Treated as immutable; do not mutate.
            content: The file's raw bytes. Provided so enrichers
                can re-extract source-level information at recorded
                locations when the analyzer-stashed value is not
                sufficient. See module docstring.
            context: The per-file scan context (file kind, internal
                path, artifact identity). Read-only.

        Returns:
            An iterable of Signals representing the augmented stream.
            The result must contain at least every signal from the
            input (possibly with replaced context dicts) and may
            contain additional signals emitted by this enricher.
            Order within the result is the enricher's choice; the
            engine treats the stream as a multiset.

        Implementation guidance: iterate the signals, check each
        for `self.name in sig.enrichment_hints`, and dispatch to a
        per-signal enrichment method only when the hint matches.
        Signals without the matching hint should be passed through
        to the output unchanged.

        Raises:
            Implementations may raise to indicate internal failure.
            The engine catches these, records a diagnostic, and
            continues with the un-enriched stream from before this
            enricher was invoked. Subsequent enrichers in the chain
            still run on that fallback stream.
        """