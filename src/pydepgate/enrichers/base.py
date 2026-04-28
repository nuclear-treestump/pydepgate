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
limits, signal-id filter sets, magic-byte tables); they may not
accumulate signals, caches, or counters across calls. Construct any
per-call accumulators inside `enrich` and discard them on return.

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
    confidence, or description (these are analyzer-determined
    properties and must remain identifiable across the pipeline)

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
snippet. Enrichers that extract source-level information from
specific (line, column) positions must be aware of this distinction
and handle the .pth case appropriately (or filter to file kinds
they support via `applies_to` and the rule engine's downstream
file-kind matching).
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

    See the module docstring for the full statelessness, picklability,
    and mutation contracts.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for diagnostics. Must be stable across runs."""

    @property
    def applies_to(self) -> frozenset[str]:
        """Set of signal_id values this enricher considers.

        An empty frozenset (the default) means the enricher should
        be invoked for every file regardless of which signals are
        present. Most enrichers will narrow this to the specific
        signal IDs they augment, allowing the engine to skip them
        when no relevant signals were emitted.

        This is an optimization hint, not a security boundary.
        Enrichers must still tolerate being called with signals
        outside their declared applies_to set; the engine may
        relax the filter in future iterations.
        """
        return frozenset()

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
            content: The file's raw bytes. Provided so enrichers can
                re-extract source-level information (literal values,
                token spans) at recorded locations without re-running
                the parser pass. See the module docstring for what
                this means across file kinds.
            context: The per-file scan context (file kind, internal
                path, artifact identity). Read-only.

        Returns:
            An iterable of Signals representing the augmented stream.
            The result must contain at least every signal from the
            input (possibly with replaced context dicts) and may
            contain additional signals emitted by this enricher.
            Order within the result is the enricher's choice; the
            engine treats the stream as a multiset.

        Raises:
            Implementations may raise to indicate internal failure.
            The engine catches these, records a diagnostic, and
            continues with the un-enriched stream from before this
            enricher was invoked. Subsequent enrichers in the chain
            still run on the un-enriched stream.
        """