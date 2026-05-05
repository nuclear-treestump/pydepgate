"""pydepgate.analyzers.base

Base classes and protocols for pydepgate analyzers.

An analyzer inspects a parsed representation of source code and emits
Signals describing notable patterns. Analyzers do not:
  - execute, compile, or import the input
  - know about rules (they just emit signals)
  - make severity judgments (that's for rules)

They do:
  - walk the parsed structure
  - emit Signals with a confidence level
  - include enough location context for downstream layers to reason about

  

"""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Iterable

from pydepgate.parsers.pysource import ParsedPySource, SourceLocation


class Confidence(IntEnum):
    """How certain the analyzer is that the pattern it observed is real.

    This is distinct from severity. Severity is a rule-level judgment about
    how bad a finding is. Confidence is an analyzer-level judgment about
    whether the analyzer is seeing what it thinks it's seeing.

    An encoding_abuse signal with DEFINITE confidence is very reliably a
    base64-decode-then-exec pattern. A rule can then decide that such a
    pattern is CRITICAL in setup.py and merely INFO in application code.
    """
    AMBIGUOUS = 10
    LOW = 30
    MEDIUM = 50
    HIGH = 70
    DEFINITE = 90


class Scope(IntEnum):
    """Where in the source structure a signal was observed.

    Module-level observations are the highest-impact (they execute on
    import). Function-level observations are lower-impact unless the
    function is called at module level. Class-body observations sit
    between.
    """
    MODULE = 10
    CLASS_BODY = 20
    FUNCTION = 30
    NESTED_FUNCTION = 40
    UNKNOWN = 99


@dataclass(frozen=True)
class Signal:
    """A single notable pattern detected by an analyzer.

    The `enrichment_hints` field carries names of enrichers (see
    `pydepgate.enrichers`) that the analyzer wants invoked on this
    signal. An empty frozenset (the default) means no enrichment is
    requested. The hint is set by the analyzer at construction time
    based on the analyzer's local knowledge of the data; the
    enricher uses the hint as a coarse filter before applying its
    own (size, format, budget) criteria.
    """
    analyzer: str
    signal_id: str
    confidence: Confidence
    scope: Scope
    location: SourceLocation
    description: str
    context: dict[str, Any] = field(default_factory=dict)
    enrichment_hints: frozenset[str] = field(default_factory=frozenset)

class Analyzer(ABC):
    """Base class for analyzers.

    An analyzer is a stateless object (all state lives in the visitor
    pattern during a single analyze() call). Subclasses implement the
    analyze() method for Python source, and/or analyze_pth() for .pth
    files. Most analyzers only care about one input type.

    Statelessness contract:

    Implementations MUST NOT retain mutable state across
    `analyze_python` invocations. Two reasons:

    1. The engine reserves the right to invoke `analyze_python`
        concurrently from worker processes (currently serial; the
        pipeline is shaped to make parallelism a one-line change).
        Mutable per-instance state would be invisible across worker
        boundaries and produce silent inconsistencies between serial
        and parallel scans.

    2. A single `StaticEngine` instance handles many scans across
        its lifetime. State retained between calls would make scan N
        depend on scans 1..N-1, which is the wrong contract.

    Analyzers may hold immutable configuration in `__init__`
    (thresholds, regex compilations, alphabet tables); they may
    not accumulate findings, counters, or caches across calls.
    Construct any per-call accumulators inside `analyze_python`
    and discard them on return.

    """
    safe_for_library_scan: bool = False
    """Whether this analyzer is appropriate to run on FileKind.LIBRARY_PY
    files (ordinary library code outside startup vectors). The engine
    filters analyzers using this attribute when scanning in deep mode.

    Default False. Subclasses opt in by setting True. The criterion
    is calibration: an analyzer is safe for library scanning when its
    signals carry meaningful information without rule-layer promotion.
    Most pydepgate analyzers fail this test because their signals are
    designed to be elevated by file-kind-specific rules; in library
    code they would produce many false positives.

    The density analyzer overrides this to True because its signals
    (entropy, Unicode anomalies, structural patterns) are equally
    meaningful regardless of file context, even though severity
    calibration differs across file kinds via the rule layer.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier, used in Signal.analyzer."""

    def analyze_python(self, parsed: ParsedPySource) -> Iterable[Signal]:
        """Analyze a parsed Python source file. Default: no signals."""
        return ()

    def analyze_pth_exec_line(
        self,
        line_text: str,
        location: SourceLocation,
    ) -> Iterable[Signal]:
        """Analyze an executable line from a .pth file. Default: no signals.

        .pth exec lines are single Python statements, not full modules.
        They can be parsed with ast.parse(mode='single') if the analyzer
        needs an AST.
        """
        return ()