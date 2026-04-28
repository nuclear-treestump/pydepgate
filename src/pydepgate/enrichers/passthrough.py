"""
A no-op enricher used to verify pipeline wiring.

This module exists for two reasons:

  1. The skeleton PR for the enricher subsystem ships without any
     useful enricher; the no-op proves the wiring works end to end
     without committing to a specific feature surface.

  2. The picklability and statelessness test suites need a real
     `Enricher` subclass to exercise. The no-op is the smallest
     concrete implementation that satisfies the ABC.

Production enrichers (payload_peek and any future siblings) live in
their own modules. The no-op is internal-only; it is not registered
in any default enricher list, and should not be instantiated by
production code paths. The leading underscore on the module name
signals this intent.
"""

from __future__ import annotations

from typing import Iterable

from pydepgate.analyzers.base import Signal
from pydepgate.engines.base import ScanContext
from pydepgate.enrichers.base import Enricher


class NoOpEnricher(Enricher):
    """Returns the input signal stream unchanged.

    Useful for wiring tests, picklability tests, and as a baseline
    when measuring the overhead of enrichment-aware pipeline shapes.
    """

    @property
    def name(self) -> str:
        return "noop"

    def enrich(
        self,
        signals: tuple[Signal, ...],
        content: bytes,
        context: ScanContext,
    ) -> Iterable[Signal]:
        return signals