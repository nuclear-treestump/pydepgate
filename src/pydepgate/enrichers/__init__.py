"""pydepgate.enrichers.__init__

pydepgate signal enrichers.

Enrichers operate on the raw signal stream produced by analyzers,
augmenting context and (optionally) emitting new signals. See
`pydepgate.enrichers.base` for the contract.
"""

from pydepgate.enrichers.base import Enricher

__all__ = ["Enricher"]