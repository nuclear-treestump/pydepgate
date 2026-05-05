"""pydepgate.rules.__init__

Rules engine for pydepgate.

Rules are data: each rule has match conditions and an effect. The
evaluator iterates rules per signal, finds applicable matches, and
produces findings according to the effects.

Rules come from three sources, in load order:
  - Bundled defaults shipped with pydepgate.
  - System config (stub for now; loader to be implemented).
  - User config from .gate files (loader in Session B).

User rules always override default rules in case of conflict, but
suppressed default findings remain visible in the suppressed_findings
section of scan results.
"""