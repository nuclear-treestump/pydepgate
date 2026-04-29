"""
Bundled default rules for pydepgate.

These rules encode pydepgate's baseline policy: what severity to assign
to each signal in each context. Users override these via .gate files;
defaults are starting points, not policy.

Each rule has a descriptive snake_case ID and an explain string that
is surfaced via 'pydepgate explain'.
"""

from __future__ import annotations

from pydepgate.rules.groups import DEFAULT_RULES


__all__ = ["DEFAULT_RULES"]