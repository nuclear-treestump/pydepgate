"""pydepgate.reporters._common.color

Color handling for pydepgate's reporters.

Owns the ANSI color palette and the auto/always/never color-mode
decision logic shared by all reporters that emit human-readable
output. The visualizers (density_map, peek_render) have their own
color handling on a separate, untouched code path; this module is
specifically the home of what cli/reporter.py used to define
locally as _Color, _color_enabled, _severity_color.

NO_COLOR support follows the https://no-color.org standard.
PYDEPGATE_NO_COLOR is honored as an alias.

Symbols here are public (no leading underscore) because they cross
module boundaries within the reporters package. Internal naming
within a single module would be private; package-level shared
names are public, matching the convention in
visualizers/peek_render.py (ColorScheme, PLAIN, ANSI).
"""

from __future__ import annotations

import os
import sys

from pydepgate.engines.base import Severity


# Color mode constants. Used as the values of args.color and as
# argument values to color_enabled().
COLOR_AUTO = "auto"
COLOR_ALWAYS = "always"
COLOR_NEVER = "never"


class Color:
    """ANSI color codes used by pydepgate's human-readable output.

    Direct codes rather than a third-party dep, consistent with
    pydepgate's stdlib-only constraint.
    """

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


def color_enabled(color_mode: str) -> bool:
    """Decide whether ANSI color codes should be emitted.

    Three modes:
      always  Always emit color, even when stdout is not a TTY and
              even when NO_COLOR is set in the environment. The user
              explicitly asked for color; respect that.
      never   Never emit color.
      auto    Defer to environment and TTY detection. Color is
              disabled if NO_COLOR or PYDEPGATE_NO_COLOR is set in
              the environment, or if stdout is not a terminal
              (output is being piped or redirected).

    The auto branch is the historical default behavior; always and
    never are the explicit escape hatches.
    """
    if color_mode == COLOR_ALWAYS:
        return True
    if color_mode == COLOR_NEVER:
        return False

    # auto (or any unrecognized value, defensively): the historical
    # rules. NO_COLOR per the no-color.org standard takes precedence
    # over auto-detection but not over an explicit "always".
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("PYDEPGATE_NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    return True


def severity_color(severity: Severity, color: bool) -> tuple[str, str]:
    """Return (prefix, suffix) ANSI codes for a severity. ('', '') if no color."""
    if not color:
        return ("", "")
    palette = {
        Severity.CRITICAL: Color.RED + Color.BOLD,
        Severity.HIGH: Color.RED,
        Severity.MEDIUM: Color.YELLOW,
        Severity.LOW: Color.BLUE,
        Severity.INFO: Color.DIM,
    }
    prefix = palette.get(severity, "")
    return (prefix, Color.RESET if prefix else "")