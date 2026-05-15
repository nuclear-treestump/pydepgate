"""pydepgate.pdgplatform.__init__

OS-aware primitives shared across pydepgate subsystems.

Currently houses:

  paths  XDG Base Directory resolution with Windows and macOS
         fallbacks, plus pydepgate-specific cache directory
         helpers built on top.

Future modules may include platform-specific signal handling
and other OS abstractions. The surface is intentionally small
until a second user shows up.

"""
