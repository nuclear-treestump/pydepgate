"""pydepgate.pdgplatform.paths

XDG Base Directory resolution with platform-aware fallbacks.

Public surface:

    xdg_cache_home() -> Path
        $XDG_CACHE_HOME if set; otherwise the platform default
        (Linux: ~/.cache, macOS: ~/Library/Caches, Windows:
        %LOCALAPPDATA% or ~/AppData/Local).

    xdg_config_home() -> Path
        $XDG_CONFIG_HOME if set; otherwise the platform default
        (Linux: ~/.config, macOS: ~/Library/Application Support,
        Windows: %APPDATA% or ~/AppData/Roaming).

    xdg_data_home() -> Path
        $XDG_DATA_HOME if set; otherwise the platform default
        (Linux: ~/.local/share, macOS: ~/Library/Application
        Support, Windows: %LOCALAPPDATA% or ~/AppData/Local).

    pydepgate_cache_dir() -> Path
        xdg_cache_home() / "pydepgate"

    pydepgate_config_dir() -> Path
        xdg_config_home() / "pydepgate"

    pydepgate_data_dir() -> Path
        xdg_data_home() / "pydepgate"

    ensure_directory(path) -> Path
        mkdir(parents=True, exist_ok=True) and return.

This module is stdlib-only. All functions read sys.platform and
os.environ at call time rather than at import time so tests can
patch the environment without restarting the process.

Tilde expansion: XDG environment variables are expanded with
os.path.expanduser before being used. A user who sets
XDG_CACHE_HOME=~/mycache expects the tilde to resolve.

Precedence rule: when XDG_* is set, it always wins, including
on macOS and Windows. This deviates slightly from a pure
platform-native model but matches the behavior of every
cross-platform Python tool I have looked at (platformdirs,
appdirs, click). A developer who deliberately exports
XDG_CACHE_HOME on macOS to test Linux-like behavior gets what
they asked for.

The XDG Base Directory Specification is at:
    https://specifications.freedesktop.org/basedir-spec/

The Windows %LOCALAPPDATA% and %APPDATA% conventions are
documented under the Microsoft KNOWNFOLDERID reference.

macOS conventions follow Apple's File System Programming Guide.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Application namespace under the platform cache/config/data
# directories. All pydepgate state lives under this single name
# so a user can wipe everything pydepgate-related with a single
# `rm -rf` of the namespace directory, and so different
# subsystems do not collide on common filenames.
_PYDEPGATE_NAMESPACE = "pydepgate"


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _expand_env_path(value: str) -> Path:
    """Expand a path read from an environment variable.

    Handles tilde expansion since users sometimes set XDG
    variables with shell-style home references. os.path.expanduser
    reads $HOME at call time, which is the right behavior for test
    patchability.
    """
    return Path(os.path.expanduser(value))


def _is_darwin() -> bool:
    """Read sys.platform at call time for test patchability.

    Wrapped in a function rather than evaluated at module load so
    `mock.patch("sys.platform", "darwin")` works without having to
    reimport the module.
    """
    return sys.platform == "darwin"


def _is_windows() -> bool:
    """Read sys.platform at call time for test patchability."""
    return sys.platform == "win32"


# ---------------------------------------------------------------------------
# XDG cache home
# ---------------------------------------------------------------------------


def xdg_cache_home() -> Path:
    """Resolve the user cache directory.

    Order of precedence:
      1. $XDG_CACHE_HOME (any platform; XDG always wins when set)
      2. macOS: ~/Library/Caches
      3. Windows: %LOCALAPPDATA% or ~/AppData/Local
      4. POSIX default (Linux, BSD, others): ~/.cache
    """
    explicit = os.environ.get("XDG_CACHE_HOME")
    if explicit:
        return _expand_env_path(explicit)

    if _is_darwin():
        return Path.home() / "Library" / "Caches"

    if _is_windows():
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return _expand_env_path(local_app_data)
        return Path.home() / "AppData" / "Local"

    return Path.home() / ".cache"


# ---------------------------------------------------------------------------
# XDG config home
# ---------------------------------------------------------------------------


def xdg_config_home() -> Path:
    """Resolve the user configuration directory.

    Order of precedence:
      1. $XDG_CONFIG_HOME
      2. macOS: ~/Library/Application Support
      3. Windows: %APPDATA% or ~/AppData/Roaming
      4. POSIX default: ~/.config

    Note: on Windows, %APPDATA% is the roaming-profile location;
    user-specific configuration that should follow a roaming
    Windows account lives here, while cache data (which should
    not roam) goes to %LOCALAPPDATA%.
    """
    explicit = os.environ.get("XDG_CONFIG_HOME")
    if explicit:
        return _expand_env_path(explicit)

    if _is_darwin():
        return Path.home() / "Library" / "Application Support"

    if _is_windows():
        app_data = os.environ.get("APPDATA")
        if app_data:
            return _expand_env_path(app_data)
        return Path.home() / "AppData" / "Roaming"

    return Path.home() / ".config"


# ---------------------------------------------------------------------------
# XDG data home
# ---------------------------------------------------------------------------


def xdg_data_home() -> Path:
    """Resolve the user data directory.

    Order of precedence:
      1. $XDG_DATA_HOME
      2. macOS: ~/Library/Application Support
      3. Windows: %LOCALAPPDATA% or ~/AppData/Local
      4. POSIX default: ~/.local/share

    macOS uses the same Application Support directory as
    xdg_config_home() because Apple's conventions do not
    distinguish "data" from "config" at the directory level.
    Subsystems disambiguate via subdirectories under the
    pydepgate namespace.
    """
    explicit = os.environ.get("XDG_DATA_HOME")
    if explicit:
        return _expand_env_path(explicit)

    if _is_darwin():
        return Path.home() / "Library" / "Application Support"

    if _is_windows():
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return _expand_env_path(local_app_data)
        return Path.home() / "AppData" / "Local"

    return Path.home() / ".local" / "share"


# ---------------------------------------------------------------------------
# pydepgate-namespaced helpers
# ---------------------------------------------------------------------------


def pydepgate_cache_dir() -> Path:
    """Cache directory for pydepgate.

    Equivalent to `xdg_cache_home() / "pydepgate"`. Subsystems
    place their cache subdirectories here:

        pydepgate/cvedb/             CVE database cache
        pydepgate/<future>/

    Does NOT create the directory. Callers that need it to exist
    pass the result through ensure_directory():

        cvedb_dir = ensure_directory(pydepgate_cache_dir() / "cvedb")
    """
    return xdg_cache_home() / _PYDEPGATE_NAMESPACE


def pydepgate_config_dir() -> Path:
    """Configuration directory for pydepgate.

    Equivalent to `xdg_config_home() / "pydepgate"`. Reserved
    for future use; no subsystem currently writes here.

    Does NOT create the directory.
    """
    return xdg_config_home() / _PYDEPGATE_NAMESPACE


def pydepgate_data_dir() -> Path:
    """Persistent data directory for pydepgate.

    Equivalent to `xdg_data_home() / "pydepgate"`. Reserved for
    future use; no subsystem currently writes here.

    Does NOT create the directory.
    """
    return xdg_data_home() / _PYDEPGATE_NAMESPACE


# ---------------------------------------------------------------------------
# Directory creation helper
# ---------------------------------------------------------------------------


def ensure_directory(path: Path) -> Path:
    """Create the directory if it does not exist; return the path.

    Idempotent: existing directories are not touched. Parents are
    created as needed. Returns the path argument unchanged so the
    function composes cleanly:

        db_dir = ensure_directory(pydepgate_cache_dir() / "cvedb")

    Raises OSError (or a subclass like FileExistsError or
    NotADirectoryError) if the path exists but is not a directory,
    or if creation fails for permission or filesystem reasons. The
    caller is responsible for deciding whether to recover from
    such failures.
    """
    path.mkdir(parents=True, exist_ok=True)
    return path
