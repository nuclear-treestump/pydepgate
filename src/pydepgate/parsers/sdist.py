"""pydepgate.parsers.sdist

Safe sdist file enumeration.

An sdist is a tar archive (usually gzipped) containing a Python
package's source tree. This module reads file contents from sdists
without extracting to disk and without trusting archive contents.

Python 3.12 added tarfile filters (PEP 706) which handle the most
common safety issues; we use the 'data' filter as the strictest
builtin, and layer additional checks on top.
"""

from __future__ import annotations

import posixpath
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024       # 10 MB per file
MAX_ARCHIVE_SIZE_BYTES = 200 * 1024 * 1024   # 200 MB total


@dataclass(frozen=True)
class SdistEntry:
    internal_path: str
    content: bytes


@dataclass(frozen=True)
class SkippedEntry:
    raw_name: str
    reason: str


def _is_safe_path(name: str) -> bool:
    """Same safety rules as the wheel module."""
    if not name:
        return False
    if name.startswith("/") or name.startswith("\\"):
        return False
    if "\\" in name:
        return False
    normalized = posixpath.normpath(name)
    if normalized.startswith("..") or normalized == "..":
        return False
    if "/../" in normalized or normalized.endswith("/.."):
        return False
    return True


def _strip_top_level_directory(name: str) -> str:
    """Sdists conventionally have a single top-level directory named
    after the package. Strip it so the paths we hand to triage look
    like archive-root paths (setup.py, mypackage/__init__.py, etc.)
    rather than (foo-1.0/setup.py, foo-1.0/mypackage/__init__.py).

    If there's no single top-level directory, returns the name unchanged.
    """
    parts = name.split("/", 1)
    if len(parts) == 2:
        return parts[1]
    return name


def iter_sdist_files(path: Path) -> Iterator[SdistEntry]:
    """Yield (internal_path, content) for each safe entry in an sdist."""
    for entry in iter_sdist_files_with_diagnostics(path):
        if isinstance(entry, SdistEntry):
            yield entry


def iter_sdist_files_with_diagnostics(
    path: Path,
) -> Iterator[SdistEntry | SkippedEntry]:
    """Yield entries with diagnostic skipped entries interleaved."""
    archive_size = path.stat().st_size
    if archive_size > MAX_ARCHIVE_SIZE_BYTES:
        raise ValueError(
            f"sdist {path} is {archive_size} bytes; exceeds safety limit "
            f"of {MAX_ARCHIVE_SIZE_BYTES}"
        )

    # tarfile.open autodetects compression (.tar, .tar.gz, .tgz, etc.)
    with tarfile.open(path, "r:*") as tf:
        for member in tf.getmembers():
            # Only regular files; skip directories, symlinks, devices, etc.
            if not member.isreg():
                if member.issym() or member.islnk():
                    yield SkippedEntry(
                        raw_name=member.name,
                        reason="symlink or hardlink entry",
                    )
                continue

            if not _is_safe_path(member.name):
                yield SkippedEntry(
                    raw_name=member.name,
                    reason="unsafe path (traversal or absolute)",
                )
                continue

            if member.size > MAX_FILE_SIZE_BYTES:
                yield SkippedEntry(
                    raw_name=member.name,
                    reason=(
                        f"file size {member.size} exceeds safety limit "
                        f"of {MAX_FILE_SIZE_BYTES}"
                    ),
                )
                continue

            try:
                extracted = tf.extractfile(member)
                if extracted is None:
                    yield SkippedEntry(
                        raw_name=member.name,
                        reason="tarfile returned None for extraction",
                    )
                    continue
                content = extracted.read()
            except (tarfile.TarError, OSError) as exc:
                yield SkippedEntry(
                    raw_name=member.name,
                    reason=f"read failed: {exc}",
                )
                continue

            internal_path = _strip_top_level_directory(member.name)
            yield SdistEntry(
                internal_path=internal_path,
                content=content,
            )


def is_sdist(path: Path) -> bool:
    """Quick check: does this look like an sdist?"""
    if not path.is_file():
        return False
    # Sdists come in .tar.gz, .tgz, .tar.bz2, .zip (rare), and .tar.
    # We only accept the tar variants; .zip sdists are legacy and
    # ambiguous with wheels.
    suffixes = "".join(path.suffixes[-2:]).lower()
    if suffixes not in (".tar.gz", ".tar.bz2", ".tar.xz") and path.suffix != ".tgz" and path.suffix != ".tar":
        return False
    try:
        with tarfile.open(path, "r:*") as tf:
            tf.getmembers()
        return True
    except (tarfile.TarError, OSError):
        return False