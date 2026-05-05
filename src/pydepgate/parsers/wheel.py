"""pydepgate.parsers.wheel

Safe wheel file enumeration.

A wheel is a zip archive with a specific layout. This module reads
file contents out of a wheel without extracting to disk, and without
trusting the archive's entry names or sizes.

Yields (internal_path, content_bytes) tuples for each entry in the
archive that passes safety checks. Entries that fail safety checks
are silently skipped; callers that want to know about skipped entries
should use iter_wheel_files_with_diagnostics.
"""

from __future__ import annotations

import posixpath
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


# Safety limits. Values chosen to be larger than any legitimate wheel
# but small enough to prevent resource exhaustion from adversarial inputs.
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024       # 10 MB per file
MAX_ARCHIVE_SIZE_BYTES = 200 * 1024 * 1024   # 200 MB total


@dataclass(frozen=True)
class WheelEntry:
    """A single file read from a wheel."""
    internal_path: str
    content: bytes


@dataclass(frozen=True)
class SkippedEntry:
    """An entry in the wheel that was not read, with the reason why."""
    raw_name: str
    reason: str


def _is_safe_path(name: str) -> bool:
    """Return True if a zip entry name is safe to treat as a relative path.

    Rejects absolute paths, paths containing '..' components, and paths
    with backslashes (which would be interpreted as directories on some
    systems but not others).
    """
    if not name:
        return False
    if name.startswith("/") or name.startswith("\\"):
        return False
    if "\\" in name:
        return False
    # Normalize and check no component is '..'
    normalized = posixpath.normpath(name)
    if normalized.startswith("..") or normalized == "..":
        return False
    if "/../" in normalized or normalized.endswith("/.."):
        return False
    return True


def iter_wheel_files(path: Path) -> Iterator[WheelEntry]:
    """Yield (internal_path, content) for each safe entry in a wheel.

    Unsafe entries (path traversal, oversized, symlinks) are silently
    skipped. For diagnostic information about skipped entries, use
    iter_wheel_files_with_diagnostics.

    Raises:
        zipfile.BadZipFile: if the file is not a valid zip archive.
        OSError: if the file cannot be read.
    """
    for entry, _ in iter_wheel_files_with_diagnostics(path):
        if isinstance(entry, WheelEntry):
            yield entry


def iter_wheel_files_with_diagnostics(
    path: Path,
) -> Iterator[tuple[WheelEntry | SkippedEntry, None]]:
    """Yield (entry_or_skipped, None) for each entry in the wheel.

    The second tuple slot is reserved for future extension (e.g. per-entry
    metadata). Currently always None.

    Raises:
        zipfile.BadZipFile: if the file is not a valid zip archive.
        OSError: if the file cannot be read.
        ValueError: if the archive exceeds MAX_ARCHIVE_SIZE_BYTES.
    """
    archive_size = path.stat().st_size
    if archive_size > MAX_ARCHIVE_SIZE_BYTES:
        raise ValueError(
            f"wheel {path} is {archive_size} bytes; exceeds safety limit "
            f"of {MAX_ARCHIVE_SIZE_BYTES}"
        )

    with zipfile.ZipFile(path, "r") as zf:
        for info in zf.infolist():
            # Skip directory entries.
            if info.is_dir():
                continue

            # Reject unsafe paths before reading any content.
            if not _is_safe_path(info.filename):
                yield SkippedEntry(
                    raw_name=info.filename,
                    reason="unsafe path (traversal attempt or absolute path)",
                ), None
                continue

            # Reject oversized entries.
            if info.file_size > MAX_FILE_SIZE_BYTES:
                yield SkippedEntry(
                    raw_name=info.filename,
                    reason=(
                        f"file size {info.file_size} exceeds safety limit "
                        f"of {MAX_FILE_SIZE_BYTES}"
                    ),
                ), None
                continue

            # Detect symlinks via external_attr (Unix mode bits in upper 16).
            # A symlink has mode bits with S_IFLNK (0o120000) set.
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                yield SkippedEntry(
                    raw_name=info.filename,
                    reason="symlink entry",
                ), None
                continue

            try:
                content = zf.read(info.filename)
            except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
                yield SkippedEntry(
                    raw_name=info.filename,
                    reason=f"read failed: {exc}",
                ), None
                continue

            # Normalize the path to forward slashes for consistency with
            # triage. ZipFile already uses forward slashes but we
            # normalize defensively.
            normalized_path = info.filename.replace("\\", "/")

            yield WheelEntry(
                internal_path=normalized_path,
                content=content,
            ), None


def is_wheel(path: Path) -> bool:
    """Quick check: does this look like a wheel?

    Returns True if the path exists, ends in .whl, and appears to be a
    zip archive. Does not validate the wheel's internal structure.
    """
    if not path.suffix == ".whl":
        return False
    if not path.is_file():
        return False
    try:
        with zipfile.ZipFile(path, "r") as zf:
            zf.testzip()  # Returns first bad file, or None if all good.
        return True
    except zipfile.BadZipFile:
        return False