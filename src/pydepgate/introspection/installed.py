"""pydepgate.introspection.installed

Read files from installed Python packages.

Uses importlib.metadata to locate packages by name and enumerate
their installed files. Falls back to filesystem walking when
metadata is incomplete.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class InstalledFile:
    """A file belonging to an installed package."""
    internal_path: str       # relative to the package's install root
    absolute_path: Path      # actual location on disk
    content: bytes


@dataclass(frozen=True)
class InstalledPackageNotFound(Exception):
    """Raised when a package is not installed in the current environment."""
    package_name: str

    def __str__(self) -> str:
        return f"package not installed: {self.package_name}"


MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024


def find_package(name: str):
    """Return the Distribution for an installed package, or raise."""
    try:
        return distribution(name)
    except PackageNotFoundError:
        raise InstalledPackageNotFound(package_name=name) from None


def iter_installed_package_files(name: str) -> Iterator[InstalledFile]:
    """Yield files belonging to the named installed package.

    internal_path is relative to the package's install location,
    matching what a wheel unpacker would produce for the same package.
    This means findings from scan_installed are directly comparable
    to findings from scan_wheel on the same package.

    Raises:
        InstalledPackageNotFound: if the package is not installed.
    """
    dist = find_package(name)

    # dist.files can return None if RECORD is missing. In that case,
    # fall back to walking the install directory.
    files = dist.files
    if files is None:
        yield from _iter_by_walking(dist)
        return

    for relative in files:
        # relative is a PackagePath (a PurePosixPath-like object)
        # pointing at a file relative to the package's scheme base.
        try:
            absolute = dist.locate_file(relative)
        except Exception:
            continue

        absolute_path = Path(str(absolute))
        if not absolute_path.is_file():
            continue

        try:
            size = absolute_path.stat().st_size
        except OSError:
            continue

        if size > MAX_FILE_SIZE_BYTES:
            continue

        try:
            content = absolute_path.read_bytes()
        except OSError:
            continue

        # Normalize internal path to forward slashes.
        internal_path = str(relative).replace("\\", "/")

        yield InstalledFile(
            internal_path=internal_path,
            absolute_path=absolute_path,
            content=content,
        )


def _iter_by_walking(dist) -> Iterator[InstalledFile]:
    """Fallback: walk the package's install directory.

    Used when dist.files is None (no RECORD file). Less precise than
    the RECORD-based enumeration because it can't distinguish files
    the package installed from files that happen to be in the same
    directory, but better than nothing.
    """
    # Best-effort guess at the install root: the directory containing
    # the dist-info/egg-info.
    try:
        metadata_path = Path(str(dist._path))  # type: ignore[attr-defined]
    except Exception:
        return

    install_root = metadata_path.parent
    if not install_root.is_dir():
        return

    # Find the package directory by name. Distribution.name gives us
    # the canonical name; we use a case-insensitive match.
    package_name = dist.metadata["Name"].replace("-", "_").lower()
    for child in install_root.iterdir():
        if child.name.lower() == package_name and child.is_dir():
            package_dir = child
            break
    else:
        return

    for file_path in package_dir.rglob("*"):
        if not file_path.is_file():
            continue
        try:
            size = file_path.stat().st_size
        except OSError:
            continue
        if size > MAX_FILE_SIZE_BYTES:
            continue
        try:
            content = file_path.read_bytes()
        except OSError:
            continue

        internal_path = str(file_path.relative_to(install_root)).replace("\\", "/")
        yield InstalledFile(
            internal_path=internal_path,
            absolute_path=file_path,
            content=content,
        )