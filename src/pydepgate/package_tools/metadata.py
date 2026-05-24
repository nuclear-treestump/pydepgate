"""pydepgate.package_tools.metadata

Artifact-level package metadata extraction.

This module reads package identity and provenance-adjacent metadata
from package artifacts without extracting archive members to disk. It
is intentionally small and stdlib-only so future package_tools passes
can share one source of truth for package name, version, artifact
format hints, and warning state.

The first supported artifact type is a wheel. A wheel normally carries
its package identity in the root .dist-info/METADATA file, with build
and tag information in .dist-info/WHEEL. The wheel filename is useful
as a fallback and as a consistency check, but it is not treated as more
authoritative than core metadata.

Important trust boundary:

  A downloaded .whl file usually does not contain trustworthy download
  origin information. Core metadata can identify what the artifact
  claims to be. WHEEL can identify the wheel generator and tags.
  RECORD can describe member hashes inside the wheel. None of those
  prove where the file came from. If direct_url.json is present it is
  parsed and surfaced, but callers should treat it as artifact-declared
  data rather than external provenance.

Public surface:

    normalize_package_name(name) -> str
        PEP 503 style normalization for package-name comparisons.

    parse_wheel_filename(filename) -> WheelFilenameInfo | None
        Parse the distribution, version, optional build tag, and tag
        fields from a wheel filename.

    read_package_metadata(path) -> PackageMetadata
        Dispatch to the artifact-specific metadata reader for a
        supported package artifact.

    read_wheel_metadata(path) -> PackageMetadata
        Read package-level metadata from a wheel safely and return a
        frozen, pickle-safe PackageMetadata object.

    PackageMetadata
        Stable package metadata record for package_tools consumers.

    WheelFilenameInfo, DirectUrlInfo
        Frozen supporting records.
"""

from __future__ import annotations

import json
import posixpath
import re
import sys
import zipfile
from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------------------------------
# Limits and identifiers
# ---------------------------------------------------------------------------

MAX_WHEEL_ARCHIVE_BYTES = 200 * 1024 * 1024
MAX_CORE_METADATA_BYTES = 1 * 1024 * 1024
MAX_WHEEL_METADATA_BYTES = 128 * 1024
MAX_DIRECT_URL_BYTES = 512 * 1024

IDENTITY_SOURCE_CORE_METADATA = "core-metadata"
IDENTITY_SOURCE_WHEEL_FILENAME = "wheel-filename"
IDENTITY_SOURCE_UNRESOLVED = "unresolved"

_ARTIFACT_TYPE_WHEEL = "wheel"
_DIST_INFO_SUFFIX = ".dist-info"
_CORE_METADATA_LEAF = "METADATA"
_WHEEL_METADATA_LEAF = "WHEEL"
_DIRECT_URL_LEAF = "direct_url.json"

_NAME_NORMALIZER = re.compile(r"[-_.]+")
_VALID_WHEEL_TAG = re.compile(r"^[A-Za-z0-9_.]+$")
_VALID_WHEEL_VERSION = re.compile(r"^[0-9][A-Za-z0-9_.!+]*$")


# ---------------------------------------------------------------------------
# Public result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WheelFilenameInfo:
    """Identity and tag fields parsed from a wheel filename.

    Attributes:
        filename: Original basename that was parsed.
        distribution: Distribution component from the filename.
        version: Version component from the filename.
        build_tag: Optional build tag. None when the wheel filename
            does not carry one.
        python_tag: Python tag component, for example "py3" or
            "cp311".
        abi_tag: ABI tag component, for example "none" or
            "cp311".
        platform_tag: Platform tag component, for example "any" or
            "manylinux_2_28_x86_64".
    """

    filename: str
    distribution: str
    version: str
    build_tag: str | None
    python_tag: str
    abi_tag: str
    platform_tag: str


@dataclass(frozen=True)
class DirectUrlInfo:
    """Subset of PEP 610 direct_url.json fields.

    direct_url.json is normally installation metadata, not source
    wheel metadata. If a wheel carries it anyway, pydepgate surfaces
    the declared values for forensic context. Callers must not treat
    these fields as proof that the wheel was downloaded from the
    declared URL.
    """

    url: str | None
    vcs: str | None
    requested_revision: str | None
    commit_id: str | None
    dir_info_editable: bool | None
    archive_hashes: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class PackageMetadata:
    """Package-level metadata for a scanned artifact.

    Attributes:
        artifact_type: Artifact family. Currently "wheel".
        artifact_path: Path supplied by the caller.
        name: Best available package name. Prefer core metadata;
            fall back to the wheel filename only when core metadata
            does not provide a complete identity.
        normalized_name: PEP 503 style normalized package name, or
            None when name is not available.
        version: Best available package version.
        identity_source: Which source supplied the final name and
            version. One of IDENTITY_SOURCE_CORE_METADATA,
            IDENTITY_SOURCE_WHEEL_FILENAME, or IDENTITY_SOURCE_UNRESOLVED.
        metadata_name: Name field read from .dist-info/METADATA.
        metadata_version: Version field read from .dist-info/METADATA.
        filename_name: Distribution component parsed from the wheel
            filename.
        filename_version: Version component parsed from the wheel
            filename.
        dist_info_dir: Selected root .dist-info directory, if one
            could be selected safely.
        metadata_path: Selected METADATA member path, if any.
        wheel_metadata_path: Selected WHEEL member path, if any.
        wheel_version: Wheel-Version value from WHEEL.
        wheel_generator: Generator value from WHEEL.
        root_is_purelib: Root-Is-Purelib parsed as a bool when present.
        wheel_tags: Tag values from WHEEL.
        requires_python: Requires-Python value from core metadata.
        requires_dist: Requires-Dist values from core metadata.
        provides_extra: Provides-Extra values from core metadata.
        project_urls: Project-URL values from core metadata.
        summary: Summary value from core metadata.
        direct_url: Parsed direct_url.json subset, if present.
        warnings: Non-fatal extraction warnings. Warnings are part of
            the record so downstream package tools can decide whether
            to fail closed, degrade, or show diagnostics.
    """

    artifact_type: str
    artifact_path: Path
    artifact_filename: str
    name: str | None
    normalized_name: str | None
    version: str | None
    identity_source: str
    metadata_name: str | None
    metadata_version: str | None
    filename_name: str | None
    filename_version: str | None
    dist_info_dir: str | None
    metadata_path: str | None
    wheel_metadata_path: str | None
    wheel_version: str | None
    wheel_generator: str | None
    root_is_purelib: bool | None
    wheel_tags: tuple[str, ...]
    requires_python: str | None
    requires_dist: tuple[str, ...]
    provides_extra: tuple[str, ...]
    project_urls: tuple[str, ...]
    summary: str | None
    direct_url: DirectUrlInfo | None
    warnings: tuple[str, ...]

    @property
    def has_identity(self) -> bool:
        """Return True when both package name and version are available."""
        return self.name is not None and self.version is not None

    @property
    def identity_key(self) -> tuple[str, str] | None:
        """Return the normalized (name, version) key, if available.

        The normalized name is suitable for cache keys and package-name
        comparisons. The version is preserved exactly as declared.
        """
        if self.normalized_name is None or self.version is None:
            return None
        return self.normalized_name, self.version

    @property
    def candidate_lookup_keys(self) -> tuple[tuple[str, str], ...]:
        """Return candidate (name, version) keys for package lookups.

        The first key uses the artifact's declared name. The second key
        uses the normalized name when it differs. This lets consumers
        query data stores that may have chosen either representation
        without repeating normalization logic.
        """
        if self.name is None or self.version is None:
            return ()
        keys: list[tuple[str, str]] = [(self.name, self.version)]
        if self.normalized_name and self.normalized_name != self.name:
            keys.append((self.normalized_name, self.version))
        return tuple(keys)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def normalize_package_name(name: str) -> str:
    """Return a PEP 503 style normalized package name.

    Runs of hyphen, underscore, and dot are collapsed to a single
    hyphen, and the result is lowercased. Leading and trailing
    whitespace is stripped before normalization.
    """
    return _NAME_NORMALIZER.sub("-", name.strip()).lower()


def parse_wheel_filename(filename: str) -> WheelFilenameInfo | None:
    """Parse a wheel filename into identity and tag components.

    Returns None when the basename is not shaped like a wheel
    filename. The parser is deliberately conservative: it accepts the
    two standard component counts, with or without a build tag, and
    refuses empty components, unexpected separators, non-numeric
    version starts, and build tags that do not start with a digit.
    """
    base = Path(filename).name
    if not base.endswith(".whl"):
        return None

    stem = base[:-4]
    parts = stem.split("-")
    if len(parts) == 5:
        distribution, version, python_tag, abi_tag, platform_tag = parts
        build_tag = None
    elif len(parts) == 6:
        distribution, version, build_tag, python_tag, abi_tag, platform_tag = parts
    else:
        return None

    values = (distribution, version, python_tag, abi_tag, platform_tag)
    if build_tag is not None:
        values = values + (build_tag,)
    if any(not value for value in values):
        return None
    if not _VALID_WHEEL_VERSION.match(version):
        return None
    if build_tag is not None and not build_tag[0].isdigit():
        return None
    if not all(
        _VALID_WHEEL_TAG.match(value)
        for value in (distribution, python_tag, abi_tag, platform_tag)
    ):
        return None

    return WheelFilenameInfo(
        filename=base,
        distribution=distribution,
        version=version,
        build_tag=build_tag,
        python_tag=python_tag,
        abi_tag=abi_tag,
        platform_tag=platform_tag,
    )


def read_package_metadata(path: Path) -> PackageMetadata:
    """Read package metadata from a supported package artifact.

    Currently dispatches only to read_wheel_metadata. Keeping this
    small public entry point in the metadata module gives future
    artifact readers, such as sdists, a natural place to plug in
    without making callers know every artifact-specific function.

    Raises:
        ValueError: if the artifact type is not supported.
    """
    artifact_path = Path(path)
    if artifact_path.suffix == ".whl":
        return read_wheel_metadata(artifact_path)
    raise ValueError(f"unsupported package artifact type: {artifact_path}")


def read_wheel_metadata(path: Path) -> PackageMetadata:
    """Read package metadata from a wheel artifact.

    The function reads only root .dist-info metadata members. It does
    not extract archive contents to disk, does not follow paths, and
    refuses oversized metadata members. Non-fatal ambiguity and parse
    issues are returned in PackageMetadata.warnings.

    Raises:
        zipfile.BadZipFile: if the file is not a valid zip archive.
        OSError: if the file cannot be read.
        ValueError: if the wheel archive exceeds MAX_WHEEL_ARCHIVE_BYTES.
    """
    wheel_path = Path(path)
    warnings: list[str] = []

    archive_size = wheel_path.stat().st_size
    if archive_size > MAX_WHEEL_ARCHIVE_BYTES:
        raise ValueError(
            f"wheel {wheel_path} is {archive_size} bytes; exceeds "
            f"metadata safety limit of {MAX_WHEEL_ARCHIVE_BYTES}"
        )

    filename_info = parse_wheel_filename(wheel_path.name)
    if filename_info is None:
        warnings.append(f"wheel filename {wheel_path.name!r} could not be parsed")

    metadata_name: str | None = None
    metadata_version: str | None = None
    metadata_path: str | None = None
    dist_info_dir: str | None = None
    summary: str | None = None
    requires_python: str | None = None
    requires_dist: tuple[str, ...] = ()
    provides_extra: tuple[str, ...] = ()
    project_urls: tuple[str, ...] = ()

    wheel_metadata_path: str | None = None
    wheel_version: str | None = None
    wheel_generator: str | None = None
    root_is_purelib: bool | None = None
    wheel_tags: tuple[str, ...] = ()
    direct_url: DirectUrlInfo | None = None

    with zipfile.ZipFile(wheel_path, "r") as zf:
        infos = [info for info in zf.infolist() if not info.is_dir()]
        metadata_infos = _find_root_dist_info_members(
            infos,
            _CORE_METADATA_LEAF,
            warnings,
        )
        selected_metadata = _select_dist_info_member(
            metadata_infos,
            filename_info,
            warnings,
            _CORE_METADATA_LEAF,
        )

        if selected_metadata is not None:
            metadata_path = _normalize_zip_name(selected_metadata.filename)
            dist_info_dir = metadata_path.split("/", 1)[0]
            data = _read_limited_member(
                zf,
                selected_metadata,
                MAX_CORE_METADATA_BYTES,
                warnings,
                "core metadata",
            )
            if data is not None:
                core = _parse_metadata_message(data, warnings, metadata_path)
                metadata_name = _first_header(core, "Name", warnings)
                metadata_version = _first_header(core, "Version", warnings)
                summary = _first_header(core, "Summary", warnings)
                requires_python = _first_header(
                    core,
                    "Requires-Python",
                    warnings,
                )
                requires_dist = _all_headers(core, "Requires-Dist", warnings)
                provides_extra = _all_headers(core, "Provides-Extra", warnings)
                project_urls = _all_headers(core, "Project-URL", warnings)

        wheel_info = _select_related_member(
            infos,
            dist_info_dir,
            filename_info,
            _WHEEL_METADATA_LEAF,
            warnings,
        )
        if wheel_info is not None:
            wheel_metadata_path = _normalize_zip_name(wheel_info.filename)
            data = _read_limited_member(
                zf,
                wheel_info,
                MAX_WHEEL_METADATA_BYTES,
                warnings,
                "wheel metadata",
            )
            if data is not None:
                wheel_msg = _parse_metadata_message(
                    data,
                    warnings,
                    wheel_metadata_path,
                )
                wheel_version = _first_header(
                    wheel_msg,
                    "Wheel-Version",
                    warnings,
                )
                wheel_generator = _first_header(
                    wheel_msg,
                    "Generator",
                    warnings,
                )
                root_is_purelib = _parse_bool_header(
                    _first_header(wheel_msg, "Root-Is-Purelib", warnings),
                    warnings,
                    "Root-Is-Purelib",
                )
                wheel_tags = _all_headers(wheel_msg, "Tag", warnings)

        direct_info = _select_related_member(
            infos,
            dist_info_dir,
            filename_info,
            _DIRECT_URL_LEAF,
            warnings,
        )
        if direct_info is not None:
            data = _read_limited_member(
                zf,
                direct_info,
                MAX_DIRECT_URL_BYTES,
                warnings,
                "direct_url metadata",
            )
            if data is not None:
                direct_url = _parse_direct_url(data, warnings)

    filename_name = filename_info.distribution if filename_info else None
    filename_version = filename_info.version if filename_info else None

    if metadata_name and filename_name:
        if normalize_package_name(metadata_name) != normalize_package_name(
            filename_name,
        ):
            warnings.append(
                "core metadata name does not match wheel filename name: "
                f"{metadata_name!r} != {filename_name!r}"
            )
    if metadata_version and filename_version:
        if metadata_version != filename_version:
            warnings.append(
                "core metadata version does not match wheel filename "
                f"version: {metadata_version!r} != {filename_version!r}"
            )

    name, version, source = _resolve_identity(
        metadata_name,
        metadata_version,
        filename_name,
        filename_version,
        warnings,
    )
    normalized_name = normalize_package_name(name) if name else None

    p_data = PackageMetadata(
        artifact_type=_ARTIFACT_TYPE_WHEEL,
        artifact_path=wheel_path,
        artifact_filename=wheel_path.name,
        name=name,
        normalized_name=normalized_name,
        version=version,
        identity_source=source,
        metadata_name=metadata_name,
        metadata_version=metadata_version,
        filename_name=filename_name,
        filename_version=filename_version,
        dist_info_dir=dist_info_dir,
        metadata_path=metadata_path,
        wheel_metadata_path=wheel_metadata_path,
        wheel_version=wheel_version,
        wheel_generator=wheel_generator,
        root_is_purelib=root_is_purelib,
        wheel_tags=wheel_tags,
        requires_python=requires_python,
        requires_dist=requires_dist,
        provides_extra=provides_extra,
        project_urls=project_urls,
        summary=summary,
        direct_url=direct_url,
        warnings=tuple(warnings),
    )

    return p_data


# ---------------------------------------------------------------------------
# Archive member selection
# ---------------------------------------------------------------------------


def _is_safe_zip_path(name: str) -> bool:
    """Return True if a zip member name is safe to inspect."""
    if not name:
        return False
    if name.startswith("/") or name.startswith("\\"):
        return False
    if "\\" in name:
        return False
    normalized = posixpath.normpath(name)
    if normalized in {".", ".."}:
        return False
    if normalized.startswith("../"):
        return False
    if "/../" in normalized or normalized.endswith("/.."):
        return False
    return True


def _normalize_zip_name(name: str) -> str:
    """Normalize a safe zip member name to forward-slash form."""
    return posixpath.normpath(name).replace("\\", "/")


def _root_dist_info_leaf(name: str) -> tuple[str, str] | None:
    """Return (dist_info_dir, leaf) for root .dist-info members."""
    if not _is_safe_zip_path(name):
        return None
    normalized = _normalize_zip_name(name)
    parts = normalized.split("/")
    if len(parts) != 2:
        return None
    dist_info_dir, leaf = parts
    if not dist_info_dir.endswith(_DIST_INFO_SUFFIX):
        return None
    if not leaf:
        return None
    return dist_info_dir, leaf


def _find_root_dist_info_members(
    infos: Iterable[zipfile.ZipInfo],
    leaf: str,
    warnings: list[str],
) -> list[zipfile.ZipInfo]:
    """Find safe root .dist-info members with the requested leaf name."""
    found: list[zipfile.ZipInfo] = []
    unsafe_seen = 0
    for info in infos:
        parsed = _root_dist_info_leaf(info.filename)
        if parsed is None:
            if info.filename.endswith("/" + leaf) or info.filename.endswith(leaf):
                unsafe_seen += 1
            continue
        _, entry_leaf = parsed
        if entry_leaf == leaf:
            found.append(info)
    if unsafe_seen:
        warnings.append(f"ignored {unsafe_seen} unsafe or non-root {leaf} candidate(s)")
    return found


def _select_dist_info_member(
    infos: list[zipfile.ZipInfo],
    filename_info: WheelFilenameInfo | None,
    warnings: list[str],
    leaf: str,
) -> zipfile.ZipInfo | None:
    """Select a unique dist-info metadata member, if possible."""
    if not infos:
        warnings.append(f"no root .dist-info/{leaf} member found")
        return None
    if len(infos) == 1:
        return infos[0]

    warnings.append(f"multiple root .dist-info/{leaf} members found")
    if filename_info is None:
        warnings.append(
            f"cannot choose {leaf} member without a parseable wheel filename"
        )
        return None

    matches = [
        info
        for info in infos
        if _dist_info_matches_filename(info.filename, filename_info)
    ]
    if len(matches) == 1:
        warnings.append(f"selected {leaf} member matching the wheel filename")
        return matches[0]
    if len(matches) > 1:
        warnings.append(f"multiple {leaf} members match the wheel filename")
    else:
        warnings.append(f"no {leaf} member matches the wheel filename")
    return None


def _select_related_member(
    infos: list[zipfile.ZipInfo],
    dist_info_dir: str | None,
    filename_info: WheelFilenameInfo | None,
    leaf: str,
    warnings: list[str],
) -> zipfile.ZipInfo | None:
    """Select WHEEL or direct_url.json beside the selected METADATA."""
    candidates = _find_root_dist_info_members(infos, leaf, warnings)
    if not candidates:
        return None

    if dist_info_dir is not None:
        matching_dir = [
            info
            for info in candidates
            if _root_dist_info_leaf(info.filename)
            and _root_dist_info_leaf(info.filename)[0] == dist_info_dir
        ]
        if len(matching_dir) == 1:
            return matching_dir[0]
        if len(matching_dir) > 1:
            warnings.append(f"multiple {leaf} members found in selected dist-info dir")
            return None

    return _select_dist_info_member(candidates, filename_info, warnings, leaf)


def _dist_info_matches_filename(
    member_name: str,
    filename_info: WheelFilenameInfo,
) -> bool:
    """Return True when a dist-info directory matches the filename."""
    parsed = _root_dist_info_leaf(member_name)
    if parsed is None:
        return False
    dist_info_dir, _ = parsed
    parsed_dir = _parse_dist_info_dir(dist_info_dir)
    if parsed_dir is None:
        return False
    name, version = parsed_dir
    return (
        normalize_package_name(name)
        == normalize_package_name(filename_info.distribution)
        and version == filename_info.version
    )


def _parse_dist_info_dir(dist_info_dir: str) -> tuple[str, str] | None:
    """Parse distribution and version from a .dist-info directory."""
    if not dist_info_dir.endswith(_DIST_INFO_SUFFIX):
        return None
    stem = dist_info_dir[: -len(_DIST_INFO_SUFFIX)]
    if "-" not in stem:
        return None
    name, version = stem.rsplit("-", 1)
    if not name or not version:
        return None
    return name, version


def _read_limited_member(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    max_bytes: int,
    warnings: list[str],
    description: str,
) -> bytes | None:
    """Read a zip member after checking its declared size."""
    if info.file_size > max_bytes:
        warnings.append(
            f"ignored {description} member {info.filename!r}: "
            f"declared size {info.file_size} exceeds limit {max_bytes}"
        )
        return None
    try:
        data = zf.read(info.filename)
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        warnings.append(f"failed to read {description} member {info.filename!r}: {exc}")
        return None
    if len(data) > max_bytes:
        warnings.append(
            f"ignored {description} member {info.filename!r}: "
            f"read size {len(data)} exceeds limit {max_bytes}"
        )
        return None
    return data


# ---------------------------------------------------------------------------
# Metadata parsing
# ---------------------------------------------------------------------------


def _parse_metadata_message(
    data: bytes,
    warnings: list[str],
    source_path: str,
) -> Message:
    """Parse RFC 822 style package metadata bytes."""
    try:
        return BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:
        warnings.append(f"failed to parse metadata member {source_path!r}: {exc}")
        return Message()


def _clean_header_value(value: object, field: str, warnings: list[str]) -> str | None:
    """Return a clean one-line header value, or None if unusable."""
    text = str(value).strip()
    if not text:
        return None
    if any(ord(ch) < 32 and ch not in "\t" for ch in text):
        warnings.append(f"ignored {field} header containing control characters")
        return None
    return text


def _first_header(msg: Message, field: str, warnings: list[str]) -> str | None:
    """Return the first usable value for a metadata header."""
    values = msg.get_all(field, [])
    if not values:
        return None
    if len(values) > 1:
        warnings.append(f"metadata header {field!r} appears more than once")
    return _clean_header_value(values[0], field, warnings)


def _all_headers(msg: Message, field: str, warnings: list[str]) -> tuple[str, ...]:
    """Return all usable values for a repeatable metadata header."""
    cleaned: list[str] = []
    for value in msg.get_all(field, []):
        text = _clean_header_value(value, field, warnings)
        if text is not None:
            cleaned.append(text)
    return tuple(cleaned)


def _parse_bool_header(
    value: str | None,
    warnings: list[str],
    field: str,
) -> bool | None:
    """Parse a metadata boolean field."""
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    warnings.append(f"metadata header {field!r} is not a boolean: {value!r}")
    return None


def _parse_direct_url(data: bytes, warnings: list[str]) -> DirectUrlInfo | None:
    """Parse a small, useful subset of direct_url.json."""
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        warnings.append(f"failed to parse direct_url.json: {exc}")
        return None
    if not isinstance(raw, dict):
        warnings.append("ignored direct_url.json: top-level JSON is not an object")
        return None

    url = _json_string(raw.get("url"))
    archive_info = raw.get("archive_info")
    vcs_info = raw.get("vcs_info")
    dir_info = raw.get("dir_info")

    archive_hashes: tuple[tuple[str, str], ...] = ()
    if isinstance(archive_info, dict):
        hashes = archive_info.get("hashes")
        if isinstance(hashes, dict):
            archive_hashes = tuple(
                sorted(
                    (str(name), str(value))
                    for name, value in hashes.items()
                    if isinstance(name, str) and isinstance(value, str)
                )
            )
        else:
            legacy_hash = _json_string(archive_info.get("hash"))
            if legacy_hash:
                archive_hashes = (("hash", legacy_hash),)

    vcs = None
    requested_revision = None
    commit_id = None
    if isinstance(vcs_info, dict):
        vcs = _json_string(vcs_info.get("vcs"))
        requested_revision = _json_string(vcs_info.get("requested_revision"))
        commit_id = _json_string(vcs_info.get("commit_id"))

    dir_info_editable = None
    if isinstance(dir_info, dict):
        editable = dir_info.get("editable")
        if isinstance(editable, bool):
            dir_info_editable = editable

    return DirectUrlInfo(
        url=url,
        vcs=vcs,
        requested_revision=requested_revision,
        commit_id=commit_id,
        dir_info_editable=dir_info_editable,
        archive_hashes=archive_hashes,
    )


def _json_string(value: object) -> str | None:
    """Return a non-empty string JSON field, or None."""
    if isinstance(value, str) and value:
        return value
    return None


def _resolve_identity(
    metadata_name: str | None,
    metadata_version: str | None,
    filename_name: str | None,
    filename_version: str | None,
    warnings: list[str],
) -> tuple[str | None, str | None, str]:
    """Resolve the final package identity from metadata and filename."""
    if metadata_name and metadata_version:
        return metadata_name, metadata_version, IDENTITY_SOURCE_CORE_METADATA

    if metadata_name or metadata_version:
        warnings.append(
            "core metadata identity is incomplete; falling back to wheel "
            "filename if possible"
        )

    if filename_name and filename_version:
        return filename_name, filename_version, IDENTITY_SOURCE_WHEEL_FILENAME

    warnings.append("package identity could not be resolved")
    return None, None, IDENTITY_SOURCE_UNRESOLVED
