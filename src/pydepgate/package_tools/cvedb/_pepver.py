"""pydepgate.package_tools.cvedb._pepver

Small PEP 440 version parser and comparator for cvedb range checks.

This module is private to the cvedb package. It exists because cvedb
range matching needs Python package version ordering, but pydepgate does
not take runtime dependencies. The implementation is intentionally
conservative: versions that cannot be parsed return None from parse and
comparison helpers rather than falling back to string ordering.

Supported version forms include epochs, release segments, pre-releases,
post releases, development releases, local versions, and common PEP 440
spellings such as alpha/beta/c/pre/preview/rev/r aliases. The comparator
uses PEP 440 ordering for parsed versions and treats release trailing
zero segments as insignificant for comparison.

Public surface:

    parse_version(value) -> Pep440Version | None
        Parse a PEP 440 version string into an immutable record.

    canonicalize_version(value) -> str | None
        Return a normalized spelling for a parseable version.

    compare_versions(left, right) -> int | None
        Return -1, 0, or 1 for parseable versions. Return None if either
        side is not parseable.

    version_in_range(version, introduced='', fixed='', last_affected='')
        Evaluate one OSV-style range row. introduced is inclusive,
        fixed is exclusive, and last_affected is inclusive. Return None
        when the comparison cannot be evaluated safely.

This is not a public packaging library. Keep the API narrow so the CVE
lookup layer can depend on it without making it part of pydepgate's
external contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PRE_NORMALIZATION: Final[dict[str, str]] = {
    "a": "a",
    "alpha": "a",
    "b": "b",
    "beta": "b",
    "c": "rc",
    "rc": "rc",
    "pre": "rc",
    "preview": "rc",
}

_PRE_ORDER: Final[dict[str, int]] = {
    "a": 0,
    "b": 1,
    "rc": 2,
}

_POST_NORMALIZATION: Final[set[str]] = {"post", "rev", "r"}

_VERSION_RE: Final[re.Pattern[str]] = re.compile(
    r"""
    ^\s*
    v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:
        [._-]?
        (?P<pre_label>a|b|c|rc|alpha|beta|pre|preview)
        [._-]?
        (?P<pre_number>[0-9]+)?
    )?
    (?:
        -(?P<implicit_post_number>[0-9]+)
        |
        (?:
            [._-]?
            (?P<post_label>post|rev|r)
            [._-]?
            (?P<post_number>[0-9]+)?
        )
    )?
    (?:
        [._-]?
        (?P<dev_label>dev)
        [._-]?
        (?P<dev_number>[0-9]+)?
    )?
    (?:\+(?P<local>[a-z0-9]+(?:[._-][a-z0-9]+)*))?
    \s*$
    """,
    re.IGNORECASE | re.VERBOSE,
)

_LOCAL_SPLIT_RE: Final[re.Pattern[str]] = re.compile(r"[._-]")


# ---------------------------------------------------------------------------
# Sentinel objects used by the sort key
# ---------------------------------------------------------------------------


class _NegativeInfinity:
    """Sort before every non-negative-infinity value."""

    def __lt__(self, other: object) -> bool:
        return not isinstance(other, _NegativeInfinity)

    def __le__(self, other: object) -> bool:
        return True

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _NegativeInfinity)

    def __gt__(self, other: object) -> bool:
        return False

    def __ge__(self, other: object) -> bool:
        return isinstance(other, _NegativeInfinity)

    def __repr__(self) -> str:
        return "-Infinity"


class _Infinity:
    """Sort after every non-infinity value."""

    def __lt__(self, other: object) -> bool:
        return False

    def __le__(self, other: object) -> bool:
        return isinstance(other, _Infinity)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Infinity)

    def __gt__(self, other: object) -> bool:
        return not isinstance(other, _Infinity)

    def __ge__(self, other: object) -> bool:
        return True

    def __repr__(self) -> str:
        return "Infinity"


_NEG_INF: Final = _NegativeInfinity()
_INF: Final = _Infinity()


# ---------------------------------------------------------------------------
# Result records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Pep440Version:
    """Parsed PEP 440 version data.

    Attributes:
        original: Original input string stripped of surrounding
            whitespace. It is retained for diagnostics and tests only.
        epoch: Numeric epoch. Missing epochs normalize to zero.
        release: Release segment as integers. Each component has leading
            zeroes removed by integer conversion.
        pre: Normalized pre-release pair, such as ("a", 1), ("b", 2),
            or ("rc", 1). None means no pre-release segment.
        post: Post-release number, or None when absent.
        dev: Development-release number, or None when absent.
        local: Local-version segments. Numeric segments are stored as
            integers. Text segments are lower-case strings.
    """

    original: str
    epoch: int
    release: tuple[int, ...]
    pre: tuple[str, int] | None
    post: int | None
    dev: int | None
    local: tuple[int | str, ...] | None

    @property
    def public(self) -> str:
        """Return the normalized public version without local labels."""

        return _format_public(self)

    @property
    def canonical(self) -> str:
        """Return the normalized version, including local labels."""

        if self.local is None:
            return self.public
        return f"{self.public}+{_format_local(self.local)}"

    @property
    def is_prerelease(self) -> bool:
        """Return whether this version is a pre-release or dev release."""

        return self.pre is not None or self.dev is not None

    @property
    def is_postrelease(self) -> bool:
        """Return whether this version is a post release."""

        return self.post is not None

    def sort_key(self) -> tuple[object, ...]:
        """Return a PEP 440 ordering key for internal comparisons."""

        if self.pre is None and self.post is None and self.dev is not None:
            pre_key: object = _NEG_INF
        elif self.pre is None:
            pre_key = _INF
        else:
            pre_key = (_PRE_ORDER[self.pre[0]], self.pre[1])

        if self.post is None:
            post_key: object = _NEG_INF
        else:
            post_key = self.post

        if self.dev is None:
            dev_key: object = _INF
        else:
            dev_key = self.dev

        if self.local is None:
            local_key: object = _NEG_INF
        else:
            local_key = _local_sort_key(self.local)

        return (
            self.epoch,
            _release_sort_key(self.release),
            pre_key,
            post_key,
            dev_key,
            local_key,
        )


# ---------------------------------------------------------------------------
# Parsing and normalization
# ---------------------------------------------------------------------------


def parse_version(value: str) -> Pep440Version | None:
    """Parse a PEP 440 version string.

    Args:
        value: Version text to parse.

    Returns:
        Pep440Version when the input is parseable, otherwise None.
    """

    if not isinstance(value, str):
        return None

    original = value.strip()
    if not original:
        return None

    match = _VERSION_RE.match(original)
    if match is None:
        return None

    groups = match.groupdict()

    try:
        epoch = int(groups["epoch"] or "0")
        release = tuple(int(part) for part in groups["release"].split("."))
    except ValueError:
        return None

    pre = _parse_pre(groups.get("pre_label"), groups.get("pre_number"))
    if pre is None and groups.get("pre_label"):
        return None

    post = _parse_post(
        groups.get("implicit_post_number"),
        groups.get("post_label"),
        groups.get("post_number"),
    )
    if post is None and (
        groups.get("implicit_post_number") is not None
        or groups.get("post_label") is not None
    ):
        return None

    dev = _parse_dev(groups.get("dev_label"), groups.get("dev_number"))
    if dev is None and groups.get("dev_label"):
        return None

    local = _parse_local(groups.get("local"))
    if local is None and groups.get("local"):
        return None

    return Pep440Version(
        original=original,
        epoch=epoch,
        release=release,
        pre=pre,
        post=post,
        dev=dev,
        local=local,
    )


def canonicalize_version(value: str) -> str | None:
    """Return normalized version text, or None for unparseable input."""

    parsed = parse_version(value)
    if parsed is None:
        return None
    return parsed.canonical


def public_version(value: str) -> str | None:
    """Return normalized public version text without local labels."""

    parsed = parse_version(value)
    if parsed is None:
        return None
    return parsed.public


def _parse_pre(label: str | None, number: str | None) -> tuple[str, int] | None:
    if label is None:
        return None
    normalized = _PRE_NORMALIZATION.get(label.lower())
    if normalized is None:
        return None
    return normalized, int(number or "0")


def _parse_post(
    implicit_number: str | None,
    label: str | None,
    number: str | None,
) -> int | None:
    if implicit_number is not None:
        return int(implicit_number)
    if label is None:
        return None
    if label.lower() not in _POST_NORMALIZATION:
        return None
    return int(number or "0")


def _parse_dev(label: str | None, number: str | None) -> int | None:
    if label is None:
        return None
    if label.lower() != "dev":
        return None
    return int(number or "0")


def _parse_local(local: str | None) -> tuple[int | str, ...] | None:
    if local is None:
        return None

    parts: list[int | str] = []
    for raw_part in _LOCAL_SPLIT_RE.split(local.lower()):
        if not raw_part:
            return None
        if raw_part.isdigit():
            parts.append(int(raw_part))
        else:
            parts.append(raw_part)
    return tuple(parts)


# ---------------------------------------------------------------------------
# Comparison and range evaluation
# ---------------------------------------------------------------------------


def compare_versions(left: str, right: str) -> int | None:
    """Compare two PEP 440 versions.

    Returns:
        -1 when left is older than right, 0 when they compare equal,
        1 when left is newer than right, or None when either input is
        not parseable.
    """

    left_version = parse_version(left)
    right_version = parse_version(right)
    if left_version is None or right_version is None:
        return None

    left_key = left_version.sort_key()
    right_key = right_version.sort_key()

    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def version_in_range(
    version: str,
    *,
    introduced: str = "",
    fixed: str = "",
    last_affected: str = "",
) -> bool | None:
    """Evaluate an OSV-style version range row.

    Args:
        version: Candidate package version.
        introduced: Inclusive lower bound. Empty string and "0" mean no
            lower bound.
        fixed: Exclusive upper bound. Empty string means no fixed bound.
        last_affected: Inclusive upper bound. Empty string means no
            last-affected bound.

    Returns:
        True if the version is inside the range, False if it is outside,
        or None if any required version comparison cannot be performed.
    """

    if parse_version(version) is None:
        return None

    lower = introduced.strip()
    upper_fixed = fixed.strip()
    upper_last = last_affected.strip()

    if lower and lower != "0":
        lower_cmp = compare_versions(version, lower)
        if lower_cmp is None:
            return None
        if lower_cmp < 0:
            return False

    if upper_fixed:
        fixed_cmp = compare_versions(version, upper_fixed)
        if fixed_cmp is None:
            return None
        if fixed_cmp >= 0:
            return False

    if upper_last:
        last_cmp = compare_versions(version, upper_last)
        if last_cmp is None:
            return None
        if last_cmp > 0:
            return False

    return True


def is_prerelease(value: str) -> bool | None:
    """Return whether a parseable version is a pre-release."""

    parsed = parse_version(value)
    if parsed is None:
        return None
    return parsed.is_prerelease


def is_postrelease(value: str) -> bool | None:
    """Return whether a parseable version is a post release."""

    parsed = parse_version(value)
    if parsed is None:
        return None
    return parsed.is_postrelease


# ---------------------------------------------------------------------------
# Formatting and sort-key helpers
# ---------------------------------------------------------------------------


def _format_public(version: Pep440Version) -> str:
    release = ".".join(str(part) for part in version.release)
    pieces: list[str] = []
    if version.epoch:
        pieces.append(f"{version.epoch}!")
    pieces.append(release)
    if version.pre is not None:
        pieces.append(f"{version.pre[0]}{version.pre[1]}")
    if version.post is not None:
        pieces.append(f".post{version.post}")
    if version.dev is not None:
        pieces.append(f".dev{version.dev}")
    return "".join(pieces)


def _format_local(local: tuple[int | str, ...]) -> str:
    return ".".join(str(part) for part in local)


def _release_sort_key(release: tuple[int, ...]) -> tuple[int, ...]:
    trimmed = tuple(reversed(tuple(_drop_leading_zeroes(reversed(release)))))
    if not trimmed:
        return (0,)
    return trimmed


def _drop_leading_zeroes(values) -> tuple[int, ...]:
    kept: list[int] = []
    dropping = True
    for value in values:
        if dropping and value == 0:
            continue
        dropping = False
        kept.append(value)
    return tuple(kept)


def _local_sort_key(local: tuple[int | str, ...]) -> tuple[tuple[int, int | str], ...]:
    key: list[tuple[int, int | str]] = []
    for part in local:
        if isinstance(part, int):
            key.append((1, part))
        else:
            key.append((0, part))
    return tuple(key)
