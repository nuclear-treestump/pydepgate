"""pydepgate.package_tools.cvedb.fetcher

HTTP fetcher for the OSV PyPI vulnerability dataset.

Public surface:

    head_check(url, ...) -> HeadInfo
        Validate that the URL serves the kind of resource we
        expect before committing to a full download. Checks
        status code, content type, and content length against a
        configurable size range.

    download(url, destination, ...) -> FetchResult
        Stream the resource to disk with atomic write semantics,
        SHA256 computation during streaming, and bounded retries
        on transient failures.

    HeadInfo, FetchResult
        Frozen, picklable dataclasses returned on success.

    FetchError, HeadCheckError, DownloadError, SizeLimitExceeded
        Exception hierarchy for failure modes.

This module is stdlib-only. urllib handles HTTP, hashlib computes
SHA256 inline with the byte stream, and pathlib drives the disk
side. The fetcher does not know about OSV specifically; it takes a
URL and a destination path and is reusable for any large-binary
download where pre-flight size validation and atomic write matter.

The two top-level functions are independent. head_check is cheap
and informational; download performs the actual fetch and accepts
an optional pre-computed HeadInfo so a caller can split the round
trip from the validation. The intended composition is:

    info = head_check(url)
    result = download(url, destination, head_info=info)

The download is atomic at the filesystem level: bytes are streamed
to {destination}.tmp and only renamed to {destination} after the
full body has been received, the on-the-fly SHA256 has been
finalized, and (if a HeadInfo was supplied) the actual byte count
matches the advertised Content-Length. A partial download never
leaves a file at the canonical path.

Retries: connection errors and 5xx/429 status codes retry up to
max_retries times with exponential backoff. 4xx codes other than
429 fail immediately so the caller gets a fast signal that the URL
or request shape is wrong.

Testing seam: head_check and download both accept an urlopen
parameter defaulting to urllib.request.urlopen. Tests substitute a
fake without monkey-patching the global module.
"""

from __future__ import annotations

import hashlib
import http.client
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

# User-Agent product identity. The version segment is read lazily in
# _build_user_agent so test environments that patch the version module
# see the patched value and so this import does not happen at module
# load time.
_USER_AGENT_PRODUCT = "pydepgate-cvedb"
_USER_AGENT_SOURCE = "+https://github.com/nuclear-treestump/pydepgate"

# Content-Type values acceptable for a binary zip download. GCS
# sometimes serves zips as application/octet-stream when the object
# metadata does not pin a more specific type. Both are acceptable.
DEFAULT_ACCEPTED_CONTENT_TYPES: tuple[str, ...] = (
    "application/zip",
    "application/octet-stream",
)

# Size sanity limits for the OSV PyPI all.zip. Today's value is
# around 90MB. The lower bound exists so we refuse a server that
# returns a stub or empty response; the upper bound is the first
# defense against decompression bombs. A second defense lives in
# the importer, which validates decompressed sizes per-entry and
# in aggregate.
DEFAULT_MIN_CONTENT_LENGTH = 15 * 1024 * 1024
DEFAULT_MAX_CONTENT_LENGTH = 200 * 1024 * 1024

# Default per-operation timeout. urllib does not distinguish connect
# from read timeouts; this single value applies to each socket
# operation. 60 seconds is generous enough for a slow link and tight
# enough that a stalled server fails the request rather than hanging
# forever.
DEFAULT_TIMEOUT_SECONDS = 60.0

# Streaming chunk size. 64KB balances throughput against memory and
# matches the common readinto loop size. Smaller chunks waste syscall
# overhead; larger chunks delay the progress callback.
DEFAULT_CHUNK_SIZE = 64 * 1024

# Retry policy. Three attempts total (one initial plus two retries)
# is enough to cover transient blips without making the user wait
# forever on a hard failure. Backoff is exponential starting at one
# second.
DEFAULT_MAX_RETRIES = 2
DEFAULT_RETRY_BACKOFF_BASE_SECONDS = 1.0

# HTTP status codes that warrant a retry. 429 (rate limit) is
# included as a special case alongside the 5xx server-error codes.
# Every other 4xx code means the request is wrong and retrying it
# would not help.
_RETRIABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


# ---------------------------------------------------------------------------
# Public result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HeadInfo:
    """Result of a successful HEAD check.

    Attributes:
        url: The URL that was checked. Not necessarily the final
            URL after redirects; urllib follows redirects
            transparently and this field carries the input value.
        status: HTTP status code returned by the server.
        content_type: Content-Type header value normalized to its
            primary type (parameters stripped, lowercased).
        content_length: Content-Length header parsed as an int.
        etag: ETag header value, or None if absent. Useful for
            future caching: a follow-up HEAD with the same ETag
            indicates the content is unchanged.
        last_modified: Last-Modified header value, or None.
    """

    url: str
    status: int
    content_type: str
    content_length: int
    etag: str | None
    last_modified: str | None


@dataclass(frozen=True)
class FetchResult:
    """Result of a successful download.

    Attributes:
        path: Final on-disk path of the downloaded file.
        bytes_written: Number of bytes that ended up on disk.
            Equal to the response body length on success.
        sha256: Hex-encoded SHA256 of the downloaded bytes,
            computed inline with the byte stream rather than via
            a post-write re-read of the file.
        content_type: Content-Type from the GET response,
            normalized.
        etag: ETag from the GET response, or None.
        last_modified: Last-Modified from the GET response, or
            None.
    """

    path: Path
    bytes_written: int
    sha256: str
    content_type: str
    etag: str | None
    last_modified: str | None


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class FetchError(Exception):
    """Base class for any fetcher failure."""


class HeadCheckError(FetchError):
    """A HEAD request failed validation.

    Raised when the server responded but the response is not
    acceptable: wrong status, wrong content type, or missing
    content length.
    """


class DownloadError(FetchError):
    """A GET request failed.

    Raised when the server could not be reached after retries, when
    a non-retriable HTTP error occurred, or when the streamed body
    did not match the size advertised by a prior HEAD check.
    """


class SizeLimitExceeded(FetchError):
    """Content-Length was outside the acceptable range.

    Raised by head_check when the server-advertised size falls
    below the minimum or above the maximum configured for the
    check. Treated as a separate type from HeadCheckError because
    callers may want to distinguish "server is wrong" from
    "server is potentially malicious."
    """


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _build_user_agent() -> str:
    """Construct the User-Agent header value.

    Reads the package version lazily from
    pydepgate.cli.subcommands.version so test environments that
    patch the version module see the patched value, and so the
    import does not happen at module load time. Falls back to a
    static identifier if the version cannot be read.
    """
    try:
        from pydepgate.cli.subcommands.version import get_version

        version = get_version()
    except Exception:
        version = "unknown"
    return f"{_USER_AGENT_PRODUCT}/{version} ({_USER_AGENT_SOURCE})"


def _normalize_content_type(raw: str | None) -> str:
    """Strip parameters and lowercase a Content-Type header.

    "application/zip; charset=binary" becomes "application/zip".
    None becomes the empty string so callers can compare uniformly
    without special-casing missing headers.
    """
    if raw is None:
        return ""
    return raw.split(";", 1)[0].strip().lower()


def _build_request(
    url: str,
    method: str,
    user_agent: str,
) -> urllib.request.Request:
    """Build a urllib Request with our standard headers."""
    return urllib.request.Request(
        url,
        method=method,
        headers={
            "User-Agent": user_agent,
            "Accept": "application/zip,application/octet-stream,*/*;q=0.1",
        },
    )


def _is_retriable_error(exc: BaseException) -> bool:
    """Return True for errors that warrant a retry.

    Transient network errors, retriable HTTP status codes, and
    timeout errors are retriable. Everything else fails on the
    first attempt.
    """
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in _RETRIABLE_STATUS_CODES
    if isinstance(
        exc,
        (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            ConnectionError,
            OSError,
        ),
    ):
        return True
    return False


def _sleep_backoff(attempt: int, base: float) -> None:
    """Sleep for base * 2**attempt seconds.

    attempt is zero-indexed: 0 -> base, 1 -> base*2, 2 -> base*4.
    Pulled out so tests can monkey-patch the sleep to keep
    retry-path test cases fast.
    """
    time.sleep(base * (2**attempt))


def _cleanup_partial(path: Path) -> None:
    """Remove a partial .tmp file, ignoring errors.

    Called from the retry loop and the failure paths of download.
    A failed unlink is not worth raising over; the next attempt
    will overwrite the file anyway, and the canonical destination
    is never touched on failure.
    """
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError:
        return


# ---------------------------------------------------------------------------
# HEAD check
# ---------------------------------------------------------------------------


def head_check(
    url: str,
    *,
    min_content_length: int = DEFAULT_MIN_CONTENT_LENGTH,
    max_content_length: int = DEFAULT_MAX_CONTENT_LENGTH,
    accepted_content_types: tuple[str, ...] = DEFAULT_ACCEPTED_CONTENT_TYPES,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    urlopen: Callable = urllib.request.urlopen,
) -> HeadInfo:
    """Validate that a URL serves the kind of resource we expect.

    Sends a HEAD request, reads the response headers, and validates:

      * Status code is 200.
      * Content-Type matches one of the accepted values.
      * Content-Length is present and within [min, max] inclusive.

    Returns a HeadInfo on success. Raises HeadCheckError or
    SizeLimitExceeded on validation failure. Raises DownloadError
    on network failure. HEAD is not retried; if the server cannot
    answer a HEAD request, retrying the same request is unlikely
    to help and retrying does not give the caller actionable info.

    Args:
        url: The URL to check.
        min_content_length: Lower bound (inclusive) on expected
            size in bytes.
        max_content_length: Upper bound (inclusive) on expected
            size in bytes.
        accepted_content_types: Tuple of acceptable Content-Type
            primary types. Compared after parameter stripping and
            lowercasing.
        timeout: Per-operation timeout in seconds.
        urlopen: Callable matching urllib.request.urlopen's
            signature. Defaults to the real urllib. Tests inject
            a stub.
    """
    user_agent = _build_user_agent()
    request = _build_request(url, method="HEAD", user_agent=user_agent)
    try:
        with urlopen(request, timeout=timeout) as response:
            status = response.status
            headers = response.headers
    except urllib.error.HTTPError as exc:
        raise HeadCheckError(
            f"HEAD {url} returned HTTP {exc.code}: {exc.reason}"
        ) from exc
    except (
        urllib.error.URLError,
        http.client.HTTPException,
        TimeoutError,
        ConnectionError,
        OSError,
    ) as exc:
        raise DownloadError(f"HEAD {url} failed: {type(exc).__name__}: {exc}") from exc

    if status != 200:
        raise HeadCheckError(f"HEAD {url} returned status {status}, expected 200")

    content_type = _normalize_content_type(headers.get("Content-Type"))
    if content_type not in accepted_content_types:
        raise HeadCheckError(
            f"HEAD {url} returned Content-Type {content_type!r}, "
            f"expected one of {list(accepted_content_types)}"
        )

    content_length_raw = headers.get("Content-Length")
    if content_length_raw is None:
        raise HeadCheckError(
            f"HEAD {url} did not include a Content-Length header. "
            f"This fetcher requires servers to advertise the "
            f"resource size in advance."
        )
    try:
        content_length = int(content_length_raw)
    except ValueError as exc:
        raise HeadCheckError(
            f"HEAD {url} returned non-integer Content-Length " f"{content_length_raw!r}"
        ) from exc

    if content_length < min_content_length:
        raise SizeLimitExceeded(
            f"HEAD {url} reported Content-Length {content_length}, "
            f"below the minimum {min_content_length}"
        )
    if content_length > max_content_length:
        raise SizeLimitExceeded(
            f"HEAD {url} reported Content-Length {content_length}, "
            f"above the maximum {max_content_length}"
        )

    return HeadInfo(
        url=url,
        status=status,
        content_type=content_type,
        content_length=content_length,
        etag=headers.get("ETag"),
        last_modified=headers.get("Last-Modified"),
    )


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


def download(
    url: str,
    destination: Path,
    *,
    head_info: HeadInfo | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_retries: int = DEFAULT_MAX_RETRIES,
    progress_callback: Callable[[int, int | None], None] | None = None,
    urlopen: Callable = urllib.request.urlopen,
) -> FetchResult:
    """Stream a URL to a file on disk with atomic write semantics.

    The download is written to {destination}.tmp during streaming
    and atomically renamed to {destination} once the body has been
    received in full, the on-the-fly SHA256 has been finalized,
    and (if head_info is supplied) the byte count matches the
    advertised Content-Length. The partial .tmp is removed on any
    failure path so the next attempt starts from a clean state.

    Retries: connection errors and retriable HTTP status codes
    retry up to max_retries additional times after the first
    attempt, with exponential backoff. Each retry is a fresh
    request; this fetcher does NOT use HTTP range requests to
    resume an interrupted download. Resume support would require
    trust that the server's bytes have not changed mid-download,
    which is a property of OSV's snapshot publishing model that
    has not been independently validated.

    Args:
        url: The URL to download.
        destination: Final on-disk path. Parent directory must
            already exist; this function does not create
            directories. The temporary file is at
            {destination}.tmp.
        head_info: Optional pre-fetched HeadInfo. When provided,
            the downloaded byte count is validated against
            head_info.content_length. When None, no size
            validation is performed beyond what the streaming
            loop reads.
        chunk_size: Bytes per read iteration.
        timeout: Per-operation timeout in seconds, applied to
            each socket read.
        max_retries: Number of retry attempts after the initial
            try. Zero means try once and fail on the first error.
        progress_callback: Optional callable invoked after each
            chunk with (bytes_received, total_expected).
            total_expected is head_info.content_length when
            head_info was provided, otherwise None.
        urlopen: Callable matching urllib.request.urlopen's
            signature.

    Returns:
        FetchResult on success.

    Raises:
        DownloadError: All retry attempts failed, or a
            non-retriable error occurred, or the body size did
            not match the advertised Content-Length.
    """
    temp_path = destination.with_name(destination.name + ".tmp")
    user_agent = _build_user_agent()

    expected_size = head_info.content_length if head_info else None
    last_error: BaseException | None = None

    for attempt in range(max_retries + 1):
        try:
            return _download_attempt(
                url=url,
                temp_path=temp_path,
                destination=destination,
                expected_size=expected_size,
                chunk_size=chunk_size,
                timeout=timeout,
                user_agent=user_agent,
                progress_callback=progress_callback,
                urlopen=urlopen,
            )
        except DownloadError as exc:
            last_error = exc
            cause = exc.__cause__ if exc.__cause__ is not None else exc
            _cleanup_partial(temp_path)
            if not _is_retriable_error(cause) or attempt >= max_retries:
                raise
            _sleep_backoff(attempt, DEFAULT_RETRY_BACKOFF_BASE_SECONDS)

    # Defensive: the loop above either returns or raises. This is
    # only reached if max_retries is negative, which is a programmer
    # error rather than a runtime condition.
    _cleanup_partial(temp_path)
    raise DownloadError(f"GET {url} failed after {max_retries} retries: {last_error}")


def _download_attempt(
    *,
    url: str,
    temp_path: Path,
    destination: Path,
    expected_size: int | None,
    chunk_size: int,
    timeout: float,
    user_agent: str,
    progress_callback: Callable[[int, int | None], None] | None,
    urlopen: Callable,
) -> FetchResult:
    """One pass of the download. Raises DownloadError on failure.

    Separated from download() so the retry loop has a clean inner
    function to call. Each call here is a fresh HTTP request and
    a fresh temp file write; there is no partial-state carry
    between attempts.
    """
    request = _build_request(url, method="GET", user_agent=user_agent)
    hasher = hashlib.sha256()
    bytes_written = 0

    try:
        with urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            if status != 200:
                raise DownloadError(f"GET {url} returned status {status}, expected 200")
            headers = response.headers
            content_type = _normalize_content_type(headers.get("Content-Type"))
            etag = headers.get("ETag")
            last_modified = headers.get("Last-Modified")

            with open(temp_path, "wb") as out:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    out.write(chunk)
                    hasher.update(chunk)
                    bytes_written += len(chunk)
                    if progress_callback is not None:
                        progress_callback(bytes_written, expected_size)
    except urllib.error.HTTPError as exc:
        raise DownloadError(
            f"GET {url} returned HTTP {exc.code}: {exc.reason}"
        ) from exc
    except (
        urllib.error.URLError,
        http.client.HTTPException,
        TimeoutError,
        ConnectionError,
        OSError,
    ) as exc:
        raise DownloadError(f"GET {url} failed: {type(exc).__name__}: {exc}") from exc

    if expected_size is not None and bytes_written != expected_size:
        raise DownloadError(
            f"GET {url} returned {bytes_written} bytes, expected "
            f"{expected_size} per HEAD check"
        )

    # Atomic rename. os.replace is atomic on POSIX and Windows for
    # same-filesystem paths; temp and destination share a parent
    # directory so this holds.
    os.replace(temp_path, destination)

    return FetchResult(
        path=destination,
        bytes_written=bytes_written,
        sha256=hasher.hexdigest(),
        content_type=content_type,
        etag=etag,
        last_modified=last_modified,
    )
