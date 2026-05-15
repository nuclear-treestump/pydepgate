"""Tests for pydepgate.package_tools.cvedb.fetcher.

Covers:

  * HEAD check happy path and every documented failure mode.
  * Download happy path with and without head_info validation.
  * Atomic write semantics: success replaces destination,
    failure leaves the destination untouched and the .tmp
    removed.
  * Retry on transient errors with backoff suppression.
  * No retry on non-retriable errors (4xx other than 429).
  * Picklability of HeadInfo and FetchResult.
  * SHA256 matches the downloaded bytes.
  * Progress callback invoked with correct values.

The urlopen function is injected through the public parameter
on head_check and download, so no monkey-patching of urllib is
required.
"""

from __future__ import annotations

import io
import pickle
import tempfile
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Callable
from unittest import mock

from pydepgate.package_tools.cvedb.fetcher import (
    DEFAULT_MAX_CONTENT_LENGTH,
    DEFAULT_MIN_CONTENT_LENGTH,
    DownloadError,
    FetchResult,
    HeadCheckError,
    HeadInfo,
    SizeLimitExceeded,
    download,
    head_check,
)

# ---------------------------------------------------------------------------
# Test fakes
# ---------------------------------------------------------------------------


def _make_headers(pairs: dict[str, str]) -> Message:
    """Build a Message instance acting as response headers."""
    msg = Message()
    for key, value in pairs.items():
        msg[key] = value
    return msg


class FakeResponse:
    """Stand-in for urllib's HTTPResponse object.

    Supports the context-manager protocol, the status attribute,
    the headers attribute, and the read(size) method. Enough to
    exercise head_check and download without a real socket.
    """

    def __init__(
        self,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> None:
        self.status = status
        self.headers = _make_headers(headers or {})
        self._body = body
        self._pos = 0

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            chunk = self._body[self._pos :]
            self._pos = len(self._body)
            return chunk
        chunk = self._body[self._pos : self._pos + size]
        self._pos += len(chunk)
        return chunk


def _ok_head_response(
    *, size: int, content_type: str = "application/zip"
) -> FakeResponse:
    return FakeResponse(
        status=200,
        headers={
            "Content-Type": content_type,
            "Content-Length": str(size),
            "ETag": '"abc123"',
            "Last-Modified": "Wed, 14 May 2026 12:00:00 GMT",
        },
    )


def _ok_get_response(
    *, body: bytes, content_type: str = "application/zip"
) -> FakeResponse:
    return FakeResponse(
        status=200,
        headers={
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
        },
        body=body,
    )


def _stub_urlopen(*responses: FakeResponse | Exception) -> Callable:
    """Build an urlopen stub that yields the given responses in order.

    Each call returns the next response, or raises if the next item
    is an exception. Used to script multi-call test scenarios such as
    the retry path.
    """
    iterator = iter(responses)

    def fake_urlopen(_request, timeout=None):
        item = next(iterator)
        if isinstance(item, Exception):
            raise item
        return item

    return fake_urlopen


# ---------------------------------------------------------------------------
# head_check
# ---------------------------------------------------------------------------


class TestHeadCheckHappyPath(unittest.TestCase):
    def test_returns_head_info_on_valid_response(self):
        size = DEFAULT_MIN_CONTENT_LENGTH + 1
        url = "https://example.invalid/PyPI/all.zip"
        info = head_check(
            url,
            urlopen=_stub_urlopen(_ok_head_response(size=size)),
        )
        self.assertIsInstance(info, HeadInfo)
        self.assertEqual(info.url, url)
        self.assertEqual(info.status, 200)
        self.assertEqual(info.content_type, "application/zip")
        self.assertEqual(info.content_length, size)
        self.assertEqual(info.etag, '"abc123"')
        self.assertEqual(info.last_modified, "Wed, 14 May 2026 12:00:00 GMT")

    def test_accepts_octet_stream_content_type(self):
        size = DEFAULT_MIN_CONTENT_LENGTH + 1
        info = head_check(
            "https://example.invalid/PyPI/all.zip",
            urlopen=_stub_urlopen(
                _ok_head_response(size=size, content_type="application/octet-stream")
            ),
        )
        self.assertEqual(info.content_type, "application/octet-stream")

    def test_strips_content_type_parameters(self):
        size = DEFAULT_MIN_CONTENT_LENGTH + 1
        info = head_check(
            "https://example.invalid/PyPI/all.zip",
            urlopen=_stub_urlopen(
                _ok_head_response(
                    size=size, content_type="application/zip; charset=binary"
                )
            ),
        )
        self.assertEqual(info.content_type, "application/zip")


class TestHeadCheckFailures(unittest.TestCase):
    def test_non_200_status_raises_head_check_error(self):
        response = FakeResponse(
            status=403,
            headers={
                "Content-Type": "application/zip",
                "Content-Length": str(DEFAULT_MIN_CONTENT_LENGTH + 1),
            },
        )
        with self.assertRaises(HeadCheckError) as ctx:
            head_check(
                "https://example.invalid/PyPI/all.zip",
                urlopen=_stub_urlopen(response),
            )
        self.assertIn("status 403", str(ctx.exception))

    def test_wrong_content_type_raises_head_check_error(self):
        response = FakeResponse(
            status=200,
            headers={
                "Content-Type": "text/html",
                "Content-Length": str(DEFAULT_MIN_CONTENT_LENGTH + 1),
            },
        )
        with self.assertRaises(HeadCheckError) as ctx:
            head_check(
                "https://example.invalid/PyPI/all.zip",
                urlopen=_stub_urlopen(response),
            )
        self.assertIn("Content-Type", str(ctx.exception))

    def test_missing_content_length_raises_head_check_error(self):
        response = FakeResponse(
            status=200,
            headers={"Content-Type": "application/zip"},
        )
        with self.assertRaises(HeadCheckError) as ctx:
            head_check(
                "https://example.invalid/PyPI/all.zip",
                urlopen=_stub_urlopen(response),
            )
        self.assertIn("Content-Length", str(ctx.exception))

    def test_non_integer_content_length_raises_head_check_error(self):
        response = FakeResponse(
            status=200,
            headers={
                "Content-Type": "application/zip",
                "Content-Length": "not-a-number",
            },
        )
        with self.assertRaises(HeadCheckError) as ctx:
            head_check(
                "https://example.invalid/PyPI/all.zip",
                urlopen=_stub_urlopen(response),
            )
        self.assertIn("non-integer", str(ctx.exception))

    def test_content_length_below_minimum_raises_size_limit(self):
        response = FakeResponse(
            status=200,
            headers={
                "Content-Type": "application/zip",
                "Content-Length": str(DEFAULT_MIN_CONTENT_LENGTH - 1),
            },
        )
        with self.assertRaises(SizeLimitExceeded) as ctx:
            head_check(
                "https://example.invalid/PyPI/all.zip",
                urlopen=_stub_urlopen(response),
            )
        self.assertIn("below the minimum", str(ctx.exception))

    def test_content_length_above_maximum_raises_size_limit(self):
        response = FakeResponse(
            status=200,
            headers={
                "Content-Type": "application/zip",
                "Content-Length": str(DEFAULT_MAX_CONTENT_LENGTH + 1),
            },
        )
        with self.assertRaises(SizeLimitExceeded) as ctx:
            head_check(
                "https://example.invalid/PyPI/all.zip",
                urlopen=_stub_urlopen(response),
            )
        self.assertIn("above the maximum", str(ctx.exception))

    def test_http_error_raises_head_check_error(self):
        exc = urllib.error.HTTPError(
            url="https://example.invalid/PyPI/all.zip",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=None,
        )
        with self.assertRaises(HeadCheckError) as ctx:
            head_check(
                "https://example.invalid/PyPI/all.zip",
                urlopen=_stub_urlopen(exc),
            )
        self.assertIn("HTTP 404", str(ctx.exception))

    def test_network_error_raises_download_error(self):
        exc = urllib.error.URLError("connection refused")
        with self.assertRaises(DownloadError) as ctx:
            head_check(
                "https://example.invalid/PyPI/all.zip",
                urlopen=_stub_urlopen(exc),
            )
        self.assertIn("URLError", str(ctx.exception))

    def test_head_is_not_retried(self):
        # HEAD failure must NOT trigger a second urlopen call.
        call_count = {"n": 0}

        def fake_urlopen(_request, timeout=None):
            call_count["n"] += 1
            raise urllib.error.URLError("connection refused")

        with self.assertRaises(DownloadError):
            head_check(
                "https://example.invalid/PyPI/all.zip",
                urlopen=fake_urlopen,
            )
        self.assertEqual(call_count["n"], 1)


# ---------------------------------------------------------------------------
# download
# ---------------------------------------------------------------------------


class TestDownloadHappyPath(unittest.TestCase):
    def test_writes_bytes_to_destination(self):
        body = b"hello world" * 100
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            result = download(
                "https://example.invalid/resource",
                dest,
                urlopen=_stub_urlopen(_ok_get_response(body=body)),
            )
            self.assertTrue(dest.exists())
            self.assertEqual(dest.read_bytes(), body)
            self.assertEqual(result.bytes_written, len(body))
            self.assertEqual(result.path, dest)

    def test_temp_file_removed_after_success(self):
        body = b"abcdef" * 50
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            tmp_path = dest.with_name(dest.name + ".tmp")
            download(
                "https://example.invalid/resource",
                dest,
                urlopen=_stub_urlopen(_ok_get_response(body=body)),
            )
            self.assertFalse(tmp_path.exists())

    def test_sha256_matches_body(self):
        import hashlib

        body = b"some specific test bytes for hashing 12345"
        expected_hash = hashlib.sha256(body).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            result = download(
                "https://example.invalid/resource",
                dest,
                urlopen=_stub_urlopen(_ok_get_response(body=body)),
            )
            self.assertEqual(result.sha256, expected_hash)

    def test_head_info_size_validation_passes(self):
        body = b"x" * 1024
        head_info = HeadInfo(
            url="https://example.invalid/resource",
            status=200,
            content_type="application/zip",
            content_length=len(body),
            etag=None,
            last_modified=None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            result = download(
                "https://example.invalid/resource",
                dest,
                head_info=head_info,
                urlopen=_stub_urlopen(_ok_get_response(body=body)),
            )
            self.assertEqual(result.bytes_written, len(body))

    def test_progress_callback_invoked(self):
        body = b"y" * 200
        calls: list[tuple[int, int | None]] = []
        head_info = HeadInfo(
            url="https://example.invalid/resource",
            status=200,
            content_type="application/zip",
            content_length=len(body),
            etag=None,
            last_modified=None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            download(
                "https://example.invalid/resource",
                dest,
                head_info=head_info,
                chunk_size=64,
                progress_callback=lambda recv, total: calls.append((recv, total)),
                urlopen=_stub_urlopen(_ok_get_response(body=body)),
            )
        self.assertGreater(len(calls), 0)
        # The last call's received-byte count equals the body size.
        self.assertEqual(calls[-1][0], len(body))
        # When head_info was supplied, total is its content_length.
        self.assertEqual(calls[-1][1], len(body))

    def test_progress_total_is_none_without_head_info(self):
        body = b"z" * 100
        calls: list[tuple[int, int | None]] = []
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            download(
                "https://example.invalid/resource",
                dest,
                chunk_size=32,
                progress_callback=lambda recv, total: calls.append((recv, total)),
                urlopen=_stub_urlopen(_ok_get_response(body=body)),
            )
        self.assertGreater(len(calls), 0)
        self.assertIsNone(calls[-1][1])


class TestDownloadFailures(unittest.TestCase):
    def test_size_mismatch_raises_download_error(self):
        body = b"q" * 100
        head_info = HeadInfo(
            url="https://example.invalid/resource",
            status=200,
            content_type="application/zip",
            content_length=200,
            etag=None,
            last_modified=None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            with self.assertRaises(DownloadError) as ctx:
                download(
                    "https://example.invalid/resource",
                    dest,
                    head_info=head_info,
                    max_retries=0,
                    urlopen=_stub_urlopen(_ok_get_response(body=body)),
                )
            self.assertIn("returned 100 bytes, expected 200", str(ctx.exception))
            self.assertFalse(dest.exists())

    def test_partial_temp_removed_after_failure(self):
        head_info = HeadInfo(
            url="https://example.invalid/resource",
            status=200,
            content_type="application/zip",
            content_length=200,
            etag=None,
            last_modified=None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            tmp_path = dest.with_name(dest.name + ".tmp")
            with self.assertRaises(DownloadError):
                download(
                    "https://example.invalid/resource",
                    dest,
                    head_info=head_info,
                    max_retries=0,
                    urlopen=_stub_urlopen(_ok_get_response(body=b"short")),
                )
            self.assertFalse(tmp_path.exists())
            self.assertFalse(dest.exists())

    def test_404_raises_download_error_without_retry(self):
        call_count = {"n": 0}
        exc = urllib.error.HTTPError(
            url="https://example.invalid/resource",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=None,
        )

        def fake_urlopen(_request, timeout=None):
            call_count["n"] += 1
            raise exc

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            with self.assertRaises(DownloadError):
                download(
                    "https://example.invalid/resource",
                    dest,
                    max_retries=3,
                    urlopen=fake_urlopen,
                )
        # Non-retriable: exactly one attempt.
        self.assertEqual(call_count["n"], 1)


class TestDownloadRetries(unittest.TestCase):
    def test_transient_error_then_success(self):
        body = b"recovery" * 10
        responses: list[FakeResponse | Exception] = [
            urllib.error.URLError("connection reset"),
            _ok_get_response(body=body),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            with mock.patch(
                "pydepgate.package_tools.cvedb.fetcher.time.sleep"
            ) as sleep_mock:
                result = download(
                    "https://example.invalid/resource",
                    dest,
                    max_retries=1,
                    urlopen=_stub_urlopen(*responses),
                )
            self.assertEqual(result.bytes_written, len(body))
            self.assertEqual(dest.read_bytes(), body)
            # One backoff sleep between the two attempts.
            self.assertEqual(sleep_mock.call_count, 1)

    def test_500_then_success(self):
        body = b"after-5xx"
        responses: list[FakeResponse | Exception] = [
            urllib.error.HTTPError(
                url="https://example.invalid/resource",
                code=500,
                msg="Internal Server Error",
                hdrs=None,
                fp=None,
            ),
            _ok_get_response(body=body),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            with mock.patch("pydepgate.package_tools.cvedb.fetcher.time.sleep"):
                result = download(
                    "https://example.invalid/resource",
                    dest,
                    max_retries=1,
                    urlopen=_stub_urlopen(*responses),
                )
            self.assertEqual(dest.read_bytes(), body)
            self.assertEqual(result.bytes_written, len(body))

    def test_retries_exhausted_raises(self):
        responses: list[FakeResponse | Exception] = [
            urllib.error.URLError("x"),
            urllib.error.URLError("x"),
            urllib.error.URLError("x"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            tmp_path = dest.with_name(dest.name + ".tmp")
            with mock.patch("pydepgate.package_tools.cvedb.fetcher.time.sleep"):
                with self.assertRaises(DownloadError):
                    download(
                        "https://example.invalid/resource",
                        dest,
                        max_retries=2,
                        urlopen=_stub_urlopen(*responses),
                    )
            self.assertFalse(tmp_path.exists())
            self.assertFalse(dest.exists())


# ---------------------------------------------------------------------------
# Picklability
# ---------------------------------------------------------------------------


class TestPicklability(unittest.TestCase):
    """The static engine's picklability contract is in CONTRIBUTING.md.

    These result types are not analyzers, but the contract is the
    right discipline regardless: keep them frozen, keep them simple,
    pickle-round-trip them in the test suite.
    """

    def test_head_info_round_trip(self):
        info = HeadInfo(
            url="https://example.invalid/resource",
            status=200,
            content_type="application/zip",
            content_length=12345,
            etag='"abc"',
            last_modified="Wed, 14 May 2026 12:00:00 GMT",
        )
        restored = pickle.loads(pickle.dumps(info))
        self.assertEqual(restored, info)

    def test_fetch_result_round_trip(self):
        result = FetchResult(
            path=Path("/tmp/x.bin"),
            bytes_written=12345,
            sha256="deadbeef" * 8,
            content_type="application/zip",
            etag='"abc"',
            last_modified="Wed, 14 May 2026 12:00:00 GMT",
        )
        restored = pickle.loads(pickle.dumps(result))
        self.assertEqual(restored, result)


# ---------------------------------------------------------------------------
# User-Agent
# ---------------------------------------------------------------------------


class TestUserAgent(unittest.TestCase):
    """Indirect test: verify the request carries our identity.

    Captures the Request object passed to urlopen and inspects its
    headers. Both head_check and download exercise the same builder.
    """

    def test_head_request_carries_user_agent(self):
        captured: dict[str, object] = {}

        def fake_urlopen(request, timeout=None):
            captured["headers"] = dict(request.header_items())
            return _ok_head_response(size=DEFAULT_MIN_CONTENT_LENGTH + 1)

        head_check(
            "https://example.invalid/resource",
            urlopen=fake_urlopen,
        )
        # urllib normalizes header names to title case in
        # header_items(). The User-Agent key may appear as
        # "User-agent" depending on the urllib version.
        headers_lower = {k.lower(): v for k, v in captured["headers"].items()}
        self.assertIn("user-agent", headers_lower)
        self.assertIn("pydepgate-cvedb/", headers_lower["user-agent"])

    def test_get_request_carries_user_agent(self):
        captured: dict[str, object] = {}

        def fake_urlopen(request, timeout=None):
            captured["headers"] = dict(request.header_items())
            return _ok_get_response(body=b"hello")

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            download(
                "https://example.invalid/resource",
                dest,
                urlopen=fake_urlopen,
            )
        headers_lower = {k.lower(): v for k, v in captured["headers"].items()}
        self.assertIn("user-agent", headers_lower)
        self.assertIn("pydepgate-cvedb/", headers_lower["user-agent"])


if __name__ == "__main__":
    unittest.main()
