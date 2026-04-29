"""Tests for pydepgate.cli._archive.

Coverage map:

  - Cipher primitives (CRC table, key init, key updates, keystream,
    encrypt) at the function level. These tests lock the spec
    behavior independently of the ZIP framing.
  - DOS time/date encoding.
  - Round-trip via Python's zipfile module: this is the primary
    interoperability check. If our archive cannot be opened by
    zipfile.ZipFile with the right password, nothing else will
    open it either.
  - Round-trip via the system unzip command, gated on unzip being
    on PATH. Verifies wire-format compatibility with the dominant
    non-Python ZIP reader.
  - Error paths: empty input, invalid names, non-ASCII passwords,
    partial-write resistance.
  - Wire-format details: signatures, flag bits, sizes, CRC fields,
    and CDH-LFH agreement.
"""

from __future__ import annotations

import secrets as _secrets
import shutil
import struct
import subprocess
import tempfile
import unittest
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

from pydepgate.cli._archive import (
    _CRC_TABLE,
    _FLAG_ENCRYPTED,
    _FLAG_UTF8,
    _SIG_CDH,
    _SIG_EOCD,
    _SIG_LFH,
    _crc_update,
    _encrypt,
    _init_keys,
    _stream_byte,
    _to_dos_time_date,
    _update_keys,
    write_encrypted_zip,
)


# =============================================================================
# CRC-32 table
# =============================================================================

class CRCTableTests(unittest.TestCase):
    """The CRC table must match zlib's polynomial."""

    def test_table_has_256_entries(self):
        self.assertEqual(len(_CRC_TABLE), 256)

    def test_table_zero_is_zero(self):
        self.assertEqual(_CRC_TABLE[0], 0)

    def test_byte_update_matches_zlib(self):
        """Our byte update plus the standard finalization XOR matches
        zlib.crc32 on the same single byte."""
        for b in range(256):
            with self.subTest(byte=b):
                running = _crc_update(0xFFFFFFFF, b)
                ours_final = running ^ 0xFFFFFFFF
                theirs = zlib.crc32(bytes([b]))
                self.assertEqual(ours_final, theirs)


# =============================================================================
# Cipher primitives
# =============================================================================

class CipherInitTests(unittest.TestCase):
    """Initial key state and password-driven setup."""

    def test_empty_password_keys_unchanged(self):
        keys = _init_keys(b"")
        self.assertEqual(keys, [0x12345678, 0x23456789, 0x34567890])

    def test_single_char_password_changes_all_three_keys(self):
        keys = _init_keys(b"x")
        self.assertNotEqual(keys[0], 0x12345678)
        self.assertNotEqual(keys[1], 0x23456789)
        self.assertNotEqual(keys[2], 0x34567890)

    def test_keys_remain_uint32_after_long_password(self):
        keys = _init_keys(b"a" * 1000)
        for k in keys:
            self.assertGreaterEqual(k, 0)
            self.assertLessEqual(k, 0xFFFFFFFF)

    def test_different_passwords_yield_different_keys(self):
        a = _init_keys(b"infected")
        b = _init_keys(b"malware")
        self.assertNotEqual(a, b)

    def test_init_returns_independent_lists(self):
        """Two separate _init_keys calls must produce independent
        list objects (mutation of one must not affect the other)."""
        a = _init_keys(b"infected")
        b = _init_keys(b"infected")
        self.assertIsNot(a, b)
        a[0] = 0
        self.assertNotEqual(b[0], 0)


class CipherUpdateTests(unittest.TestCase):
    """Per-byte key update mechanics."""

    def test_update_advances_state(self):
        keys = [0x12345678, 0x23456789, 0x34567890]
        before = list(keys)
        _update_keys(keys, ord("A"))
        self.assertNotEqual(keys, before)

    def test_update_mutates_in_place_returns_none(self):
        keys = [0x12345678, 0x23456789, 0x34567890]
        result = _update_keys(keys, 0x41)
        self.assertIsNone(result)

    def test_update_preserves_uint32_across_all_bytes(self):
        keys = [0x12345678, 0x23456789, 0x34567890]
        for b in range(256):
            _update_keys(keys, b)
            for k in keys:
                self.assertGreaterEqual(k, 0)
                self.assertLessEqual(k, 0xFFFFFFFF)


class StreamByteTests(unittest.TestCase):
    """Keystream byte derivation."""

    def test_stream_byte_in_byte_range(self):
        keys = _init_keys(b"infected")
        for _ in range(100):
            s = _stream_byte(keys)
            self.assertGreaterEqual(s, 0)
            self.assertLessEqual(s, 0xFF)
            _update_keys(keys, ord("X"))

    def test_stream_byte_changes_with_key_state(self):
        """Different key states should produce different stream
        bytes (with extremely rare coincidental equality)."""
        keys = _init_keys(b"infected")
        s1 = _stream_byte(keys)
        _update_keys(keys, ord("A"))
        s2 = _stream_byte(keys)
        self.assertNotEqual(s1, s2)


class EncryptTests(unittest.TestCase):
    """The encrypt primitive."""

    def test_encrypt_empty_returns_empty(self):
        keys = _init_keys(b"infected")
        self.assertEqual(_encrypt(b"", keys), b"")

    def test_encrypt_returns_same_length(self):
        keys = _init_keys(b"infected")
        plain = b"Hello, world!\n"
        cipher = _encrypt(plain, keys)
        self.assertEqual(len(plain), len(cipher))

    def test_encrypt_changes_input(self):
        keys = _init_keys(b"infected")
        plain = b"a" * 100
        cipher = _encrypt(plain, keys)
        self.assertNotEqual(plain, cipher)

    def test_encrypt_is_deterministic_given_keys(self):
        """Encrypting the same plaintext with the same fresh keys
        twice yields the same ciphertext."""
        plain = b"deterministic test vector for ZipCrypto"
        c1 = _encrypt(plain, _init_keys(b"infected"))
        c2 = _encrypt(plain, _init_keys(b"infected"))
        self.assertEqual(c1, c2)

    def test_different_passwords_yield_different_ciphertext(self):
        plain = b"cross-password test"
        c1 = _encrypt(plain, _init_keys(b"infected"))
        c2 = _encrypt(plain, _init_keys(b"malware"))
        self.assertNotEqual(c1, c2)
        self.assertNotEqual(c1, plain)
        self.assertNotEqual(c2, plain)

    def test_encrypt_advances_keys(self):
        """Encrypting twice with the SAME key list (no re-init)
        produces two different ciphertext blocks because the keys
        have advanced."""
        keys = _init_keys(b"infected")
        block = b"X" * 16
        c1 = _encrypt(block, keys)
        c2 = _encrypt(block, keys)
        self.assertNotEqual(c1, c2)


# =============================================================================
# DOS time/date encoding
# =============================================================================

class DosTimeDateTests(unittest.TestCase):

    def test_known_value(self):
        dt = datetime(2026, 4, 29, 18, 46, 18, tzinfo=timezone.utc)
        time, date = _to_dos_time_date(dt)
        self.assertEqual(time, (18 << 11) | (46 << 5) | (18 // 2))
        self.assertEqual(date, ((2026 - 1980) << 9) | (4 << 5) | 29)

    def test_pre_1980_clamped(self):
        dt = datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        time, date = _to_dos_time_date(dt)
        self.assertEqual(time, 0)
        self.assertEqual(date, (1 << 5) | 1)

    def test_max_representable_year(self):
        dt = datetime(2107, 12, 31, 23, 59, 58, tzinfo=timezone.utc)
        time, date = _to_dos_time_date(dt)
        self.assertEqual(time, (23 << 11) | (59 << 5) | (58 // 2))
        self.assertEqual(date, ((2107 - 1980) << 9) | (12 << 5) | 31)

    def test_seconds_truncated_to_two_second_resolution(self):
        dt = datetime(2026, 1, 1, 12, 30, 45, tzinfo=timezone.utc)
        time, _ = _to_dos_time_date(dt)
        # 45 // 2 = 22 (representing 44 seconds)
        self.assertEqual(time & 0x1F, 22)


# =============================================================================
# Round-trip via Python's zipfile module
# =============================================================================

class RoundTripBasicTests(unittest.TestCase):
    """Write our archive, read with zipfile.ZipFile."""

    def test_single_text_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            content = b"Hello, world!\n"
            write_encrypted_zip(path, [("hello.txt", content)])

            with zipfile.ZipFile(path, "r") as zf:
                zf.setpassword(b"infected")
                self.assertEqual(zf.namelist(), ["hello.txt"])
                self.assertEqual(zf.read("hello.txt"), content)

    def test_multiple_entries_preserve_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            entries = [
                ("a.txt", b"A content\n"),
                ("b.txt", b"B content\n"),
                ("c.txt", b"C content\n"),
            ]
            write_encrypted_zip(path, entries)

            with zipfile.ZipFile(path, "r") as zf:
                zf.setpassword(b"infected")
                self.assertEqual(
                    zf.namelist(),
                    ["a.txt", "b.txt", "c.txt"],
                )
                for name, content in entries:
                    self.assertEqual(zf.read(name), content)

    def test_empty_content_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            write_encrypted_zip(path, [("empty.txt", b"")])

            with zipfile.ZipFile(path, "r") as zf:
                zf.setpassword(b"infected")
                self.assertEqual(zf.read("empty.txt"), b"")

    def test_subdirectory_in_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            entries = [
                ("subdir/report.txt", b"report"),
                ("subdir/iocs.txt", b"iocs"),
            ]
            write_encrypted_zip(path, entries)

            with zipfile.ZipFile(path, "r") as zf:
                zf.setpassword(b"infected")
                self.assertEqual(
                    sorted(zf.namelist()),
                    ["subdir/iocs.txt", "subdir/report.txt"],
                )
                self.assertEqual(
                    zf.read("subdir/report.txt"), b"report",
                )
                self.assertEqual(
                    zf.read("subdir/iocs.txt"), b"iocs",
                )

    def test_backslash_in_name_normalized_to_forward_slash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            write_encrypted_zip(
                path, [("subdir\\file.txt", b"content")],
            )

            with zipfile.ZipFile(path, "r") as zf:
                zf.setpassword(b"infected")
                self.assertEqual(zf.namelist(), ["subdir/file.txt"])

    def test_unicode_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            write_encrypted_zip(path, [("café.txt", b"contents")])

            with zipfile.ZipFile(path, "r") as zf:
                zf.setpassword(b"infected")
                self.assertEqual(zf.namelist(), ["café.txt"])
                self.assertEqual(zf.read("café.txt"), b"contents")

    def test_large_compressible_content(self):
        # 1 MB of compressible data round-trips correctly.
        block = b"The quick brown fox jumps over the lazy dog.\n"
        content = (block * (1024 * 1024 // len(block) + 1))[:1024 * 1024]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            write_encrypted_zip(path, [("large.txt", content)])

            with zipfile.ZipFile(path, "r") as zf:
                zf.setpassword(b"infected")
                self.assertEqual(zf.read("large.txt"), content)

    def test_incompressible_content(self):
        """Random bytes; deflate may produce output >= input.
        Archive must still be valid."""
        content = _secrets.token_bytes(8192)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            write_encrypted_zip(path, [("random.bin", content)])

            with zipfile.ZipFile(path, "r") as zf:
                zf.setpassword(b"infected")
                self.assertEqual(zf.read("random.bin"), content)


class RoundTripPasswordTests(unittest.TestCase):

    def test_default_password_is_infected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            write_encrypted_zip(path, [("file.txt", b"content")])

            with zipfile.ZipFile(path, "r") as zf:
                zf.setpassword(b"infected")
                self.assertEqual(zf.read("file.txt"), b"content")

    def test_custom_password_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            write_encrypted_zip(
                path,
                [("file.txt", b"content")],
                password="hunter2",
            )

            with zipfile.ZipFile(path, "r") as zf:
                zf.setpassword(b"hunter2")
                self.assertEqual(zf.read("file.txt"), b"content")

    def test_wrong_password_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            write_encrypted_zip(path, [("file.txt", b"content")])

            with zipfile.ZipFile(path, "r") as zf:
                zf.setpassword(b"wrong-password")
                with self.assertRaises(RuntimeError):
                    zf.read("file.txt")

    def test_long_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            password = "x" * 1024
            write_encrypted_zip(
                path, [("file.txt", b"content")], password=password,
            )

            with zipfile.ZipFile(path, "r") as zf:
                zf.setpassword(password.encode("ascii"))
                self.assertEqual(zf.read("file.txt"), b"content")


class RoundTripCompressionTests(unittest.TestCase):

    def test_deflate_default_actually_compresses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            content = b"compressible " * 1000
            write_encrypted_zip(path, [("file.txt", content)])

            with zipfile.ZipFile(path, "r") as zf:
                info = zf.getinfo("file.txt")
                self.assertEqual(
                    info.compress_type, zipfile.ZIP_DEFLATED,
                )
                # +12 for encryption header overhead. Deflate of
                # this highly repetitive input should beat raw.
                self.assertLess(
                    info.compress_size - 12, len(content),
                )

    def test_stored_compression(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            content = b"stored content\n"
            write_encrypted_zip(
                path,
                [("file.txt", content)],
                compression="stored",
            )

            with zipfile.ZipFile(path, "r") as zf:
                info = zf.getinfo("file.txt")
                self.assertEqual(
                    info.compress_type, zipfile.ZIP_STORED,
                )
                # Stored: compressed size equals plaintext size + 12.
                self.assertEqual(
                    info.compress_size, len(content) + 12,
                )
                zf.setpassword(b"infected")
                self.assertEqual(zf.read("file.txt"), content)


class RoundTripFilesystemTests(unittest.TestCase):

    def test_creates_parent_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deep" / "nested" / "test.zip"
            self.assertFalse(path.parent.exists())

            write_encrypted_zip(path, [("file.txt", b"content")])

            self.assertTrue(path.exists())
            self.assertTrue(path.parent.is_dir())

    def test_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            path.write_bytes(b"placeholder content")

            write_encrypted_zip(path, [("file.txt", b"new content")])

            with zipfile.ZipFile(path, "r") as zf:
                zf.setpassword(b"infected")
                self.assertEqual(zf.read("file.txt"), b"new content")


# =============================================================================
# Error paths
# =============================================================================

class ErrorPathTests(unittest.TestCase):

    def test_empty_entries_list_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            with self.assertRaises(ValueError) as cm:
                write_encrypted_zip(path, [])
            self.assertIn("empty", str(cm.exception).lower())

    def test_unknown_compression_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            with self.assertRaises(ValueError) as cm:
                write_encrypted_zip(
                    path, [("f.txt", b"x")], compression="bzip2",
                )
            self.assertIn("compression", str(cm.exception).lower())

    def test_empty_filename_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            with self.assertRaises(ValueError) as cm:
                write_encrypted_zip(path, [("", b"x")])
            self.assertIn("name", str(cm.exception).lower())

    def test_filename_with_null_byte_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            with self.assertRaises(ValueError) as cm:
                write_encrypted_zip(path, [("a\x00b", b"x")])
            self.assertIn("null", str(cm.exception).lower())

    def test_non_ascii_password_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            with self.assertRaises(ValueError) as cm:
                write_encrypted_zip(
                    path, [("f.txt", b"x")], password="café",
                )
            self.assertIn("ascii", str(cm.exception).lower())

    def test_failure_after_partial_validation_does_not_create_file(self):
        """If the second entry fails validation, no archive is
        created on disk."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            with self.assertRaises(ValueError):
                write_encrypted_zip(path, [
                    ("good.txt", b"content"),
                    ("\x00bad.txt", b"content"),
                ])
            self.assertFalse(path.exists())


# =============================================================================
# Wire-format details
# =============================================================================

class WireFormatTests(unittest.TestCase):
    """Verify specific bytes in the produced archive."""

    def _write_simple_archive(
        self,
        tmp: str,
        name: str = "f.txt",
        content: bytes = b"x",
        compression: str = "deflate",
    ) -> bytes:
        path = Path(tmp) / "test.zip"
        write_encrypted_zip(
            path, [(name, content)], compression=compression,
        )
        return path.read_bytes()

    def test_starts_with_lfh_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = self._write_simple_archive(tmp)
            sig = struct.unpack("<I", data[0:4])[0]
            self.assertEqual(sig, _SIG_LFH)

    def test_contains_eocd_signature_at_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = self._write_simple_archive(tmp)
            # EOCD with no comment is the last 22 bytes.
            sig = struct.unpack("<I", data[-22:-18])[0]
            self.assertEqual(sig, _SIG_EOCD)

    def test_lfh_has_encrypted_flag_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = self._write_simple_archive(tmp)
            flag = struct.unpack("<H", data[6:8])[0]
            self.assertTrue(flag & _FLAG_ENCRYPTED)

    def test_lfh_has_utf8_flag_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = self._write_simple_archive(tmp)
            flag = struct.unpack("<H", data[6:8])[0]
            self.assertTrue(flag & _FLAG_UTF8)

    def test_compressed_size_includes_encryption_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = b"x" * 100
            data = self._write_simple_archive(
                tmp, content=content, compression="stored",
            )
            comp_size = struct.unpack("<I", data[18:22])[0]
            self.assertEqual(comp_size, 100 + 12)

    def test_uncompressed_size_in_lfh_is_correct(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = b"x" * 12345
            data = self._write_simple_archive(tmp, content=content)
            uncomp_size = struct.unpack("<I", data[22:26])[0]
            self.assertEqual(uncomp_size, 12345)

    def test_lfh_crc32_matches_plaintext_crc(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = b"specific content for CRC verification"
            data = self._write_simple_archive(tmp, content=content)
            stored_crc = struct.unpack("<I", data[14:18])[0]
            expected_crc = zlib.crc32(content) & 0xFFFFFFFF
            self.assertEqual(stored_crc, expected_crc)


class CDHConsistencyTests(unittest.TestCase):
    """Central directory header must agree with local file header."""

    def _read_lfh_and_cdh(
        self, data: bytes, name_len: int,
    ) -> tuple[bytes, bytes]:
        """Extract LFH and CDH bytes from a single-entry archive."""
        lfh = data[: 30 + name_len]
        idx = data.find(struct.pack("<I", _SIG_CDH))
        cdh = data[idx : idx + 46 + name_len]
        return lfh, cdh

    def test_cdh_crc_matches_lfh(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            write_encrypted_zip(path, [("f.txt", b"content")])
            data = path.read_bytes()
            lfh, cdh = self._read_lfh_and_cdh(data, len(b"f.txt"))

            lfh_crc = struct.unpack("<I", lfh[14:18])[0]
            cdh_crc = struct.unpack("<I", cdh[16:20])[0]
            self.assertEqual(lfh_crc, cdh_crc)

    def test_cdh_filename_matches_lfh(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            write_encrypted_zip(path, [("hello.txt", b"content")])
            data = path.read_bytes()
            name_len = len(b"hello.txt")
            lfh, cdh = self._read_lfh_and_cdh(data, name_len)

            lfh_name = lfh[30 : 30 + name_len]
            cdh_name = cdh[46 : 46 + name_len]
            self.assertEqual(lfh_name, cdh_name)
            self.assertEqual(lfh_name, b"hello.txt")

    def test_cdh_compressed_size_matches_lfh(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            write_encrypted_zip(
                path, [("f.txt", b"x" * 100)], compression="stored",
            )
            data = path.read_bytes()
            lfh, cdh = self._read_lfh_and_cdh(data, len(b"f.txt"))

            lfh_size = struct.unpack("<I", lfh[18:22])[0]
            cdh_size = struct.unpack("<I", cdh[20:24])[0]
            self.assertEqual(lfh_size, cdh_size)


# =============================================================================
# External unzip round-trip (gated)
# =============================================================================

@unittest.skipUnless(
    shutil.which("unzip"),
    "unzip command not available on this system",
)
class ExternalUnzipTests(unittest.TestCase):
    """Round-trip via the system unzip command.

    These tests run only when `unzip` is on PATH. They verify
    interoperability with the most common reference implementation
    of the ZIP format outside Python itself.
    """

    def test_unzip_extracts_correct_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = tmp_path / "test.zip"
            content = b"External unzip test content\n"
            write_encrypted_zip(archive, [("file.txt", content)])

            extract_dir = tmp_path / "out"
            extract_dir.mkdir()
            result = subprocess.run(
                [
                    "unzip", "-P", "infected",
                    "-d", str(extract_dir),
                    str(archive),
                ],
                capture_output=True,
            )
            self.assertEqual(
                result.returncode, 0,
                msg=f"unzip failed: {result.stderr.decode(errors='replace')}",
            )

            extracted = (extract_dir / "file.txt").read_bytes()
            self.assertEqual(extracted, content)

    def test_unzip_test_command_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "test.zip"
            write_encrypted_zip(
                archive,
                [("a.txt", b"A"), ("b.txt", b"B" * 1000)],
            )

            result = subprocess.run(
                ["unzip", "-P", "infected", "-t", str(archive)],
                capture_output=True,
            )
            self.assertEqual(
                result.returncode, 0,
                msg=f"unzip -t failed: {result.stderr.decode(errors='replace')}",
            )

    def test_unzip_rejects_wrong_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "test.zip"
            write_encrypted_zip(archive, [("file.txt", b"content")])

            result = subprocess.run(
                ["unzip", "-P", "wrongpw", "-t", str(archive)],
                capture_output=True,
            )
            # unzip returns non-zero when password is wrong.
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()