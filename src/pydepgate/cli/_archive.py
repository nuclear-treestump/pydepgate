"""pydepgate.cli._archive

ZipCrypto archive writer for pydepgate.

This module produces single-archive ZIP files encrypted with the
ZipCrypto algorithm, the original PKZIP encryption format documented
in PKWARE APPNOTE.TXT section 6.1. The default password is "infected",
which is the de-facto convention in the malware research community
for archived samples; AV vendors and analysis tools recognize this
convention and skip scanning archive contents.

The driving use case in pydepgate is the decoded-payload report
artifact: a forensic deliverable that contains decoded malware
source code as ordinary text. Writing such a file as plaintext
on Windows triggers Defender quarantine on signature pattern match.
Wrapping it in a ZipCrypto archive with the password "infected"
defeats this scan because Defender (and every other major AV) does
not attempt to decrypt password-protected archives.

SECURITY DISCLAIMER:
ZipCrypto is cryptographically broken. A known-plaintext attack
with five known plaintext bytes recovers the keys in seconds, and
the encryption header is largely guessable. This module uses
ZipCrypto for two reasons only:

  1. AV vendor recognition of the "infected" archive convention as
     a do-not-scan marker, preventing false-positive quarantine of
     forensic reports that contain malware source code.
  2. A high-friction barrier preventing casual double-click
     execution of malware source by curious users.

Do NOT reuse this code for actual confidentiality. The cipher is
used here because the malware research community uses it; not
because it is secure.

Public surface:
    write_encrypted_zip(path, entries, *, password, compression)
"""

from __future__ import annotations

import io
import secrets
import struct
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# ZIP format constants
# ---------------------------------------------------------------------------

# Record signatures: little-endian "PK" plus a record type marker.
_SIG_LFH  = 0x04034B50  # PK\x03\x04, local file header
_SIG_CDH  = 0x02014B50  # PK\x01\x02, central directory header
_SIG_EOCD = 0x06054B50  # PK\x05\x06, end of central directory

# General purpose bit flag bits (ZIP APPNOTE 4.4.4).
_FLAG_ENCRYPTED = 0x0001  # bit 0: file is encrypted
_FLAG_UTF8      = 0x0800  # bit 11: filename is UTF-8

# Compression methods (ZIP APPNOTE 4.4.5).
_METHOD_STORED   = 0
_METHOD_DEFLATED = 8

# ZIP version markers. 2.0 is the floor for non-trivial features
# (subdirectories, deflate, ZipCrypto). We do not use anything that
# requires a higher version, so we declare 2.0 and stay within its
# guarantees.
_VERSION_NEEDED  = 20
_VERSION_MADE_BY = 20  # high byte 0 = MS-DOS host, low byte 20 = 2.0


# ---------------------------------------------------------------------------
# CRC-32 byte-update table
# ---------------------------------------------------------------------------
#
# The standard IEEE 802.3 CRC-32 polynomial in reversed representation.
# Used both for ZIP file checksums and for the ZipCrypto key updates.
# We need our own per-byte update primitive because the ZipCrypto key
# update is one byte at a time and zlib does not expose a single-byte
# update entry point.

_CRC_POLY = 0xEDB88320


def _make_crc_table() -> list[int]:
    """Build the byte-indexed CRC-32 table at import time."""
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            if c & 1:
                c = (c >> 1) ^ _CRC_POLY
            else:
                c >>= 1
        table.append(c)
    return table


_CRC_TABLE = _make_crc_table()


def _crc_update(crc: int, byte: int) -> int:
    """Single-byte CRC-32 running-state update.

    Returns the running CRC (no final XOR with 0xFFFFFFFF). Equivalent
    to the inner loop of zlib.crc32 over a one-byte input.
    """
    return (crc >> 8) ^ _CRC_TABLE[(crc ^ byte) & 0xFF]


# ---------------------------------------------------------------------------
# ZipCrypto cipher
# ---------------------------------------------------------------------------
#
# Three uint32 keys with hard-coded initial values from the PKWARE
# specification. Each plaintext byte advances the key state via
# _update_keys; each ciphertext byte is produced by XORing with one
# byte of keystream derived from key 2 via _stream_byte. Encryption
# and decryption are symmetric XOR, but the key update uses the
# PLAINTEXT byte in both directions, so encrypt and decrypt produce
# different key trajectories on the same input.

_KEY0_INIT = 0x12345678
_KEY1_INIT = 0x23456789
_KEY2_INIT = 0x34567890

# Magic constant from Knuth, used in the key 1 update step. No
# derivation; this value is part of the spec.
_KEY1_MULT = 134775813


def _init_keys(password: bytes) -> list[int]:
    """Initialize the three ZipCrypto keys from password bytes.

    Keys start at fixed values and are updated by feeding each
    password byte through _update_keys. An empty password leaves
    the keys at their initial values (which is technically valid
    but produces a near-trivial cipher; do not do this).
    """
    keys = [_KEY0_INIT, _KEY1_INIT, _KEY2_INIT]
    for b in password:
        _update_keys(keys, b)
    return keys


def _update_keys(keys: list[int], byte: int) -> None:
    """Advance the key state by one byte. Mutates keys in place.

    Subtleties to note:
      - keys[0] gets a CRC-style update with the input byte.
      - keys[1] is incremented by the LOW byte of keys[0] AFTER its
        own update (sequencing matters), then multiplied by
        134775813 and incremented by 1.
      - keys[2] gets a CRC-style update using the HIGH byte of the
        updated keys[1].

    Every assignment is masked to 32 bits to match the spec's
    uint32 width. Forgetting any of these masks produces output
    that looks correct on short inputs and silently wrong on long
    ones.
    """
    keys[0] = _crc_update(keys[0], byte)
    keys[1] = (keys[1] + (keys[0] & 0xFF)) & 0xFFFFFFFF
    keys[1] = (keys[1] * _KEY1_MULT + 1) & 0xFFFFFFFF
    keys[2] = _crc_update(keys[2], (keys[1] >> 24) & 0xFF)


def _stream_byte(keys: list[int]) -> int:
    """Produce one byte of keystream from the current key state.

    Critical detail: the formula uses the LOW 16 BITS of keys[2],
    not the full 32. The (keys[2] & 0xFFFF) mask is load-bearing.
    Forgetting it produces correct output on short inputs (where
    keys[2] has not yet accumulated nonzero high bits) and silently
    wrong output as soon as the high bits become nonzero.
    """
    temp = (keys[2] & 0xFFFF) | 2
    return ((temp * (temp ^ 1)) >> 8) & 0xFF


def _encrypt(plain: bytes, keys: list[int]) -> bytes:
    """Encrypt plain bytes with the given key state. Mutates keys.

    The keystream byte and the key state both advance using the
    PLAINTEXT byte, not the ciphertext. Decryption reverses this:
    the recipient uses the decrypted plaintext byte to advance
    their key state, which is why the cipher is called symmetric
    even though encrypt and decrypt have asymmetric internal
    sequencing.
    """
    out = bytearray(len(plain))
    for i, b in enumerate(plain):
        out[i] = b ^ _stream_byte(keys)
        _update_keys(keys, b)
    return bytes(out)


# ---------------------------------------------------------------------------
# DOS date/time encoding
# ---------------------------------------------------------------------------

def _to_dos_time_date(dt: datetime) -> tuple[int, int]:
    """Convert a datetime to packed (dos_time, dos_date) 16-bit values.

    DOS time word layout:
        bits 11-15: hours (0-23)
        bits 5-10:  minutes (0-59)
        bits 0-4:   seconds / 2 (0-29; DOS time has 2-second resolution)

    DOS date word layout:
        bits 9-15: year - 1980 (0-127)
        bits 5-8:  month (1-12)
        bits 0-4:  day (1-31)

    Datetimes before 1980-01-01 are clamped to that date because
    DOS cannot represent earlier dates. This matters in practice
    when users have system clocks set wrong or when archives are
    built in sandboxes with epoch-fixed clocks.
    """
    if dt.year < 1980:
        return (0, (1 << 5) | 1)  # 1980-01-01 00:00:00
    dos_time = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    dos_date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    return dos_time, dos_date


def _dos_now() -> tuple[int, int]:
    """Return the current UTC time as (dos_time, dos_date)."""
    return _to_dos_time_date(datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Internal entry preparation
# ---------------------------------------------------------------------------

@dataclass
class _PreparedEntry:
    """One entry, fully encrypted and ready to write.

    Mutable rather than frozen because the LFH offset is not known
    until we begin writing; we set it during the write loop. The
    rest of the fields are fixed at preparation time.
    """
    name_bytes: bytes
    method: int
    crc32: int
    compressed_size: int       # includes the 12-byte encryption header
    uncompressed_size: int
    encrypted_payload: bytes   # encryption header + (compressed | stored) data
    dos_time: int
    dos_date: int
    lfh_offset: int = 0


def _prepare_entry(
    *,
    name: str,
    content: bytes,
    method: int,
    password_bytes: bytes,
    dos_time: int,
    dos_date: int,
) -> _PreparedEntry:
    """Compute everything needed to write one entry.

    Validates the entry name, computes the CRC-32 of the plaintext,
    applies compression if requested, generates the 12-byte
    encryption header (11 random bytes plus the CRC high byte as a
    verification value), and encrypts header-plus-data with a single
    continuous ZipCrypto keystream.

    Raises ValueError on invalid input.
    """
    # Normalize path separators and validate the name.
    name_normalized = name.replace("\\", "/")
    if not name_normalized:
        raise ValueError("entry name cannot be empty")
    if "\x00" in name_normalized:
        raise ValueError(
            f"entry name contains null byte: {name!r}"
        )

    name_bytes = name_normalized.encode("utf-8")
    if len(name_bytes) > 0xFFFF:
        raise ValueError(
            f"entry name too long for ZIP local file header: "
            f"{len(name_bytes)} bytes (max 65535)"
        )

    # CRC-32 of the original (uncompressed, unencrypted) content.
    # zlib.crc32 returns the unsigned final CRC (with the standard
    # 0xFFFFFFFF XOR applied); the explicit mask is documentation.
    crc32 = zlib.crc32(content) & 0xFFFFFFFF

    # Compress (or store) the file content.
    if method == _METHOD_DEFLATED:
        compressor = zlib.compressobj(
            level=6,
            method=zlib.DEFLATED,
            wbits=-15,  # raw deflate, no zlib header or trailer
        )
        compressed = compressor.compress(content) + compressor.flush()
    elif method == _METHOD_STORED:
        compressed = content
    else:
        raise ValueError(
            f"unsupported compression method: {method}"
        )

    # Build the 12-byte encryption header.
    #   bytes 0..10: random padding. ZipCrypto does not require
    #     cryptographic randomness here, but using secrets.token_bytes
    #     is the right hygiene for any byte we generate.
    #   byte 11: high-order byte of the file's CRC-32, used by
    #     readers as a fast password-check before processing the
    #     decrypted file body.
    header_plain = secrets.token_bytes(11) + bytes([(crc32 >> 24) & 0xFF])

    # Initialize keys from the password and encrypt header-then-body
    # with a single continuous keystream.
    keys = _init_keys(password_bytes)
    encrypted_header = _encrypt(header_plain, keys)
    encrypted_body = _encrypt(compressed, keys)
    encrypted_payload = encrypted_header + encrypted_body

    return _PreparedEntry(
        name_bytes=name_bytes,
        method=method,
        crc32=crc32,
        compressed_size=12 + len(compressed),
        uncompressed_size=len(content),
        encrypted_payload=encrypted_payload,
        dos_time=dos_time,
        dos_date=dos_date,
    )


# ---------------------------------------------------------------------------
# ZIP record builders
# ---------------------------------------------------------------------------

def _build_lfh(entry: _PreparedEntry) -> bytes:
    """Build a Local File Header. Returns 30 + len(name) bytes."""
    flag = _FLAG_ENCRYPTED | _FLAG_UTF8
    return struct.pack(
        "<IHHHHHIIIHH",
        _SIG_LFH,
        _VERSION_NEEDED,
        flag,
        entry.method,
        entry.dos_time,
        entry.dos_date,
        entry.crc32,
        entry.compressed_size,
        entry.uncompressed_size,
        len(entry.name_bytes),
        0,  # extra field length
    ) + entry.name_bytes


def _build_cdh(entry: _PreparedEntry) -> bytes:
    """Build a Central Directory Header. Returns 46 + len(name) bytes.

    Must agree with the matching LFH on every shared field. We share
    name_bytes by reference; do NOT re-encode the filename here.
    A re-encode that produces even one different byte (different
    normalization, different separator) is the kind of mismatch that
    strict unzippers reject as "central directory mismatch."
    """
    flag = _FLAG_ENCRYPTED | _FLAG_UTF8
    return struct.pack(
        "<IHHHHHHIIIHHHHHII",
        _SIG_CDH,
        _VERSION_MADE_BY,
        _VERSION_NEEDED,
        flag,
        entry.method,
        entry.dos_time,
        entry.dos_date,
        entry.crc32,
        entry.compressed_size,
        entry.uncompressed_size,
        len(entry.name_bytes),
        0,  # extra field length
        0,  # file comment length
        0,  # disk number where file starts
        0,  # internal file attributes
        0,  # external file attributes
        entry.lfh_offset,
    ) + entry.name_bytes


def _build_eocd(
    *,
    cd_size: int,
    cd_offset: int,
    entry_count: int,
) -> bytes:
    """Build the End of Central Directory Record. Returns 22 bytes."""
    if entry_count > 0xFFFF:
        raise ValueError(
            f"too many entries for non-zip64 archive: "
            f"{entry_count} (max 65535)"
        )
    return struct.pack(
        "<IHHHHIIH",
        _SIG_EOCD,
        0,            # this disk number
        0,            # disk where central directory starts
        entry_count,  # CD records on this disk
        entry_count,  # total CD records across all disks
        cd_size,
        cd_offset,
        0,            # archive comment length
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_encrypted_zip(
    path: Path,
    entries: list[tuple[str, bytes]],
    *,
    password: str = "infected",
    compression: str = "deflate",
) -> None:
    """Write a ZipCrypto-encrypted ZIP archive to disk.

    Args:
        path: Output path. Parent directories are created as needed.
        entries: List of (name, content) tuples. Each name is
            interpreted as a POSIX-style path inside the archive;
            backslashes are normalized to forward slashes. Names
            must be non-empty, must not contain null bytes, and
            must encode to <= 65535 bytes as UTF-8.
        password: Encryption password. Must be ASCII. Defaults to
            "infected" per the malware-research convention.
        compression: "deflate" (default) or "stored".

    Raises:
        ValueError: if entries is empty, an entry name is invalid,
            the password is non-ASCII, or compression is not one
            of the supported values. All validation happens before
            any disk write, so a failure leaves no partial archive
            on disk.
        OSError: if the file or its parent directories cannot be
            written.

    Format notes:
        - Single-disk archive (no zip64).
        - Real-time UTC mtime is written into headers; archives
          are intentionally not byte-reproducible across runs.
        - General purpose flag has both the encrypted bit and the
          UTF-8 filename bit set.
        - Archives produced by this function are readable by
          Python's zipfile module (with setpassword), unzip, 7-Zip,
          and recent macOS Archive Utility versions.
        - Windows Explorer's built-in ZIP viewer cannot open
          encrypted archives at all. Users will need 7-Zip or
          similar. This is documented behavior, not a bug, and
          is arguably a feature: a curious user double-clicking
          the file does not get a free preview of the malware
          source.
    """
    if not entries:
        raise ValueError("entries cannot be empty")

    if compression == "deflate":
        method = _METHOD_DEFLATED
    elif compression == "stored":
        method = _METHOD_STORED
    else:
        raise ValueError(
            f"unknown compression mode: {compression!r}; "
            f"expected 'deflate' or 'stored'"
        )

    try:
        password_bytes = password.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"password must be ASCII; got non-ASCII characters at "
            f"position {exc.start}"
        ) from None

    dos_time, dos_date = _dos_now()

    # Prepare every entry before doing any writing. Doing this up
    # front means a validation error on entry N+1 cannot leave a
    # half-written file on disk. Memory cost is bounded by the
    # entries list size, which is the caller's contract.
    prepared: list[_PreparedEntry] = [
        _prepare_entry(
            name=name,
            content=content,
            method=method,
            password_bytes=password_bytes,
            dos_time=dos_time,
            dos_date=dos_date,
        )
        for name, content in entries
    ]

    # Assemble the archive in memory. Doing this in a buffer rather
    # than streaming to disk simplifies offset bookkeeping and makes
    # it impossible to leave a partial file on disk if anything
    # raises during assembly.
    buf = io.BytesIO()

    # Local file headers and encrypted payloads.
    for entry in prepared:
        entry.lfh_offset = buf.tell()
        buf.write(_build_lfh(entry))
        buf.write(entry.encrypted_payload)

    # Central directory.
    cd_offset = buf.tell()
    for entry in prepared:
        buf.write(_build_cdh(entry))
    cd_size = buf.tell() - cd_offset

    # End of central directory record.
    buf.write(_build_eocd(
        cd_size=cd_size,
        cd_offset=cd_offset,
        entry_count=len(prepared),
    ))

    # One write to disk delivers the whole archive. write_bytes
    # opens with mode "wb" which truncates atomically on POSIX;
    # on Windows it is close to atomic but not guaranteed. For
    # the small archives this module produces, the difference is
    # immaterial.
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(buf.getvalue())