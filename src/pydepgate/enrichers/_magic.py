"""
Format detection for the payload_peek enricher.

This module provides three things:

1. `detect_format(data)` returns a `FormatDetection` describing what
   the input looks like. Inputs may be `str` (text-shaped, candidate
   for base64 or hex decoding) or `bytes` (candidate for binary
   format magic, or for ASCII-decode-then-text-encoding fallback).

2. Per-format magic-byte and alphabet predicates exposed individually
   for unit-testability. Each predicate is a pure function over its
   input and a small constant.

3. `scan_indicators(data)` returns a tuple of "interesting strings"
   found in the decoded final layer, e.g. `subprocess`, `urllib`,
   `os.system`. This converts a raw "this is base64-encoded Python"
   finding into "this is base64-encoded Python that imports
   subprocess and calls urllib," which is the actual triage data
   an analyst wants.

Detection priority within a single layer
----------------------------------------
1. Text encodings: base64 alphabet, pure-hex alphabet,
   `0x`-prefixed comma-or-space-separated hex list.
2. Binary compression formats by magic bytes: zlib, gzip, bzip2,
   lzma/xz.
3. Terminal binary classifications: pickle, PE, ELF, PNG, zip.
4. ASCII-Python heuristic on the decoded form.
5. Otherwise, terminal `binary_unknown` or `ascii_text`.

Why text first: the outer wrapper of every real-world chained
payload I have evidence for is a text encoding (base64 most often,
hex sometimes). Going binary-first risks treating ASCII bytes whose
first two characters happen to coincide with `0x78 0x01` (the zlib
"low compression" header — both are valid base64 alphabet chars) as
zlib data and trying to decompress them, which would either fail
or produce garbage.

Pickle handling
---------------
Pickle data IS code execution on `pickle.loads()`. Detection here
results in a terminal classification with `pickle_warning=True`;
the unwrap loop never calls `pickle.loads`. Defenders see
"WARNING: payload is Python pickle" and can decide to inspect it
in an isolated environment.

This module never executes, never imports, never compiles any
input. The only operations are byte comparison, regex matching,
and ASCII decoding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# How many initial bytes/chars we examine for terminal classification
# heuristics (Python source detection, indicator scanning).
_INSPECTION_HEAD_BYTES = 2048


# ---------------------------------------------------------------------------
# Magic-byte tables
# ---------------------------------------------------------------------------

# zlib has 32 valid first-2-byte combinations across compression levels
# and dictionary flags. The four below cover ~99% of real samples.
# Source: RFC 1950, plus empirical observation of attack samples.
_ZLIB_MAGIC = (
    b"\x78\x01",  # no/low compression
    b"\x78\x5e",  # default compression (less common but seen in malware)
    b"\x78\x9c",  # default compression (most common)
    b"\x78\xda",  # best compression
)

_GZIP_MAGIC = b"\x1f\x8b\x08"          # gzip RFC 1952; third byte is method
_BZIP2_MAGIC = b"BZh"                   # "BZh" + level digit
_LZMA_MAGIC = b"\xfd\x37\x7a\x58\x5a\x00"  # xz format; raw LZMA1 has no magic

_PE_MAGIC = b"MZ"                       # DOS executable / PE wrapper
_ELF_MAGIC = b"\x7fELF"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_ZIP_MAGIC = b"PK\x03\x04"              # zip / wheel / jar / etc.

# Pickle protocol 2-5 starts with PROTO opcode + version byte.
# Protocol 0/1 start with various opcodes and are harder to fingerprint
# unambiguously; 0x80 catches the modern ones, which is what malware
# generally uses.
_PICKLE_PROTO_BYTE = b"\x80"


# ---------------------------------------------------------------------------
# Text-encoding alphabets and shapes
# ---------------------------------------------------------------------------

# Standard + URL-safe base64. Padding char included.
_BASE64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/=-_"
)
_HEX_ALPHABET = frozenset("0123456789abcdefABCDEF")

# Tokens for the `0x`-list shape, e.g. "0x4d, 0x5a, 0x90".
_HEX_0X_TOKEN_RE = re.compile(r"^0x[0-9a-fA-F]{1,2}$")
_HEX_0X_LIST_SPLITTER = re.compile(r"[,\s]+")


# Minimum lengths for each text encoding to be considered a meaningful
# encoded payload. Below these we don't bother attempting the decode
# because the result is too small to identify anything (a 4-byte magic
# header is the floor).
_MIN_BASE64_CHARS = 16   # 16 b64 chars -> 12 bytes
_MIN_HEX_CHARS = 16      # 16 hex chars -> 8 bytes
_MIN_HEX_0X_TOKENS = 8   # 8 tokens -> 8 bytes


# ---------------------------------------------------------------------------
# Indicator strings for ASCII Python content
# ---------------------------------------------------------------------------

# When the unwrap loop terminates with python_source or ascii_text,
# we scan the bytes for these substrings. Their presence converts
# "encoded Python" into "encoded Python that does these specific
# things." Order matters only for stable test output; we report
# matches in encounter order.
_INDICATOR_KEYWORDS = (
    "subprocess",
    "socket",
    "urllib",
    "requests",
    "os.system",
    "os.popen",
    "shutil.rmtree",
    "eval(",
    "exec(",
    "compile(",
    "__import__",
    "base64.b64decode",
    "binascii.unhexlify",
    "zlib.decompress",
    "marshal.loads",
    "pickle.loads",
    "ctypes",
    "/etc/passwd",
    "/etc/shadow",
    ".ssh/id_rsa",
    "AWS_SECRET",
    "AWS_ACCESS_KEY",
    "DISCORD_TOKEN",
    "wget ",
    "curl ",
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FormatDetection:
    """What detect_format() decided about an input.

    Attributes:
        kind: A short identifier. For non-terminal cases this names
            the transformation to apply ("base64", "zlib", etc.).
            For terminal cases this names the final classification
            ("python_source", "pickle_data", "binary_unknown", etc.).
        is_terminal: True when no further unwrap should be attempted
            on this input. Terminal inputs may still be inspected
            for indicator strings, but no decode/decompress runs.
    """
    kind: str
    is_terminal: bool


# ---------------------------------------------------------------------------
# Binary magic predicates
# ---------------------------------------------------------------------------

def is_zlib(data: bytes) -> bool:
    return any(data.startswith(magic) for magic in _ZLIB_MAGIC)


def is_gzip(data: bytes) -> bool:
    return data.startswith(_GZIP_MAGIC)


def is_bzip2(data: bytes) -> bool:
    # "BZh" + a level digit '1' through '9'.
    return (
        data.startswith(_BZIP2_MAGIC)
        and len(data) >= 4
        and data[3:4] in b"123456789"
    )


def is_lzma(data: bytes) -> bool:
    return data.startswith(_LZMA_MAGIC)


def is_pe(data: bytes) -> bool:
    return data.startswith(_PE_MAGIC)


def is_elf(data: bytes) -> bool:
    return data.startswith(_ELF_MAGIC)


def is_png(data: bytes) -> bool:
    return data.startswith(_PNG_MAGIC)


def is_zip(data: bytes) -> bool:
    return data.startswith(_ZIP_MAGIC)


def is_pickle(data: bytes) -> bool:
    """Detect pickle protocol 2-5 by the leading PROTO opcode.

    The byte after 0x80 is the protocol version (2, 3, 4, or 5).
    We accept any of these; protocols 0 and 1 are not detected
    here because their leading bytes are too ambiguous (matching
    plain `(` or other punctuation in legitimate text).
    """
    if not data.startswith(_PICKLE_PROTO_BYTE):
        return False
    if len(data) < 2:
        return False
    return data[1] in (0x02, 0x03, 0x04, 0x05)


# ---------------------------------------------------------------------------
# Text-encoding alphabet predicates
# ---------------------------------------------------------------------------

def is_base64(s: str) -> bool:
    """True if s looks like a base64-encoded payload.

    Criteria: minimum length, alphabet-only (after whitespace strip),
    and presence of mixed case (excludes pure-hex strings that also
    happen to be base64-alphabet-valid).
    """
    stripped = "".join(s.split())
    if len(stripped) < _MIN_BASE64_CHARS:
        return False
    if not all(c in _BASE64_ALPHABET for c in stripped):
        return False
    # Discriminator: hex strings would also match, so require some
    # base64-only character (lowercase letter, '+', '/', '-', '_')
    # to avoid claiming pure-hex content as base64.
    has_b64_specific = any(
        c in stripped
        for c in "abcdefghijklmnopqrstuvwxyz+/-_="
        if c not in _HEX_ALPHABET
    )
    if not has_b64_specific:
        # Could be hex; let is_pure_hex claim it.
        return False
    return True


def is_pure_hex(s: str) -> bool:
    """True if s is a pure-hex string (e.g. '4d5a90...')."""
    stripped = "".join(s.split())
    if len(stripped) < _MIN_HEX_CHARS:
        return False
    if len(stripped) % 2 != 0:
        return False
    return all(c in _HEX_ALPHABET for c in stripped)


def is_hex_0x_list(s: str) -> bool:
    """True if s is a list of 0x-prefixed hex bytes.

    Examples that match:
        "0x4d, 0x5a, 0x90, 0x00"
        "0x4d 0x5a 0x90 0x00"
        "0x4d,0x5a,0x90,0x00"

    Examples that do not match:
        "0x4d"            -- single token, below floor
        "4d 5a 90 00"     -- no 0x prefix (handled by is_pure_hex)
        "0x4d, 0xZZ"      -- non-hex digit
    """
    tokens = [t for t in _HEX_0X_LIST_SPLITTER.split(s.strip()) if t]
    if len(tokens) < _MIN_HEX_0X_TOKENS:
        return False
    return all(_HEX_0X_TOKEN_RE.match(t) for t in tokens)


# ---------------------------------------------------------------------------
# ASCII-Python heuristic
# ---------------------------------------------------------------------------

# Keywords whose presence near the start of an ASCII text region
# suggests Python source. The list is conservative: each token is
# fairly Python-specific and uncommon in non-Python text.
_PYTHON_HEAD_TOKENS = (
    "import ",
    "from ",
    "def ",
    "class ",
    "if __name__",
    "print(",
    "self.",
    "return ",
    "lambda ",
    "raise ",
)


def _printable_fraction(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return printable / len(text)


def looks_like_python(text: str) -> bool:
    """Heuristic: does this text region read as Python source?

    Two conditions, both required: at least one Python-specific
    token in the first 2KB, and at least 90% printable characters.
    Tuned conservatively to minimize false positives on legitimate
    ASCII content (English prose, JSON, config files), at the cost
    of missing some pathological obfuscation.
    """
    head = text[:_INSPECTION_HEAD_BYTES]
    if not head:
        return False
    has_token = any(tok in head for tok in _PYTHON_HEAD_TOKENS)
    return has_token and _printable_fraction(head) >= 0.9


def _ascii_decode_or_none(data: bytes) -> str | None:
    """Try to decode bytes as ASCII; return None on failure or if
    the result has too many non-printable chars to be plausibly
    text-encoded content."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    head = text[:_INSPECTION_HEAD_BYTES]
    if _printable_fraction(head) < 0.85:
        return None
    return text


# ---------------------------------------------------------------------------
# Top-level detection
# ---------------------------------------------------------------------------

def detect_format(data: str | bytes) -> FormatDetection:
    """Decide what `data` is. Returns a FormatDetection.

    See module docstring for the priority order. The function is
    deterministic and side-effect-free; calling it multiple times
    on the same input always returns the same result.
    """
    if isinstance(data, str):
        return _detect_str(data)
    return _detect_bytes(data)


def _detect_str(s: str) -> FormatDetection:
    if is_base64(s):
        return FormatDetection(kind="base64", is_terminal=False)
    if is_pure_hex(s):
        return FormatDetection(kind="hex", is_terminal=False)
    if is_hex_0x_list(s):
        return FormatDetection(kind="hex_0x_list", is_terminal=False)
    if looks_like_python(s):
        return FormatDetection(kind="python_source", is_terminal=True)
    return FormatDetection(kind="ascii_text", is_terminal=True)


def _detect_bytes(data: bytes) -> FormatDetection:
    # Binary magic first. Pickle is ordered ahead of compressors so
    # a 0x80-leading payload that happens to coincide with a zlib
    # variant can't be (it can't; 0x80 is not a zlib first byte).
    if is_pickle(data):
        return FormatDetection(kind="pickle_data", is_terminal=True)
    if is_zlib(data):
        return FormatDetection(kind="zlib", is_terminal=False)
    if is_gzip(data):
        return FormatDetection(kind="gzip", is_terminal=False)
    if is_bzip2(data):
        return FormatDetection(kind="bzip2", is_terminal=False)
    if is_lzma(data):
        return FormatDetection(kind="lzma", is_terminal=False)
    if is_pe(data):
        return FormatDetection(kind="pe_executable", is_terminal=True)
    if is_elf(data):
        return FormatDetection(kind="elf_executable", is_terminal=True)
    if is_png(data):
        return FormatDetection(kind="png_image", is_terminal=True)
    if is_zip(data):
        return FormatDetection(kind="zip_archive", is_terminal=True)

    # No binary magic matched. Try ASCII-decode and re-detect on the
    # text form so b64-encoded-as-bytes content still gets unwrapped.
    text = _ascii_decode_or_none(data)
    if text is not None:
        result = _detect_str(text)
        # If the text-form classification was a recognized text
        # encoding, surface that. Otherwise the bytes-form gets the
        # final say (more conservative for opaque content).
        if not result.is_terminal:
            return result
        if result.kind == "python_source":
            return result
        # Plain ASCII text that isn't an encoding and isn't Python.
        return FormatDetection(kind="ascii_text", is_terminal=True)

    # Pure binary, nothing recognized.
    return FormatDetection(kind="binary_unknown", is_terminal=True)


# ---------------------------------------------------------------------------
# Indicator scanning
# ---------------------------------------------------------------------------

def scan_indicators(data: str | bytes) -> tuple[str, ...]:
    """Find any of the indicator keywords in `data`.

    Returns a tuple of matched keywords in encounter order. Empty
    if no indicators are present or if `data` cannot be decoded as
    ASCII for scanning. Bytes inputs are decoded with errors='replace'
    so that mixed-content blobs (ASCII Python text with embedded
    binary blobs) still surface text-shaped indicators.
    """
    if isinstance(data, bytes):
        try:
            text = data.decode("ascii", errors="replace")
        except Exception:
            return ()
    else:
        text = data

    found = []
    for keyword in _INDICATOR_KEYWORDS:
        if keyword in text:
            found.append(keyword)
    return tuple(found)