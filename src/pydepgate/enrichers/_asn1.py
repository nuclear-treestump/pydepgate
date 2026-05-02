"""
DER parser primitives and a structural classifier for ASN.1 blobs.

This module exists to give the unwrap pipeline (_unwrap.py) and the
format classifier (_magic.py) a way to look at binary_unknown bytes
and recognize structured cryptographic objects: RSA keys, ECDSA
keys, X.509 certificates, PKCS#8 private keys, and so on. It runs
on bytes that have already fallen out of the unwrap chain, never
on raw input.

Public surface:

    classify(data, *, max_depth=32) -> DERClassification
        Identify a DER blob and extract whatever structured fields
        we recognize. Always returns a DERClassification; no DER
        input ever causes this function to raise.

    looks_like_der(data) -> bool
        Cheap O(1) pre-check used by _magic.py to gate full classifier
        invocation on plausibly-DER inputs.

    FormatContext
        Marker base class for structured per-format detail objects.
        DERClassification is the first subclass; future parsers
        (JWT, PE metadata, etc.) add sibling subclasses without
        touching the FormatDetection dataclass in _magic.py.

    DERClassification
        Subclass of FormatContext. Frozen dataclass with kind,
        bit_size, fields, oids_seen, anomalies, san_entries,
        extensions. See the dataclass docstring for field semantics.

    DERAnomaly, SubjectAltName, X509Extension
        Frozen dataclasses for recorded deviations and structured
        cert sub-fields.

    read_tlv, read_oid, read_integer_unsigned, read_integer_signed,
    read_utf8_string, read_printable_string, read_ia5_string,
    read_bmp_string, read_t61_string, read_utc_time,
    read_generalized_time
        Low-level primitives. Exposed for unit-testability.

    TAG_* constants
        Universal-tag identifiers as TagInfo instances.

    OID_* constants
        Algorithm and structural OIDs we match against.

Design contract: lax with anomalies
-----------------------------------
The parser does not raise on malformed inputs. It records every
mechanically-detectable deviation as a DERAnomaly, recovers with a
sensible default, and continues parsing. An empty anomaly list
means the input was canonical DER. A populated list is data, not
failure: the analyzer that eventually consumes this output is the
component that decides which combinations of anomalies are worth
firing a finding on. The parser's job is extraction, not judgment.

The one strict gate is the outer tag: the input must be a SEQUENCE.
Anything else returns kind="unknown_der" immediately.

Recognized shapes (in classifier dispatch order):
  - X.509 Certificate (kind="x509_certificate"): outer SEQUENCE
    contains TBSCertificate SEQUENCE, signatureAlgorithm SEQUENCE,
    signatureValue BIT STRING.
  - SubjectPublicKeyInfo: outer SEQUENCE contains AlgorithmIdentifier
    SEQUENCE and subjectPublicKey BIT STRING. Kind depends on the
    algorithm OID.

FormatContext placement note
----------------------------
FormatContext currently lives in this module because DERClassification
is its only subclass. When the JWT parser (or any second classifier)
lands, the marker class should move to a new module
(pydepgate/enrichers/_format_context.py) and both parsers import from
there. The current placement is a temporary one-consumer convenience.

Safety invariants
-----------------
The parser never executes, imports, or compiles any input. It
performs only byte reads and integer arithmetic. Recursion depth
is bounded (default 32) so a maliciously nested DER blob cannot
exhaust the Python stack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Exception types
# ---------------------------------------------------------------------------

class ASN1ParseError(Exception):
    """Raised only when the parser cannot extract even a single TLV.

    Conditions that DO raise: buffer too short to contain any tag
    byte, high-form tag whose continuation bytes run off the end,
    long-form length whose octets run off the end. Everything else
    is recorded as a DERAnomaly and the parser keeps going. The
    public classify() function catches this internally; external
    callers should not see it.
    """


# ---------------------------------------------------------------------------
# Tag handling
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TagInfo:
    """One ASN.1 tag, decomposed into its three components."""
    tag_class: int
    number: int
    constructed: bool


TAG_CLASS_UNIVERSAL = 0
TAG_CLASS_APPLICATION = 1
TAG_CLASS_CONTEXT = 2
TAG_CLASS_PRIVATE = 3


TAG_BOOLEAN          = TagInfo(0, 1,  False)
TAG_INTEGER          = TagInfo(0, 2,  False)
TAG_BIT_STRING       = TagInfo(0, 3,  False)
TAG_OCTET_STRING     = TagInfo(0, 4,  False)
TAG_NULL             = TagInfo(0, 5,  False)
TAG_OID              = TagInfo(0, 6,  False)
TAG_UTF8_STRING      = TagInfo(0, 12, False)
TAG_SEQUENCE         = TagInfo(0, 16, True)
TAG_SET              = TagInfo(0, 17, True)
TAG_PRINTABLE_STRING = TagInfo(0, 19, False)
TAG_T61_STRING       = TagInfo(0, 20, False)
TAG_IA5_STRING       = TagInfo(0, 22, False)
TAG_UTC_TIME         = TagInfo(0, 23, False)
TAG_GENERALIZED_TIME = TagInfo(0, 24, False)
TAG_BMP_STRING       = TagInfo(0, 30, False)


# ---------------------------------------------------------------------------
# OIDs
# ---------------------------------------------------------------------------

OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_EC_PUBLIC_KEY  = "1.2.840.10045.2.1"
OID_DSA            = "1.2.840.10040.4.1"
OID_ED25519        = "1.3.101.112"
OID_ED448          = "1.3.101.113"

OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_SHA384_WITH_RSA = "1.2.840.113549.1.1.12"
OID_SHA512_WITH_RSA = "1.2.840.113549.1.1.13"
OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
OID_ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3"
OID_ECDSA_WITH_SHA512 = "1.2.840.10045.4.3.4"

OID_AT_COMMON_NAME          = "2.5.4.3"
OID_AT_SURNAME              = "2.5.4.4"
OID_AT_SERIAL_NUMBER        = "2.5.4.5"
OID_AT_COUNTRY              = "2.5.4.6"
OID_AT_LOCALITY             = "2.5.4.7"
OID_AT_STATE                = "2.5.4.8"
OID_AT_STREET_ADDRESS       = "2.5.4.9"
OID_AT_ORGANIZATION         = "2.5.4.10"
OID_AT_ORGANIZATIONAL_UNIT  = "2.5.4.11"
OID_AT_TITLE                = "2.5.4.12"
OID_AT_GIVEN_NAME           = "2.5.4.42"
OID_AT_EMAIL                = "1.2.840.113549.1.9.1"
OID_AT_DOMAIN_COMPONENT     = "0.9.2342.19200300.100.1.25"

OID_CE_SUBJECT_ALT_NAME      = "2.5.29.17"
OID_CE_KEY_USAGE             = "2.5.29.15"
OID_CE_BASIC_CONSTRAINTS     = "2.5.29.19"
OID_CE_EXT_KEY_USAGE         = "2.5.29.37"
OID_CE_AUTHORITY_KEY_ID      = "2.5.29.35"
OID_CE_SUBJECT_KEY_ID        = "2.5.29.14"
OID_CE_CRL_DISTRIBUTION      = "2.5.29.31"
OID_CE_CERTIFICATE_POLICIES  = "2.5.29.32"
OID_CE_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1"
OID_CE_NAME_CONSTRAINTS      = "2.5.29.30"


_SPKI_ALGORITHM_OID_TO_KIND = {
    OID_RSA_ENCRYPTION: "rsa_public_key",
    OID_EC_PUBLIC_KEY:  "ec_public_key",
    OID_DSA:            "dsa_public_key",
    OID_ED25519:        "ed25519_public_key",
    OID_ED448:          "ed448_public_key",
}


_DN_OID_LABELS = {
    OID_AT_COMMON_NAME:         "cn",
    OID_AT_SURNAME:             "sn",
    OID_AT_SERIAL_NUMBER:       "serial",
    OID_AT_COUNTRY:             "c",
    OID_AT_LOCALITY:            "l",
    OID_AT_STATE:               "st",
    OID_AT_STREET_ADDRESS:      "street",
    OID_AT_ORGANIZATION:        "o",
    OID_AT_ORGANIZATIONAL_UNIT: "ou",
    OID_AT_TITLE:               "title",
    OID_AT_GIVEN_NAME:          "givenName",
    OID_AT_EMAIL:               "email",
    OID_AT_DOMAIN_COMPONENT:    "dc",
}


# ---------------------------------------------------------------------------
# FormatContext base class
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FormatContext:
    """Marker base class for structured per-format detail objects.

    Subclasses are emitted by classifiers in this module and (eventually)
    sibling modules. The FormatDetection dataclass in _magic.py carries
    an optional FormatContext field that callers can examine for richer
    information than the bare kind string.

    Discipline for callers: never reach into a specific subclass's
    fields without first checking the kind. The pattern is

        if det.kind in DER_KINDS:
            assert isinstance(det.details, DERClassification)
            ... use det.details ...

    not

        bits = det.details.bit_size  # crashes if details is None

    The subclass set is open by design.
    """


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DERAnomaly:
    """One mechanically-detectable deviation from canonical DER."""
    where: str
    kind: str
    detail: str


@dataclass(frozen=True)
class SubjectAltName:
    """One entry in an X.509 SubjectAltName extension.

    Attributes:
        kind: One of "dns", "uri", "ip", "email", "directory",
            "other_name", "registered_id". This is the GeneralName
            CHOICE branch.
        value: String form of the entry.
        type_id: For other_name and registered_id, the inner OID.
            None for other branches.
    """
    kind: str
    value: str
    type_id: str | None = None


@dataclass(frozen=True)
class X509Extension:
    """One extension entry from an X.509 cert.

    Attributes:
        oid: Extension type OID in dotted form.
        critical: Value of the criticality flag.
        value_hex: Hex-encoded extension value bytes.
        san_entries: For SAN specifically, the parsed entries.
            None for other extensions.
    """
    oid: str
    critical: bool
    value_hex: str
    san_entries: tuple[SubjectAltName, ...] | None = None


@dataclass(frozen=True)
class DERClassification(FormatContext):
    """The parser's structured opinion of a DER blob."""
    kind: str = "unknown_der"
    bit_size: int | None = None
    fields: dict[str, str] = field(default_factory=dict)
    oids_seen: tuple[str, ...] = ()
    anomalies: tuple[DERAnomaly, ...] = ()
    san_entries: tuple[SubjectAltName, ...] = ()
    extensions: tuple[X509Extension, ...] = ()

    def summary_dict(self) -> dict:
        """Compact summary for renderers and the decoded["der"] key.

        Pulls the most commonly-rendered fields out of self.fields and
        flattens SAN/extension info into renderer-friendly shapes.
        Discards anomalies (count only), value_hex, oids_seen, and the
        full extensions list. Consumers wanting those fields should
        call full_dict() instead.
        """
        summary: dict = {
            "kind": self.kind,
            "bit_size": self.bit_size,
            "anomaly_count": len(self.anomalies),
        }
        for field_key, summary_key in (
            ("cert_subject_cn", "subject_cn"),
            ("cert_issuer_cn", "issuer_cn"),
            ("cert_not_before", "not_before"),
            ("cert_not_after", "not_after"),
            ("cert_serial", "serial"),
            ("cert_signature_oid", "signature_oid"),
            ("cert_version", "version"),
        ):
            if field_key in self.fields:
                summary[summary_key] = self.fields[field_key]
        if self.san_entries:
            summary["san_summary"] = [
                f"{s.kind}:{s.value}" for s in self.san_entries
            ]
        if self.extensions:
            summary["extension_oids"] = [
                {"oid": e.oid, "critical": e.critical}
                for e in self.extensions
            ]
        return summary

    def full_dict(self) -> dict:
        """Lossless serialization for archives and the decoded["der_full"] key.

        Every public field is included, in JSON-friendly nested-dict
        form. SubjectAltName.type_id and X509Extension.san_entries
        preserve None when not applicable rather than being elided,
        so consumers can round-trip without losing structural shape.
        """
        return {
            "kind": self.kind,
            "bit_size": self.bit_size,
            "fields": dict(self.fields),
            "oids_seen": list(self.oids_seen),
            "anomalies": [
                {"where": a.where, "kind": a.kind, "detail": a.detail}
                for a in self.anomalies
            ],
            "san_entries": [
                {"kind": s.kind, "value": s.value, "type_id": s.type_id}
                for s in self.san_entries
            ],
            "extensions": [
                {
                    "oid": e.oid,
                    "critical": e.critical,
                    "value_hex": e.value_hex,
                    "san_entries": (
                        [
                            {
                                "kind": s.kind,
                                "value": s.value,
                                "type_id": s.type_id,
                            }
                            for s in e.san_entries
                        ]
                        if e.san_entries is not None
                        else None
                    ),
                }
                for e in self.extensions
            ],
        }


# ---------------------------------------------------------------------------
# TLV reader
# ---------------------------------------------------------------------------

def read_tlv(
    buf: bytes,
    offset: int,
    anomalies: list[DERAnomaly],
    where: str,
) -> tuple[TagInfo, int, int, int]:
    """Read a single TLV starting at offset.

    Returns (tag, length, value_offset, end_offset). Lax-recovery
    semantics per module docstring.
    """
    n = len(buf)

    if offset >= n:
        raise ASN1ParseError(
            f"{where}: offset {offset} past end of buffer ({n} bytes)"
        )

    tag_byte = buf[offset]
    cur = offset + 1

    tag_class = (tag_byte & 0xC0) >> 6
    constructed = bool(tag_byte & 0x20)
    low_number = tag_byte & 0x1F

    if low_number != 0x1F:
        number = low_number
    else:
        number = 0
        while True:
            if cur >= n:
                raise ASN1ParseError(
                    f"{where}: high-form tag continuation ran off end"
                )
            b = buf[cur]
            cur += 1
            number = (number << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
            if number > (1 << 24):
                anomalies.append(DERAnomaly(
                    where, "absurd_tag_number",
                    "tag number exceeded 2^24 during high-form decode",
                ))
                break

    tag = TagInfo(tag_class, number, constructed)

    if cur >= n:
        raise ASN1ParseError(
            f"{where}: TLV ended after tag, no length byte"
        )

    len_byte = buf[cur]
    cur += 1

    if len_byte < 0x80:
        length = len_byte
    elif len_byte == 0x80:
        anomalies.append(DERAnomaly(
            where, "indefinite_length",
            "TLV uses indefinite-length encoding (BER feature, not DER)",
        ))
        length = n - cur
    else:
        num_octets = len_byte & 0x7F
        if num_octets > 8:
            anomalies.append(DERAnomaly(
                where, "absurd_length_octets",
                f"length encoded in {num_octets} octets",
            ))
            num_octets = 8
        if cur + num_octets > n:
            raise ASN1ParseError(
                f"{where}: long-form length octets ran off end of buffer"
            )

        length_octets = buf[cur:cur + num_octets]
        length = int.from_bytes(length_octets, "big")
        cur += num_octets

        if length < 0x80:
            anomalies.append(DERAnomaly(
                where, "non_minimal_length",
                f"length {length} encoded in long form",
            ))
        elif num_octets > 1 and length_octets[0] == 0x00:
            anomalies.append(DERAnomaly(
                where, "non_minimal_length",
                "long-form length has redundant leading 0x00 octet",
            ))

    value_offset = cur
    declared_end = value_offset + length

    if declared_end > n:
        overrun = declared_end - n
        anomalies.append(DERAnomaly(
            where, "length_overrun",
            f"declared length {length} exceeds available bytes by {overrun}",
        ))
        end_offset = n
    else:
        end_offset = declared_end

    return tag, length, value_offset, end_offset


# ---------------------------------------------------------------------------
# Primitive-value decoders
# ---------------------------------------------------------------------------

def read_integer_unsigned(
    value: bytes,
    anomalies: list[DERAnomaly],
    where: str,
) -> int:
    """Decode an INTEGER value as an unsigned big-endian integer."""
    if not value:
        anomalies.append(DERAnomaly(
            where, "empty_integer", "INTEGER with zero-byte value",
        ))
        return 0

    body = value
    if len(body) > 1 and body[0] == 0x00:
        next_byte = body[1]
        body = body[1:]
        if not (next_byte & 0x80):
            anomalies.append(DERAnomaly(
                where, "non_minimal_integer",
                "INTEGER has redundant leading 0x00 octet",
            ))

    return int.from_bytes(body, "big", signed=False)


def read_integer_signed(
    value: bytes,
    anomalies: list[DERAnomaly],
    where: str,
) -> int:
    """Decode an INTEGER value as a signed two's-complement integer."""
    if not value:
        anomalies.append(DERAnomaly(
            where, "empty_integer", "INTEGER with zero-byte value",
        ))
        return 0
    return int.from_bytes(value, "big", signed=True)


def read_oid(
    value: bytes,
    anomalies: list[DERAnomaly],
    where: str,
) -> str:
    """Decode an OBJECT IDENTIFIER value as a dotted-decimal string."""
    if not value:
        anomalies.append(DERAnomaly(
            where, "empty_oid", "OBJECT IDENTIFIER with zero-byte value",
        ))
        return ""

    first_byte = value[0]
    if first_byte < 40:
        first_arc, second_arc = 0, first_byte
    elif first_byte < 80:
        first_arc, second_arc = 1, first_byte - 40
    else:
        first_arc, second_arc = 2, first_byte - 80

    arcs: list[int] = [first_arc, second_arc]

    current = 0
    in_progress = False
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        in_progress = True
        if not (byte & 0x80):
            arcs.append(current)
            current = 0
            in_progress = False

    if in_progress:
        anomalies.append(DERAnomaly(
            where, "truncated_oid",
            "OID ended mid-arc (last byte had continuation bit set)",
        ))
        return ".".join(str(a) for a in arcs) + ".[?]"

    return ".".join(str(a) for a in arcs)


# ---------------------------------------------------------------------------
# String-type decoders
# ---------------------------------------------------------------------------

_PRINTABLE_STRING_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " '()+,-./:=?"
)
_IA5_MAX_BYTE = 0x7F


def read_utf8_string(
    value: bytes,
    anomalies: list[DERAnomaly],
    where: str,
) -> str:
    """Decode a UTF8String. Falls back to latin-1 with anomaly on bad UTF-8."""
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        anomalies.append(DERAnomaly(
            where, "string_decode_failed",
            f"UTF8String contained invalid UTF-8: {exc}",
        ))
        return value.decode("latin-1", errors="replace")


def read_printable_string(
    value: bytes,
    anomalies: list[DERAnomaly],
    where: str,
) -> str:
    """Decode a PrintableString. Records charset violations."""
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as exc:
        anomalies.append(DERAnomaly(
            where, "string_decode_failed",
            f"PrintableString contained non-ASCII bytes: {exc}",
        ))
        return value.decode("latin-1", errors="replace")
    invalid = [c for c in text if c not in _PRINTABLE_STRING_CHARS]
    if invalid:
        anomalies.append(DERAnomaly(
            where, "string_charset_violation",
            f"PrintableString contains {len(invalid)} non-printable-set chars",
        ))
    return text


def read_ia5_string(
    value: bytes,
    anomalies: list[DERAnomaly],
    where: str,
) -> str:
    """Decode an IA5String (7-bit ASCII)."""
    high_bit_count = sum(1 for b in value if b > _IA5_MAX_BYTE)
    if high_bit_count:
        anomalies.append(DERAnomaly(
            where, "string_charset_violation",
            f"IA5String contains {high_bit_count} bytes with high bit set",
        ))
    return value.decode("latin-1", errors="replace")


def read_bmp_string(
    value: bytes,
    anomalies: list[DERAnomaly],
    where: str,
) -> str:
    """Decode a BMPString (UTF-16BE)."""
    if len(value) % 2 != 0:
        anomalies.append(DERAnomaly(
            where, "string_decode_failed",
            f"BMPString has odd byte length {len(value)}",
        ))
        return value.decode("latin-1", errors="replace")
    try:
        return value.decode("utf-16-be")
    except UnicodeDecodeError as exc:
        anomalies.append(DERAnomaly(
            where, "string_decode_failed",
            f"BMPString contained invalid UTF-16BE: {exc}",
        ))
        return value.decode("latin-1", errors="replace")


def read_t61_string(
    value: bytes,
    anomalies: list[DERAnomaly],
    where: str,
) -> str:
    """Decode a T61String. Always emits an ambiguity anomaly."""
    anomalies.append(DERAnomaly(
        where, "t61_ambiguous",
        "T61String has no canonical Python decoding; using latin-1",
    ))
    return value.decode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# Date-type decoders
# ---------------------------------------------------------------------------

def read_utc_time(
    value: bytes,
    anomalies: list[DERAnomaly],
    where: str,
) -> str:
    """Decode UTCTime per RFC 5280. Returns ISO-8601 UTC string on success."""
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError:
        anomalies.append(DERAnomaly(
            where, "time_decode_failed", "UTCTime not ASCII",
        ))
        return value.decode("latin-1", errors="replace")

    if len(text) != 13 or not text.endswith("Z") or not text[:12].isdigit():
        anomalies.append(DERAnomaly(
            where, "time_format_violation",
            f"UTCTime has unexpected format: {text!r}",
        ))
        return text

    yy = int(text[0:2])
    year = 2000 + yy if yy < 50 else 1900 + yy
    try:
        dt = datetime(
            year=year,
            month=int(text[2:4]),
            day=int(text[4:6]),
            hour=int(text[6:8]),
            minute=int(text[8:10]),
            second=int(text[10:12]),
            tzinfo=timezone.utc,
        )
    except ValueError as exc:
        anomalies.append(DERAnomaly(
            where, "time_format_violation",
            f"UTCTime values out of range: {exc}",
        ))
        return text

    return dt.isoformat()


def read_generalized_time(
    value: bytes,
    anomalies: list[DERAnomaly],
    where: str,
) -> str:
    """Decode GeneralizedTime per RFC 5280 (strict YYYYMMDDHHMMSSZ form)."""
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError:
        anomalies.append(DERAnomaly(
            where, "time_decode_failed", "GeneralizedTime not ASCII",
        ))
        return value.decode("latin-1", errors="replace")

    if len(text) != 15 or not text.endswith("Z") or not text[:14].isdigit():
        anomalies.append(DERAnomaly(
            where, "time_format_violation",
            f"GeneralizedTime has unexpected format: {text!r}",
        ))
        return text

    try:
        dt = datetime(
            year=int(text[0:4]),
            month=int(text[4:6]),
            day=int(text[6:8]),
            hour=int(text[8:10]),
            minute=int(text[10:12]),
            second=int(text[12:14]),
            tzinfo=timezone.utc,
        )
    except ValueError as exc:
        anomalies.append(DERAnomaly(
            where, "time_format_violation",
            f"GeneralizedTime values out of range: {exc}",
        ))
        return text

    return dt.isoformat()


# ---------------------------------------------------------------------------
# Tag rendering
# ---------------------------------------------------------------------------

_UNIVERSAL_TAG_NAMES = {
    1: "BOOLEAN", 2: "INTEGER", 3: "BIT_STRING", 4: "OCTET_STRING",
    5: "NULL", 6: "OID", 12: "UTF8String", 16: "SEQUENCE",
    17: "SET", 19: "PrintableString", 20: "T61String",
    22: "IA5String", 23: "UTCTime", 24: "GeneralizedTime",
    30: "BMPString",
}


def _tag_name(tag: TagInfo) -> str:
    """Render a TagInfo as a readable label."""
    if tag.tag_class == TAG_CLASS_UNIVERSAL:
        name = _UNIVERSAL_TAG_NAMES.get(
            tag.number, f"UNIVERSAL({tag.number})",
        )
    elif tag.tag_class == TAG_CLASS_CONTEXT:
        name = f"[{tag.number}]"
    elif tag.tag_class == TAG_CLASS_APPLICATION:
        name = f"APPLICATION({tag.number})"
    else:
        name = f"PRIVATE({tag.number})"
    if tag.constructed and tag.tag_class != TAG_CLASS_UNIVERSAL:
        name += " CONSTRUCTED"
    return name


# ---------------------------------------------------------------------------
# Top-level classifier
# ---------------------------------------------------------------------------

def looks_like_der(data: bytes) -> bool:
    """Cheap O(1) check for whether data is plausibly DER.

    True iff the first byte is 0x30 (the SEQUENCE tag). This is a
    pre-check before a full classify() call to avoid walking
    arbitrary garbage. False positives are fine; classify() handles
    them gracefully.
    """
    if len(data) < 2:
        return False
    if data[0] != 0x30:
        return False
    return True


def classify(data: bytes, *, max_depth: int = 32) -> DERClassification:
    """Classify a DER blob.

    The outer tag must be SEQUENCE. Non-SEQUENCE inputs return
    immediately as kind="unknown_der". Inside the outer SEQUENCE,
    the classifier tries each recognized shape in order.

    Currently recognized shapes (in dispatch order):
      - X.509 Certificate
      - SubjectPublicKeyInfo (RSA, EC, DSA, Ed25519, Ed448)
    """
    anomalies: list[DERAnomaly] = []
    fields: dict[str, str] = {}
    oids_seen: list[str] = []

    if len(data) < 2:
        anomalies.append(DERAnomaly(
            "outer", "too_short",
            f"input is {len(data)} bytes; minimum DER TLV is 2",
        ))
        return DERClassification(
            kind="unknown_der",
            fields={},
            anomalies=tuple(anomalies),
        )

    try:
        outer_tag, _outer_length, body_offset, body_end = read_tlv(
            data, 0, anomalies, "outer",
        )
    except ASN1ParseError as exc:
        anomalies.append(DERAnomaly(
            "outer", "tlv_read_failed", str(exc),
        ))
        return DERClassification(
            kind="unknown_der",
            fields={},
            anomalies=tuple(anomalies),
        )

    if outer_tag != TAG_SEQUENCE:
        anomalies.append(DERAnomaly(
            "outer", "not_sequence",
            f"outer tag is {_tag_name(outer_tag)}, expected SEQUENCE",
        ))
        return DERClassification(
            kind="unknown_der",
            fields={},
            anomalies=tuple(anomalies),
        )

    if body_end < len(data):
        trailing = len(data) - body_end
        anomalies.append(DERAnomaly(
            "outer", "extra_trailing_bytes",
            f"{trailing} bytes after end of outer SEQUENCE",
        ))

    # Try X.509 Certificate first (most specific shape).
    cert_result = _try_classify_x509_cert(
        data, body_offset, body_end, anomalies, fields, oids_seen,
        max_depth=max_depth,
    )
    if cert_result is not None:
        return DERClassification(
            kind="x509_certificate",
            bit_size=cert_result.get("bit_size"),
            fields=fields,
            oids_seen=tuple(oids_seen),
            anomalies=tuple(anomalies),
            san_entries=cert_result.get("san_entries", ()),
            extensions=cert_result.get("extensions", ()),
        )

    # Then SPKI.
    spki = _try_classify_spki(
        data, body_offset, body_end, anomalies, fields, oids_seen,
    )
    if spki is not None:
        kind, bit_size = spki
        return DERClassification(
            kind=kind,
            bit_size=bit_size,
            fields=fields,
            oids_seen=tuple(oids_seen),
            anomalies=tuple(anomalies),
        )

    return DERClassification(
        kind="unknown_der",
        fields=fields,
        oids_seen=tuple(oids_seen),
        anomalies=tuple(anomalies),
    )


# ---------------------------------------------------------------------------
# Shape: SubjectPublicKeyInfo
# ---------------------------------------------------------------------------

def _try_classify_spki(
    data: bytes,
    start: int,
    end: int,
    anomalies: list[DERAnomaly],
    fields: dict[str, str],
    oids_seen: list[str],
) -> tuple[str, int | None] | None:
    """Try to recognize SPKI inside the outer SEQUENCE body."""
    cur = start

    try:
        algid_tag, _, algid_body, algid_end = read_tlv(
            data, cur, anomalies, "spki.algorithm",
        )
    except ASN1ParseError:
        return None

    if algid_tag != TAG_SEQUENCE:
        return None

    try:
        oid_tag, _, oid_body, oid_end = read_tlv(
            data, algid_body, anomalies, "spki.algorithm.oid",
        )
    except ASN1ParseError:
        return None

    if oid_tag != TAG_OID:
        return None

    algorithm_oid = read_oid(
        data[oid_body:oid_end], anomalies, "spki.algorithm.oid",
    )
    oids_seen.append(algorithm_oid)
    fields["spki_algorithm_oid"] = algorithm_oid

    kind = _SPKI_ALGORITHM_OID_TO_KIND.get(
        algorithm_oid, "unknown_public_key",
    )

    cur = algid_end

    if cur >= end:
        anomalies.append(DERAnomaly(
            "spki", "missing_bit_string",
            "SPKI is missing the subjectPublicKey BIT STRING",
        ))
        return (kind, None)

    try:
        bs_tag, _, bs_body, bs_end = read_tlv(
            data, cur, anomalies, "spki.subjectPublicKey",
        )
    except ASN1ParseError:
        return (kind, None)

    if bs_tag != TAG_BIT_STRING:
        anomalies.append(DERAnomaly(
            "spki.subjectPublicKey", "unexpected_tag",
            f"expected BIT STRING, got {_tag_name(bs_tag)}",
        ))
        return (kind, None)

    if bs_end < end:
        anomalies.append(DERAnomaly(
            "spki", "extra_content",
            f"{end - bs_end} bytes after subjectPublicKey BIT STRING",
        ))

    bit_size: int | None = None
    if kind == "rsa_public_key":
        bit_size = _extract_rsa_modulus_bits(
            data, bs_body, bs_end, anomalies, fields,
        )

    return (kind, bit_size)


def _extract_rsa_modulus_bits(
    data: bytes,
    bs_start: int,
    bs_end: int,
    anomalies: list[DERAnomaly],
    fields: dict[str, str],
) -> int | None:
    """Walk an RSA BIT STRING value to extract the modulus bit length."""
    if bs_start >= bs_end:
        anomalies.append(DERAnomaly(
            "spki.subjectPublicKey", "empty_bit_string",
            "BIT STRING value is empty",
        ))
        return None

    unused_bits = data[bs_start]
    if unused_bits != 0:
        anomalies.append(DERAnomaly(
            "spki.subjectPublicKey", "nonzero_unused_bits",
            f"BIT STRING has {unused_bits} unused trailing bits",
        ))

    inner_start = bs_start + 1

    try:
        inner_tag, _, inner_body, inner_end = read_tlv(
            data, inner_start, anomalies, "rsa.RSAPublicKey",
        )
    except ASN1ParseError:
        return None

    if inner_tag != TAG_SEQUENCE:
        anomalies.append(DERAnomaly(
            "rsa.RSAPublicKey", "unexpected_tag",
            f"expected SEQUENCE, got {_tag_name(inner_tag)}",
        ))
        return None

    try:
        mod_tag, _, mod_body, mod_end = read_tlv(
            data, inner_body, anomalies, "rsa.RSAPublicKey.modulus",
        )
    except ASN1ParseError:
        return None

    if mod_tag != TAG_INTEGER:
        anomalies.append(DERAnomaly(
            "rsa.RSAPublicKey.modulus", "unexpected_tag",
            f"expected INTEGER, got {_tag_name(mod_tag)}",
        ))
        return None

    modulus = read_integer_unsigned(
        data[mod_body:mod_end], anomalies, "rsa.RSAPublicKey.modulus",
    )

    if mod_end < inner_end:
        try:
            exp_tag, _, exp_body, exp_end = read_tlv(
                data, mod_end, anomalies, "rsa.RSAPublicKey.exponent",
            )
            if exp_tag == TAG_INTEGER:
                exponent = read_integer_unsigned(
                    data[exp_body:exp_end], anomalies,
                    "rsa.RSAPublicKey.exponent",
                )
                fields["rsa_exponent"] = str(exponent)
            else:
                anomalies.append(DERAnomaly(
                    "rsa.RSAPublicKey.exponent", "unexpected_tag",
                    f"expected INTEGER, got {_tag_name(exp_tag)}",
                ))
        except ASN1ParseError:
            pass

    bit_size = modulus.bit_length()
    fields["rsa_modulus_bits"] = str(bit_size)
    return bit_size


# ---------------------------------------------------------------------------
# Shape: X.509 Certificate
# ---------------------------------------------------------------------------
#
# RFC 5280 section 4.1:
#
#   Certificate  ::=  SEQUENCE  {
#        tbsCertificate       TBSCertificate,
#        signatureAlgorithm   AlgorithmIdentifier,
#        signatureValue       BIT STRING  }
#
#   TBSCertificate  ::=  SEQUENCE  {
#        version         [0]  EXPLICIT Version DEFAULT v1,
#        serialNumber         CertificateSerialNumber,
#        signature            AlgorithmIdentifier,
#        issuer               Name,
#        validity             Validity,
#        subject              Name,
#        subjectPublicKeyInfo SubjectPublicKeyInfo,
#        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
#        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
#        extensions      [3]  EXPLICIT Extensions OPTIONAL  }

def _try_classify_x509_cert(
    data: bytes,
    start: int,
    end: int,
    anomalies: list[DERAnomaly],
    fields: dict[str, str],
    oids_seen: list[str],
    *,
    max_depth: int,
) -> dict | None:
    """Try to recognize an X.509 Certificate.

    Returns a dict with extracted data on match, None on no-match.
    """
    cur = start

    try:
        tbs_tag, _, tbs_body, tbs_end = read_tlv(
            data, cur, anomalies, "cert.tbs",
        )
    except ASN1ParseError:
        return None

    if tbs_tag != TAG_SEQUENCE:
        return None

    # Inside TBSCertificate, first thing should be either [0] EXPLICIT
    # Version (constructed context tag 0) or a serialNumber INTEGER.
    try:
        first_inner_tag, _, _, _ = read_tlv(
            data, tbs_body, anomalies, "cert.tbs.first",
        )
    except ASN1ParseError:
        return None

    is_versioned = (
        first_inner_tag.tag_class == TAG_CLASS_CONTEXT
        and first_inner_tag.number == 0
        and first_inner_tag.constructed
    )
    is_unversioned = first_inner_tag == TAG_INTEGER

    if not (is_versioned or is_unversioned):
        return None

    result = _walk_tbs_certificate(
        data, tbs_body, tbs_end, anomalies, fields, oids_seen,
        max_depth=max_depth,
    )

    # signatureAlgorithm (outer, after TBSCertificate).
    cur = tbs_end
    if cur >= end:
        anomalies.append(DERAnomaly(
            "cert", "missing_signature_algorithm",
            "Certificate is missing signatureAlgorithm",
        ))
        return result

    try:
        sigalg_tag, _, sigalg_body, sigalg_end = read_tlv(
            data, cur, anomalies, "cert.signatureAlgorithm",
        )
    except ASN1ParseError:
        return result

    if sigalg_tag == TAG_SEQUENCE:
        try:
            so_tag, _, so_body, so_end = read_tlv(
                data, sigalg_body, anomalies,
                "cert.signatureAlgorithm.oid",
            )
            if so_tag == TAG_OID:
                sig_oid = read_oid(
                    data[so_body:so_end], anomalies,
                    "cert.signatureAlgorithm.oid",
                )
                oids_seen.append(sig_oid)
                fields["cert_signature_oid"] = sig_oid
        except ASN1ParseError:
            pass

    return result


def _walk_tbs_certificate(
    data: bytes,
    start: int,
    end: int,
    anomalies: list[DERAnomaly],
    fields: dict[str, str],
    oids_seen: list[str],
    *,
    max_depth: int,
) -> dict:
    """Walk the TBSCertificate body and populate fields."""
    result: dict = {
        "san_entries": (),
        "extensions": (),
        "bit_size": None,
    }
    cur = start

    # Version (optional, [0] EXPLICIT INTEGER).
    try:
        ver_tag, _, ver_body, ver_end = read_tlv(
            data, cur, anomalies, "cert.tbs.version",
        )
        if (ver_tag.tag_class == TAG_CLASS_CONTEXT
                and ver_tag.number == 0
                and ver_tag.constructed):
            try:
                inner_tag, _, inner_body, inner_end = read_tlv(
                    data, ver_body, anomalies, "cert.tbs.version.inner",
                )
                if inner_tag == TAG_INTEGER:
                    version = read_integer_unsigned(
                        data[inner_body:inner_end], anomalies,
                        "cert.tbs.version.inner",
                    )
                    fields["cert_version"] = f"v{version + 1}"
            except ASN1ParseError:
                pass
            cur = ver_end
        else:
            fields["cert_version"] = "v1"
    except ASN1ParseError:
        return result

    # Serial number.
    try:
        ser_tag, _, ser_body, ser_end = read_tlv(
            data, cur, anomalies, "cert.tbs.serial",
        )
        if ser_tag == TAG_INTEGER:
            serial = read_integer_unsigned(
                data[ser_body:ser_end], anomalies, "cert.tbs.serial",
            )
            fields["cert_serial"] = str(serial)
        cur = ser_end
    except ASN1ParseError:
        return result

    # Signature algorithm (inner, before issuer).
    try:
        sa_tag, _, sa_body, sa_end = read_tlv(
            data, cur, anomalies, "cert.tbs.signatureAlgorithm",
        )
        if sa_tag == TAG_SEQUENCE:
            try:
                inner_tag, _, inner_body, inner_end = read_tlv(
                    data, sa_body, anomalies,
                    "cert.tbs.signatureAlgorithm.oid",
                )
                if inner_tag == TAG_OID:
                    inner_oid = read_oid(
                        data[inner_body:inner_end], anomalies,
                        "cert.tbs.signatureAlgorithm.oid",
                    )
                    oids_seen.append(inner_oid)
            except ASN1ParseError:
                pass
        cur = sa_end
    except ASN1ParseError:
        return result

    # Issuer.
    try:
        issuer_tag, _, issuer_body, issuer_end = read_tlv(
            data, cur, anomalies, "cert.tbs.issuer",
        )
        if issuer_tag == TAG_SEQUENCE:
            issuer_attrs = _walk_name(
                data, issuer_body, issuer_end, anomalies,
                "cert.tbs.issuer", oids_seen,
            )
            for label, value in issuer_attrs.items():
                fields[f"cert_issuer_{label}"] = value
        cur = issuer_end
    except ASN1ParseError:
        return result

    # Validity.
    try:
        val_tag, _, val_body, val_end = read_tlv(
            data, cur, anomalies, "cert.tbs.validity",
        )
        if val_tag == TAG_SEQUENCE:
            _walk_validity(
                data, val_body, val_end, anomalies, fields,
            )
        cur = val_end
    except ASN1ParseError:
        return result

    # Subject.
    try:
        subj_tag, _, subj_body, subj_end = read_tlv(
            data, cur, anomalies, "cert.tbs.subject",
        )
        if subj_tag == TAG_SEQUENCE:
            subj_attrs = _walk_name(
                data, subj_body, subj_end, anomalies,
                "cert.tbs.subject", oids_seen,
            )
            for label, value in subj_attrs.items():
                fields[f"cert_subject_{label}"] = value
        cur = subj_end
    except ASN1ParseError:
        return result

    # SubjectPublicKeyInfo.
    try:
        spki_tag, _, spki_body, spki_end = read_tlv(
            data, cur, anomalies, "cert.tbs.spki",
        )
        if spki_tag == TAG_SEQUENCE:
            inner_anomalies: list[DERAnomaly] = []
            inner_fields: dict[str, str] = {}
            inner_oids: list[str] = []
            spki_result = _try_classify_spki(
                data, spki_body, spki_end,
                inner_anomalies, inner_fields, inner_oids,
            )
            anomalies.extend(inner_anomalies)
            oids_seen.extend(inner_oids)
            for k, v in inner_fields.items():
                fields[f"cert_{k}"] = v
            if spki_result is not None:
                _, bit_size = spki_result
                if bit_size is not None:
                    result["bit_size"] = bit_size
        cur = spki_end
    except ASN1ParseError:
        return result

    # Optional issuerUniqueID [1], subjectUniqueID [2], extensions [3].
    san_entries: list[SubjectAltName] = []
    extensions: list[X509Extension] = []
    while cur < end:
        try:
            opt_tag, _, opt_body, opt_end = read_tlv(
                data, cur, anomalies, "cert.tbs.optional",
            )
        except ASN1ParseError:
            break

        if (opt_tag.tag_class == TAG_CLASS_CONTEXT
                and opt_tag.number == 3
                and opt_tag.constructed):
            ext_block_anomalies, found_san, found_exts = _walk_extensions(
                data, opt_body, opt_end, oids_seen,
            )
            anomalies.extend(ext_block_anomalies)
            san_entries.extend(found_san)
            extensions.extend(found_exts)

        cur = opt_end

    result["san_entries"] = tuple(san_entries)
    result["extensions"] = tuple(extensions)
    return result


# ---------------------------------------------------------------------------
# X.509 helpers
# ---------------------------------------------------------------------------

def _walk_name(
    data: bytes,
    start: int,
    end: int,
    anomalies: list[DERAnomaly],
    where: str,
    oids_seen: list[str],
) -> dict[str, str]:
    """Walk an X.509 Name (sequence of RDN sets) into a label->value dict."""
    result: dict[str, str] = {}
    cur = start

    while cur < end:
        try:
            rdn_tag, _, rdn_body, rdn_end = read_tlv(
                data, cur, anomalies, f"{where}.rdn",
            )
        except ASN1ParseError:
            break

        if rdn_tag != TAG_SET:
            anomalies.append(DERAnomaly(
                f"{where}.rdn", "unexpected_tag",
                f"expected SET, got {_tag_name(rdn_tag)}",
            ))
            cur = rdn_end
            continue

        inner = rdn_body
        while inner < rdn_end:
            try:
                atv_tag, _, atv_body, atv_end = read_tlv(
                    data, inner, anomalies, f"{where}.rdn.atv",
                )
            except ASN1ParseError:
                break
            if atv_tag != TAG_SEQUENCE:
                inner = atv_end
                continue

            try:
                t_tag, _, t_body, t_end = read_tlv(
                    data, atv_body, anomalies, f"{where}.rdn.atv.type",
                )
                if t_tag != TAG_OID:
                    inner = atv_end
                    continue
                attr_oid = read_oid(
                    data[t_body:t_end], anomalies,
                    f"{where}.rdn.atv.type",
                )
                oids_seen.append(attr_oid)

                v_tag, _, v_body, v_end = read_tlv(
                    data, t_end, anomalies, f"{where}.rdn.atv.value",
                )
                if v_tag == TAG_UTF8_STRING:
                    val = read_utf8_string(
                        data[v_body:v_end], anomalies,
                        f"{where}.rdn.atv.value",
                    )
                elif v_tag == TAG_PRINTABLE_STRING:
                    val = read_printable_string(
                        data[v_body:v_end], anomalies,
                        f"{where}.rdn.atv.value",
                    )
                elif v_tag == TAG_IA5_STRING:
                    val = read_ia5_string(
                        data[v_body:v_end], anomalies,
                        f"{where}.rdn.atv.value",
                    )
                elif v_tag == TAG_BMP_STRING:
                    val = read_bmp_string(
                        data[v_body:v_end], anomalies,
                        f"{where}.rdn.atv.value",
                    )
                elif v_tag == TAG_T61_STRING:
                    val = read_t61_string(
                        data[v_body:v_end], anomalies,
                        f"{where}.rdn.atv.value",
                    )
                else:
                    anomalies.append(DERAnomaly(
                        f"{where}.rdn.atv.value", "unexpected_string_type",
                        f"unexpected tag {_tag_name(v_tag)}",
                    ))
                    val = data[v_body:v_end].decode(
                        "latin-1", errors="replace",
                    )

                label = _DN_OID_LABELS.get(attr_oid, attr_oid)
                if label in result:
                    result[label] = result[label] + " | " + val
                else:
                    result[label] = val
            except ASN1ParseError:
                pass

            inner = atv_end

        cur = rdn_end

    return result


def _walk_validity(
    data: bytes,
    start: int,
    end: int,
    anomalies: list[DERAnomaly],
    fields: dict[str, str],
) -> None:
    """Walk a Validity SEQUENCE { notBefore, notAfter } into fields."""
    cur = start
    for label in ("not_before", "not_after"):
        if cur >= end:
            anomalies.append(DERAnomaly(
                f"cert.tbs.validity.{label}", "missing",
                f"Validity is missing {label}",
            ))
            return
        try:
            t_tag, _, t_body, t_end = read_tlv(
                data, cur, anomalies, f"cert.tbs.validity.{label}",
            )
        except ASN1ParseError:
            return
        value = data[t_body:t_end]
        if t_tag == TAG_UTC_TIME:
            fields[f"cert_{label}"] = read_utc_time(
                value, anomalies, f"cert.tbs.validity.{label}",
            )
        elif t_tag == TAG_GENERALIZED_TIME:
            fields[f"cert_{label}"] = read_generalized_time(
                value, anomalies, f"cert.tbs.validity.{label}",
            )
        else:
            anomalies.append(DERAnomaly(
                f"cert.tbs.validity.{label}", "unexpected_tag",
                f"expected Time, got {_tag_name(t_tag)}",
            ))
            fields[f"cert_{label}"] = value.decode(
                "latin-1", errors="replace",
            )
        cur = t_end


def _walk_extensions(
    data: bytes,
    start: int,
    end: int,
    oids_seen: list[str],
) -> tuple[list[DERAnomaly], list[SubjectAltName], list[X509Extension]]:
    """Walk an Extensions [3] EXPLICIT SEQUENCE OF Extension block."""
    local_anomalies: list[DERAnomaly] = []
    san_out: list[SubjectAltName] = []
    ext_out: list[X509Extension] = []

    try:
        seq_tag, _, seq_body, seq_end = read_tlv(
            data, start, local_anomalies, "cert.tbs.extensions",
        )
    except ASN1ParseError:
        return local_anomalies, san_out, ext_out

    if seq_tag != TAG_SEQUENCE:
        local_anomalies.append(DERAnomaly(
            "cert.tbs.extensions", "unexpected_tag",
            f"expected SEQUENCE, got {_tag_name(seq_tag)}",
        ))
        return local_anomalies, san_out, ext_out

    cur = seq_body
    while cur < seq_end:
        try:
            ext_tag, _, ext_body, ext_end = read_tlv(
                data, cur, local_anomalies, "cert.tbs.extensions.entry",
            )
        except ASN1ParseError:
            break
        if ext_tag != TAG_SEQUENCE:
            cur = ext_end
            continue

        oid_str = ""
        critical = False
        value_bytes = b""
        inner = ext_body
        try:
            oid_tag, _, oid_body, oid_end = read_tlv(
                data, inner, local_anomalies, "ext.oid",
            )
            if oid_tag == TAG_OID:
                oid_str = read_oid(
                    data[oid_body:oid_end], local_anomalies, "ext.oid",
                )
                oids_seen.append(oid_str)
            inner = oid_end

            if inner < ext_end:
                next_tag, _, next_body, next_end = read_tlv(
                    data, inner, local_anomalies, "ext.maybe_critical",
                )
                if next_tag == TAG_BOOLEAN:
                    critical = bool(
                        data[next_body:next_end] != b"\x00"
                    )
                    inner = next_end

            if inner < ext_end:
                v_tag, _, v_body, v_end = read_tlv(
                    data, inner, local_anomalies, "ext.value",
                )
                if v_tag == TAG_OCTET_STRING:
                    value_bytes = data[v_body:v_end]
        except ASN1ParseError:
            pass

        san_entries: tuple[SubjectAltName, ...] | None = None
        if oid_str == OID_CE_SUBJECT_ALT_NAME and value_bytes:
            san_entries = _parse_san_value(
                value_bytes, local_anomalies, oids_seen,
            )
            san_out.extend(san_entries)

        ext_out.append(X509Extension(
            oid=oid_str,
            critical=critical,
            value_hex=value_bytes.hex(),
            san_entries=san_entries,
        ))
        cur = ext_end

    return local_anomalies, san_out, ext_out


def _parse_san_value(
    value_bytes: bytes,
    anomalies: list[DERAnomaly],
    oids_seen: list[str],
) -> tuple[SubjectAltName, ...]:
    """Parse the OCTET STRING contents of a SubjectAltName extension.

    Recognized GeneralName CHOICE branches per RFC 5280:
      [0] otherName, [1] rfc822Name, [2] dNSName, [4] directoryName,
      [6] uniformResourceIdentifier, [7] iPAddress, [8] registeredID

    OIDs encountered inside SAN entries (otherName.type-id and
    registeredID's value) are appended to oids_seen so analyzers
    can use that list as a cheap "is anything weird in here" filter
    that covers the smuggling channels, not just the structural OIDs.
    """
    out: list[SubjectAltName] = []

    try:
        seq_tag, _, seq_body, seq_end = read_tlv(
            value_bytes, 0, anomalies, "ext.san",
        )
    except ASN1ParseError:
        return tuple(out)

    if seq_tag != TAG_SEQUENCE:
        anomalies.append(DERAnomaly(
            "ext.san", "unexpected_tag",
            f"SAN value should be SEQUENCE, got {_tag_name(seq_tag)}",
        ))
        return tuple(out)

    cur = seq_body
    while cur < seq_end:
        try:
            gn_tag, _, gn_body, gn_end = read_tlv(
                value_bytes, cur, anomalies, "ext.san.entry",
            )
        except ASN1ParseError:
            break

        if gn_tag.tag_class != TAG_CLASS_CONTEXT:
            anomalies.append(DERAnomaly(
                "ext.san.entry", "unexpected_tag",
                f"GeneralName has non-context tag {_tag_name(gn_tag)}",
            ))
            cur = gn_end
            continue

        gn_value = value_bytes[gn_body:gn_end]
        n = gn_tag.number
        if n == 1:
            out.append(SubjectAltName(
                kind="email",
                value=read_ia5_string(gn_value, anomalies, "ext.san.email"),
            ))
        elif n == 2:
            out.append(SubjectAltName(
                kind="dns",
                value=read_ia5_string(gn_value, anomalies, "ext.san.dns"),
            ))
        elif n == 4:
            try:
                inner_tag, _, inner_body, inner_end = read_tlv(
                    value_bytes, gn_body, anomalies,
                    "ext.san.directory.inner",
                )
                if inner_tag == TAG_SEQUENCE:
                    parts = _walk_name(
                        value_bytes, inner_body, inner_end, anomalies,
                        "ext.san.directory", [],
                    )
                    rendered = ", ".join(
                        f"{k}={v}" for k, v in parts.items()
                    )
                    out.append(SubjectAltName(
                        kind="directory", value=rendered,
                    ))
                else:
                    out.append(SubjectAltName(
                        kind="directory", value="(malformed)",
                    ))
            except ASN1ParseError:
                pass
        elif n == 6:
            out.append(SubjectAltName(
                kind="uri",
                value=read_ia5_string(gn_value, anomalies, "ext.san.uri"),
            ))
        elif n == 7:
            if len(gn_value) == 4:
                ip = ".".join(str(b) for b in gn_value)
            elif len(gn_value) == 16:
                ip = ":".join(
                    gn_value[i:i+2].hex() for i in range(0, 16, 2)
                )
            else:
                ip = gn_value.hex()
                anomalies.append(DERAnomaly(
                    "ext.san.ip", "unexpected_ip_length",
                    f"iPAddress has length {len(gn_value)} (expected 4 or 16)",
                ))
            out.append(SubjectAltName(kind="ip", value=ip))
        elif n == 0:
            other_oid = ""
            other_hex = gn_value.hex()
            try:
                tid_tag, _, tid_body, tid_end = read_tlv(
                    value_bytes, gn_body, anomalies, "ext.san.other.oid",
                )
                if tid_tag == TAG_OID:
                    other_oid = read_oid(
                        value_bytes[tid_body:tid_end], anomalies,
                        "ext.san.other.oid",
                    )
                    if other_oid:
                        oids_seen.append(other_oid)
            except ASN1ParseError:
                pass
            out.append(SubjectAltName(
                kind="other_name",
                value=f"{other_oid} hex={other_hex[:64]}",
                type_id=other_oid,
            ))
        elif n == 8:
            regid_oid = read_oid(gn_value, anomalies, "ext.san.regid")
            if regid_oid:
                oids_seen.append(regid_oid)
            out.append(SubjectAltName(
                kind="registered_id",
                value=regid_oid,
                type_id=regid_oid,
            ))
        else:
            anomalies.append(DERAnomaly(
                "ext.san.entry", "unknown_general_name",
                f"unrecognized GeneralName tag [{n}]",
            ))
            out.append(SubjectAltName(
                kind=f"unknown_{n}", value=gn_value.hex(),
            ))

        cur = gn_end

    return tuple(out)