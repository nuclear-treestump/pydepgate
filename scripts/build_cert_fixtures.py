"""Generate three test cert fixtures.

This is the script that produced the hex literals committed in
test_asn1.py. Run once; the output is frozen into the test file.
Re-running this script will produce different cert bytes (different
serial number, different signature, different timestamp), so do not
re-run it casually.
"""

"""
This does not violate the 'stdlib-only' constraint for pydepgate code
because it's a standalone script that is not imported or executed by
any pydepgate component. It is a development tool for generating test
fixtures, not part of the pydepgate codebase itself.
"""

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    BasicConstraints, KeyUsage, ExtendedKeyUsage,
    SubjectAlternativeName, DNSName, UniformResourceIdentifier,
    RFC822Name, IPAddress, OtherName, UnrecognizedExtension,
)
from ipaddress import IPv4Address

def _to_hex_chunks(data: bytes, width: int = 16) -> str:
    """Format bytes as Python-source-friendly hex literals."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f'    b"\\x{chunk.hex(chr(92) + chr(120))}"  # {hex_str}'
                     .replace(chr(92) + "x", chr(92) + "x"))
    return "\n".join(lines)


def _to_python_bytes_literal(data: bytes, name: str) -> str:
    """Render bytes as `NAME = bytes.fromhex(...)` for clean test fixtures."""
    chunks = []
    hex_full = data.hex()
    for i in range(0, len(hex_full), 64):
        chunks.append(f'    "{hex_full[i:i+64]}"')
    body = "\n".join(chunks)
    return f"{name} = bytes.fromhex(\n{body}\n)"


# Common: RSA-2048 key for cert 1 and cert 3.
key2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
key4096 = rsa.generate_private_key(public_exponent=65537, key_size=4096)


# ---------------------------------------------------------------------------
# Cert 1: vanilla RSA-2048 with a normal subject, no SAN, no extensions.
# ---------------------------------------------------------------------------

subject1 = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Test Unit"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
])

cert1 = (
    x509.CertificateBuilder()
    .subject_name(subject1)
    .issuer_name(subject1)
    .public_key(key2048.public_key())
    .serial_number(12345)
    .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
    .not_valid_after(datetime(2026, 1, 1, tzinfo=timezone.utc))
    .sign(key2048, hashes.SHA256())
)

# ---------------------------------------------------------------------------
# Cert 2: RSA-2048 with populated SAN (DNS, URI, email, IP) and extensions.
# ---------------------------------------------------------------------------

subject2 = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "richcert.example.com"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Rich Org"),
])

cert2 = (
    x509.CertificateBuilder()
    .subject_name(subject2)
    .issuer_name(subject2)
    .public_key(key2048.public_key())
    .serial_number(67890)
    .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
    .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
    .add_extension(
        SubjectAlternativeName([
            DNSName("alt1.example.com"),
            DNSName("alt2.example.com"),
            UniformResourceIdentifier("https://example.com/cert"),
            RFC822Name("admin@example.com"),
            IPAddress(IPv4Address("192.0.2.42")),
        ]),
        critical=False,
    )
    .add_extension(
        BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    .add_extension(
        KeyUsage(
            digital_signature=True, key_encipherment=True,
            content_commitment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=False,
    )
    .sign(key2048, hashes.SHA256())
)

# ---------------------------------------------------------------------------
# Cert 3: RSA-4096 with deliberately suspicious-looking fields.
# - High-entropy CN
# - otherName SAN entry with custom OID
# - Critical extension with unrecognized OID
# - notAfter year 9999 (the X.509 "no expiration" sentinel)
# ---------------------------------------------------------------------------

subject3 = x509.Name([
    x509.NameAttribute(
        NameOID.COMMON_NAME,
        "x7Kp9mZ4nQrT2vWy8AbCdEfGhJkLmNoPqRsTuVwXyZ123456789",
    ),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Suspicious Org"),
])

other_name_oid = ObjectIdentifier("1.3.6.1.4.1.99999.1.2.3")
suspicious_ext_oid = ObjectIdentifier("1.3.6.1.4.1.99999.7.7.7")

# OtherName value must be valid DER. Use an OCTET STRING wrapping
# our payload bytes so cryptography accepts it.
_other_payload = b"arbitrary-payload"
_other_value = bytes([0x04, len(_other_payload)]) + _other_payload

cert3 = (
    x509.CertificateBuilder()
    .subject_name(subject3)
    .issuer_name(subject3)
    .public_key(key4096.public_key())
    .serial_number(0xdeadbeefcafebabe)
    .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
    .not_valid_after(datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc))
    .add_extension(
        SubjectAlternativeName([
            DNSName("totallynotac2.example.com"),
            OtherName(other_name_oid, _other_value),
        ]),
        critical=False,
    )
    .add_extension(
        UnrecognizedExtension(
            suspicious_ext_oid,
            b"\x04\x20unknown-critical-extension-data",
        ),
        critical=True,
    )
    .sign(key4096, hashes.SHA256())
)


# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------

certs = [
    ("CERT_VANILLA_RSA2048", cert1),
    ("CERT_RICH_SAN", cert2),
    ("CERT_SUSPICIOUS", cert3),
]

print("# Generated by build_cert_fixtures.py. Do not regenerate without")
print("# updating the assertions in the test file accordingly.")
print()
for name, cert in certs:
    der = cert.public_bytes(serialization.Encoding.DER)
    print(f"# {name}: {len(der)} bytes")
    print(_to_python_bytes_literal(der, name))
    print()