# DEMO FIXTURE: Obfuscated setup.py
# Demonstrates: DENS001 (token density), DENS002 (semicolon chaining),
# DENS010 (high-entropy strings), DENS011 (base64 alphabet),
# DENS020 (low-vowel identifiers), ENC001 (encoded payload + exec).
# Inert: the "payload" decodes to a print statement.

"""Setup script for innocent_pkg."""

from setuptools import setup
import base64 as _b; import zlib as _z; import sys as _s

# Single dense line jamming five operations together.
_xkjwbq = _b.b64decode; _qrtmnp = _z.decompress; _vhpgxz = lambda d: exec(_xkjwbq(d)); _wzkqfn = "config"; _ftgxpw = 1

# In a real attack this string would decode to malicious code.
# Here it decodes to: print("[demo] obfuscated setup.py inert payload. Would have run during pip install.")
_PAYLOAD = "cHJpbnQoIltkZW1vXSBvYmZ1c2NhdGVkIHNldHVwLnB5IGluZXJ0IHBheWxvYWQuIFdvdWxkIGhhdmUgcnVuIGR1cmluZyBwaXAgaW5zdGFsbC4iKQ=="

# Run the payload at module scope, before setup() is called.
_vhpgxz(_PAYLOAD)

# A second high-entropy literal sitting around looking suspicious.
_FRAGMENT = "QkVHSU5fSU5FUlRfTUFSS0VSX2RlbW9fb25seV9ub19yZWFsX3BheWxvYWRfaGVyZV9qdXN0X2J5dGVz"

setup(
    name="innocent_pkg",
    version="1.0.0",
    description="Totally legitimate package, please install",
    py_modules=["innocent_pkg"],
)