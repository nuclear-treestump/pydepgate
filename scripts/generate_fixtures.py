"""Regenerate .pth test fixtures that can't be reliably hand-edited.

Run from the project root:
    python scripts/generate_fixtures.py

Idempotent. running repeatedly produces byte-identical output.
"""

import pathlib

FIXTURES = pathlib.Path(__file__).parent.parent / "tests" / "fixtures" / "pth"


def write(name: str, content: bytes) -> None:
    path = FIXTURES / name
    path.write_bytes(content)
    print(f"  {name}: {len(content)} bytes")


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    print(f"Writing generated fixtures to {FIXTURES}:")

    write("empty.pth", b"")

    write("only_whitespace.pth", b"\n\n   \n\t\n\n")

    write("malformed_encoding.pth", b"\xff\xfe/some/path\n")

    write("malformed_bare_cr.pth", b"/path/one\r/path/two\r/path/three")

    oversized = b"# This fixture is deliberately oversized.\n"
    oversized += b"# Real .pth files are almost always under 200 bytes.\n"
    oversized += b"# The LiteLLM malware was 34KB; this is a scaled-down analog.\n"
    oversized += (b"# " + b"x" * 75 + b"\n") * 25
    oversized += b"import base64; exec(base64.b64decode('cHJpbnQoMSk='))\n"
    write("synthetic_oversized.pth", oversized)


if __name__ == "__main__":
    main()