"""Build synthetic wheel fixtures for SARIF validation.

Three fixtures:

  clean             Empty package. No findings expected. Exercises
                    the "clean scan" SARIF emission path.

  with_findings     A package with high-entropy literals that
                    trigger DENS010/DENS011 but do not lead to
                    decode-pass findings. Exercises the Phase C
                    SARIF result emission.

  with_codeflows    A package with a 2-layer base64 chain whose
                    innermost layer contains a subprocess.run call.
                    Triggers DENS010 on the outer literal, decode
                    pass walks through both layers, STDLIB001 fires
                    on the innermost call. Exercises the Phase D
                    codeFlow emission.

All fixtures are deliberately benign:

- The high-entropy literals contain structured ASCII data, not
  encoded payloads.
- The "with_codeflows" innermost layer calls subprocess.run with
  ['echo', 'hello'] as the argument list. This is a harmless
  command that the analyzer pattern-matches as STDLIB001 because
  the pattern matches on the function called, not the arguments.
- No fixture contains any network URL, no fixture references any
  external host, and no fixture contains any actual malicious
  pattern beyond what is needed to trigger pydepgate's signals.

Usage:
    python scripts/build_sarif_fixtures.py /path/to/output/dir

Output:
    {output_dir}/pydepgate-clean-fixture-1.0.0-py3-none-any.whl
    {output_dir}/pydepgate-with-findings-fixture-1.0.0-py3-none-any.whl
    {output_dir}/pydepgate-with-codeflows-fixture-1.0.0-py3-none-any.whl

The script is stdlib-only by design. Wheel construction uses
zipfile + manual METADATA/WHEEL/RECORD generation per PEP 427.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import sys
import zipfile
from pathlib import Path

# Wheel format constants. PEP 427.
METADATA_VERSION = "2.1"
WHEEL_VERSION = "1.0"
WHEEL_GENERATOR = "pydepgate-fixture-builder 1.0"


def _record_entry(path: str, content: bytes) -> str:
    """Build a single RECORD line for a wheel file.

    Format: {path},sha256={base64-no-padding-of-digest},{size}
    Per PEP 427, the hash is base64 url-safe, padding stripped.
    """
    digest = hashlib.sha256(content).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"{path},sha256={encoded},{len(content)}"


def _build_wheel(
    name: str,
    version: str,
    output_dir: Path,
    files: dict[str, str],
) -> Path:
    """Construct a wheel from a name, version, and {path: content} mapping.

    Generates METADATA, WHEEL, and RECORD entries automatically.
    Returns the path to the built wheel file.
    """
    wheel_filename = f"{name}-{version}-py3-none-any.whl"
    wheel_path = output_dir / wheel_filename
    dist_info_dir = f"{name.replace('-', '_')}-{version}.dist-info"

    metadata = (
        f"Metadata-Version: {METADATA_VERSION}\n"
        f"Name: {name}\n"
        f"Version: {version}\n"
        f"Summary: Synthetic fixture for pydepgate SARIF validation\n"
    )

    wheel_meta = (
        f"Wheel-Version: {WHEEL_VERSION}\n"
        f"Generator: {WHEEL_GENERATOR}\n"
        f"Root-Is-Purelib: true\n"
        f"Tag: py3-none-any\n"
    )

    # Combine user files plus auto-generated metadata files.
    all_files = dict(files)
    all_files[f"{dist_info_dir}/METADATA"] = metadata
    all_files[f"{dist_info_dir}/WHEEL"] = wheel_meta

    # Build RECORD. Each line documents a file's hash and size.
    # The RECORD entry for itself uses empty hash and size, per
    # PEP 376 convention.
    record_lines = []
    for path, content in all_files.items():
        record_lines.append(_record_entry(path, content.encode("utf-8")))
    record_lines.append(f"{dist_info_dir}/RECORD,,")
    record_content = "\n".join(record_lines) + "\n"
    all_files[f"{dist_info_dir}/RECORD"] = record_content

    # Write the zip.
    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in all_files.items():
            zf.writestr(path, content)

    return wheel_path


def build_clean_fixture(output_dir: Path) -> Path:
    """Empty wheel. No findings expected.

    Verifies the SARIF emission path for clean scans: tool block,
    empty results array, originalUriBaseIds with placeholder URI.
    """
    return _build_wheel(
        name="pydepgate-clean-fixture",
        version="1.0.0",
        output_dir=output_dir,
        files={
            "pydepgate_clean_fixture/__init__.py": (
                '"""Empty package; pydepgate should produce no findings."""\n'
            ),
        },
    )


def build_with_findings_fixture(output_dir: Path) -> Path:
    """Wheel with a high-entropy literal that triggers DENS010/DENS011.

    The literal is structured ASCII repeating known-benign text.
    No decode pipeline, no exec, no network: only the entropy/
    alphabet density signals fire. Exercises the Phase C SARIF
    result emission.
    """
    # 400+ char ASCII string. Repeating 'BENIGN_STATIC_TEST_DATA'
    # variations to satisfy DENS010's length threshold while being
    # obviously not a real payload to a human reviewer. The
    # entropy is high enough to fire DENS010 because of the long
    # alphabet but the content is meaningful English-ish ASCII.
    benign_literal = (
        "BENIGN_STATIC_DATA_FOR_PYDEPGATE_FIXTURE_TESTING_NOT_A_PAYLOAD"
        "_BENIGN_STATIC_DATA_FOR_PYDEPGATE_FIXTURE_TESTING_NOT_A_PAYLOAD"
        "_BENIGN_STATIC_DATA_FOR_PYDEPGATE_FIXTURE_TESTING_NOT_A_PAYLOAD"
        "_BENIGN_STATIC_DATA_FOR_PYDEPGATE_FIXTURE_TESTING_NOT_A_PAYLOAD"
        "_BENIGN_STATIC_DATA_FOR_PYDEPGATE_FIXTURE_TESTING_NOT_A_PAYLOAD"
        "_BENIGN_STATIC_DATA_FOR_PYDEPGATE_FIXTURE_TESTING_NOT_A_PAYLOAD"
    )

    setup_py = (
        "# Synthetic fixture for pydepgate SARIF validation.\n"
        "#\n"
        "# Contains a long static literal that triggers DENS010\n"
        "# (high entropy) and DENS011 (alphabet density). The\n"
        "# literal is meaningful English text repeated many times,\n"
        "# not an encoded payload. Pydepgate's analyzer fires on\n"
        "# entropy and length thresholds; this fixture deliberately\n"
        "# meets those thresholds without being malicious.\n"
        "\n"
        f'BENIGN_LITERAL = "{benign_literal}"\n'
        "\n"
        "# Reference to silence linters; the literal is the point.\n"
        "_ = BENIGN_LITERAL\n"
    )

    return _build_wheel(
        name="pydepgate-with-findings-fixture",
        version="1.0.0",
        output_dir=output_dir,
        files={
            "pydepgate_with_findings_fixture/__init__.py": "",
            "setup.py": setup_py,
        },
    )


def build_with_codeflows_fixture(output_dir: Path) -> Path:
    """Wheel with a 2-layer base64 chain to a benign stdlib call.

    Layer 0 (setup.py): contains a base64 literal of layer 1.
    Layer 1 (decoded): contains a base64 literal of layer 2.
    Layer 2 (decoded): contains subprocess.run(['echo', 'hello']).

    Pydepgate's decode pass should walk both layers and emit a
    Phase D SARIF result with codeFlows showing the chain. The
    final stdlib call is a benign echo command; the analyzer
    pattern-matches on the function name (subprocess.run), not
    the arguments, so STDLIB001 fires regardless of the
    arguments being harmless.

    No network access, no actual malicious pattern. The fixture
    exercises the codeFlow emission path purely as a structural
    test.
    """
    # Layer 2: innermost decoded source. subprocess.run with echo.
    # Long enough that base64-encoding it produces a literal that
    # exceeds DENS010's threshold.
    layer2_source = (
        "# Innermost decoded source for the SARIF codeFlow fixture.\n"
        "# Calls subprocess.run with a benign command; pydepgate's\n"
        "# STDLIB001 fires on the function reference, not the args.\n"
        "import os\n"
        "import subprocess\n"
        "import sys\n"
        "\n"
        "\n"
        "def innermost_layer():\n"
        "    print('hello from the innermost decoded layer')\n"
        "    result = subprocess.run(\n"
        "        ['echo', 'hello-from-fixture'],\n"
        "        capture_output=True,\n"
        "        text=True,\n"
        "        check=False,\n"
        "    )\n"
        "    print('stdout:', result.stdout)\n"
        "    print('stderr:', result.stderr)\n"
        "    return result.returncode\n"
        "\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    sys.exit(innermost_layer())\n"
    )

    # Layer 1: contains layer 2 as a base64 literal.
    # b64decode call with no exec; decode pipeline still walks
    # through this layer because the high-entropy literal is what
    # triggers traversal, not the presence of an exec.
    layer2_b64 = base64.b64encode(layer2_source.encode("utf-8")).decode("ascii")
    layer1_source = (
        "# Middle decoded layer of the SARIF codeFlow fixture.\n"
        "# Contains a base64 literal of the innermost layer.\n"
        "import base64\n"
        "\n"
        f'INNER_PAYLOAD = "{layer2_b64}"\n'
        "\n"
        "# Decoded but not executed; pydepgate scans statically.\n"
        "_decoded = base64.b64decode(INNER_PAYLOAD)\n"
    )

    # Layer 0: setup.py with layer 1 as a base64 literal.
    layer1_b64 = base64.b64encode(layer1_source.encode("utf-8")).decode("ascii")
    setup_py = (
        "# Synthetic fixture for pydepgate SARIF codeFlow validation.\n"
        "#\n"
        "# Contains a base64 literal that decodes to a Python source\n"
        "# file containing another base64 literal that decodes to a\n"
        "# subprocess.run call. Pydepgate's decode pass walks both\n"
        "# layers and emits a Phase D codeFlow showing the chain.\n"
        "#\n"
        "# The deepest layer's call is a harmless 'echo' command;\n"
        "# the fixture is benign and reviewable as plain Python.\n"
        "import base64\n"
        "\n"
        f'PAYLOAD = "{layer1_b64}"\n'
        "\n"
        "_decoded = base64.b64decode(PAYLOAD)\n"
    )

    return _build_wheel(
        name="pydepgate-with-codeflows-fixture",
        version="1.0.0",
        output_dir=output_dir,
        files={
            "pydepgate_with_codeflows_fixture/__init__.py": "",
            "setup.py": setup_py,
        },
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point. Build all three fixtures into the output directory."""
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        help="Directory to write fixture wheels into. Created if missing.",
    )
    args = parser.parse_args(argv)

    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    builders = [
        ("clean", build_clean_fixture),
        ("with_findings", build_with_findings_fixture),
        ("with_codeflows", build_with_codeflows_fixture),
    ]

    print(f"Building fixtures in {output_dir}")
    for name, builder in builders:
        wheel_path = builder(output_dir)
        print(f"  {name}: {wheel_path.name}")
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
