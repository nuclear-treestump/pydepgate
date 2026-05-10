#!/usr/bin/env bash
# scripts/validate_sarif.sh
#
# Local equivalent of .github/workflows/do_sarif_validation.yml.
# Builds the synthetic fixtures, runs pydepgate against each one
# in SARIF format, and validates the output with the Microsoft
# SARIF Multitool.
#
# Useful when iterating on SARIF emission changes before pushing
# to CI: catch validation issues on your machine instead of
# round-tripping through the runner.
#
# Requirements:
#   - Python 3.12+ with pydepgate installed (pip install -e . in
#     a checkout of the repo).
#   - .NET SDK 8.0+ for the Sarif.Multitool package.
#
# Usage:
#   scripts/validate_sarif.sh
#       Build fixtures, scan all three, validate output. Default.
#
#   scripts/validate_sarif.sh path/to/target.whl
#       Scan a specific target instead of the fixtures. Useful
#       for verifying SARIF output against a real-world wheel.
#
# Exit codes:
#   0   All SARIF documents validate cleanly.
#   1   At least one document failed validation. The specific
#       failures appear on stderr.
#   2   Tool prerequisite missing (.NET SDK, pydepgate, or python).

set -euo pipefail

# ---------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------

# Pin the Multitool version explicitly. Bump in lockstep with the
# CI workflow when reviewing the pin (recommended quarterly). If
# you bump here and not in the YAML, the local and CI behavior
# diverge. The latest stable as of writing was 4.5.4; verify on
# https://www.nuget.org/packages/Sarif.Multitool before bumping.
MULTITOOL_VERSION="4.5.4"

# Output directory for SARIF documents and fixture wheels.
WORK_DIR="${SARIF_VALIDATE_WORK_DIR:-/tmp/pydepgate-sarif-validate}"
FIXTURES_DIR="${WORK_DIR}/fixtures"
OUTPUT_DIR="${WORK_DIR}/output"

# ---------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------

require_command() {
    local cmd="$1"
    local install_hint="$2"
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: required command '$cmd' not found." >&2
        echo "Install hint: $install_hint" >&2
        exit 2
    fi
}

require_command python3 "Install Python 3.12 or later"
require_command pydepgate "pip install -e . in the repo root"
require_command dotnet "https://dotnet.microsoft.com/download"

# Ensure ~/.dotnet/tools is on PATH so locally-installed dotnet
# tools resolve. dotnet does not add it automatically on first
# install in some shells.
if [[ ":$PATH:" != *":$HOME/.dotnet/tools:"* ]]; then
    export PATH="$PATH:$HOME/.dotnet/tools"
fi

# Install the Multitool if missing, or update if version mismatch.
if ! command -v sarif &>/dev/null; then
    echo "Installing Sarif.Multitool $MULTITOOL_VERSION..."
    dotnet tool install -g Sarif.Multitool --version "$MULTITOOL_VERSION"
else
    installed_version=$(sarif --version 2>/dev/null | head -n1 || echo "unknown")
    if [[ "$installed_version" != *"$MULTITOOL_VERSION"* ]]; then
        echo "Updating Sarif.Multitool from '$installed_version' to '$MULTITOOL_VERSION'..."
        dotnet tool update -g Sarif.Multitool --version "$MULTITOOL_VERSION"
    fi
fi

# ---------------------------------------------------------------
# Working directory setup
# ---------------------------------------------------------------

mkdir -p "$FIXTURES_DIR" "$OUTPUT_DIR"

# Locate the fixture builder script. The script lives next to
# this file in scripts/, so we resolve relative to ourselves.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_BUILDER="$SCRIPT_DIR/build_sarif_fixtures.py"

if [[ ! -f "$FIXTURE_BUILDER" ]]; then
    echo "Error: fixture builder not found at $FIXTURE_BUILDER" >&2
    exit 2
fi

# ---------------------------------------------------------------
# Scan and validate
# ---------------------------------------------------------------

scan_and_validate() {
    local target="$1"
    local label="$2"
    local extra_flags=("${@:3}")
    local sarif_file="$OUTPUT_DIR/${label}.sarif"

    echo
    echo "===> Scanning $target ($label)"
    pydepgate scan "$target" --format sarif "${extra_flags[@]}" \
        > "$sarif_file" 2>/dev/null || {
        # pydepgate exits non-zero when it finds blocking findings.
        # That is expected behavior, not a scan failure.
        echo "  (pydepgate exit was non-zero; findings may be present)"
    }

    echo "===> Validating $sarif_file"
    if sarif validate "$sarif_file"; then
        echo "  OK: $label"
        return 0
    else
        echo "  FAIL: $label" >&2
        return 1
    fi
}

failures=0

if [[ $# -ge 1 ]]; then
    # User supplied a specific target. Scan that, validate, exit.
    target="$1"
    if [[ ! -f "$target" ]]; then
        echo "Error: target file not found: $target" >&2
        exit 2
    fi
    scan_and_validate "$target" "custom" || failures=$((failures + 1))
else
    # Default: build fixtures, scan all three, validate all.
    echo "===> Building synthetic fixtures in $FIXTURES_DIR"
    python3 "$FIXTURE_BUILDER" "$FIXTURES_DIR"

    # Clean fixture: no decode flags. Bare SARIF emission.
    scan_and_validate \
        "$FIXTURES_DIR/pydepgate-clean-fixture-1.0.0-py3-none-any.whl" \
        "clean" \
        || failures=$((failures + 1))

    # With-findings fixture: no decode flags either, since the
    # findings are on the high-entropy literal itself, not the
    # decoded content.
    scan_and_validate \
        "$FIXTURES_DIR/pydepgate-with-findings-fixture-1.0.0-py3-none-any.whl" \
        "with_findings" \
        || failures=$((failures + 1))

    # With-codeflows fixture: scan twice, once without decode and
    # once with, to validate both Phase C only and Phase C plus
    # Phase D emission paths.
    scan_and_validate \
        "$FIXTURES_DIR/pydepgate-with-codeflows-fixture-1.0.0-py3-none-any.whl" \
        "with_codeflows_no_decode" \
        || failures=$((failures + 1))

    scan_and_validate \
        "$FIXTURES_DIR/pydepgate-with-codeflows-fixture-1.0.0-py3-none-any.whl" \
        "with_codeflows_decoded" \
        --peek --decode-payload-depth=4 \
        || failures=$((failures + 1))
fi

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------

echo
if [[ $failures -eq 0 ]]; then
    echo "All SARIF documents validated successfully."
    echo "Documents preserved in: $OUTPUT_DIR"
    exit 0
else
    echo "$failures SARIF document(s) failed validation." >&2
    echo "Documents preserved in: $OUTPUT_DIR" >&2
    exit 1
fi