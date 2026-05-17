#!/usr/bin/env bash
# pydepgate-equiv.sh
# Run each scan twice (serial + parallel), compare findings counts.

set -u

PARALLEL_WORKERS="${PARALLEL_WORKERS:-2}"
OUTPUT_DIR="${OUTPUT_DIR:-./equiv-results}"

mkdir -p "$OUTPUT_DIR"
: > "$OUTPUT_DIR/_mismatches.tsv"
: > "$OUTPUT_DIR/_results.tsv"

# Helper: count findings in JSON output (works with stdlib python)
count_findings() {
    python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(len(d.get('findings', [])))
except Exception as exc:
    print(f'ERROR:{exc}', file=sys.stderr)
    print('-1')
"
}

PACKAGES=$(pip freeze \
    | grep -v '^-e ' \
    | grep -v '^#' \
    | grep -v '/' \
    | sed -E 's/[=<>!~].*//' \
    | sort -u)

total=$(echo "$PACKAGES" | wc -l | tr -d ' ')
echo "Comparing serial vs parallel (workers=$PARALLEL_WORKERS, force-parallel) across $total packages"
echo ""

mismatches=0
matches=0
errors=0

while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue

    # Serial: no --workers, no --force-parallel
    serial_json=$(pydepgate --format json scan "$pkg" 2>/dev/null)
    serial_rc=$?
    serial_count=$(echo "$serial_json" | count_findings)

    # Parallel: --workers N --force-parallel so the pool engages
    # regardless of file count
    parallel_json=$(pydepgate --workers "$PARALLEL_WORKERS" \
        --force-parallel --format json scan "$pkg" 2>/dev/null)
    parallel_rc=$?
    parallel_count=$(echo "$parallel_json" | count_findings)

    if [ "$serial_count" = "-1" ] || [ "$parallel_count" = "-1" ]; then
        printf "  %-40s SERIAL=%-5s PARALLEL=%-5s ERROR\n" \
            "$pkg" "$serial_count" "$parallel_count"
        errors=$((errors+1))
        continue
    fi

    if [ "$serial_count" = "$parallel_count" ]; then
        printf "  %-40s SERIAL=%-5s PARALLEL=%-5s OK\n" \
            "$pkg" "$serial_count" "$parallel_count"
        matches=$((matches+1))
    else
        printf "  %-40s SERIAL=%-5s PARALLEL=%-5s MISMATCH\n" \
            "$pkg" "$serial_count" "$parallel_count"
        mismatches=$((mismatches+1))
        printf "%s\t%s\t%s\n" \
            "$pkg" "$serial_count" "$parallel_count" \
            >> "$OUTPUT_DIR/_mismatches.tsv"
        # Save both outputs for diffing
        echo "$serial_json" > "$OUTPUT_DIR/${pkg}.serial.json"
        echo "$parallel_json" > "$OUTPUT_DIR/${pkg}.parallel.json"
    fi

    printf "%s\t%s\t%s\t%s\n" \
        "$pkg" "$serial_count" "$parallel_count" \
        "$([ "$serial_count" = "$parallel_count" ] && echo OK || echo MISMATCH)" \
        >> "$OUTPUT_DIR/_results.tsv"
done <<< "$PACKAGES"

echo ""
echo "=================================================="
echo "Matches:    $matches"
echo "Mismatches: $mismatches"
echo "Errors:     $errors"
echo "=================================================="
[ "$mismatches" -gt 0 ] && \
    echo "Mismatches saved to: $OUTPUT_DIR/_mismatches.tsv"
[ "$mismatches" -gt 0 ] && \
    echo "Diff a mismatch with: diff <(jq . FILE.serial.json) <(jq . FILE.parallel.json)"