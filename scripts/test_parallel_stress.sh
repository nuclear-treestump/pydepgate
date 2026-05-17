#!/usr/bin/env bash
# pydepgate-stress.sh
# Basic stress test: scan every installed package, summarize.

set -u

WORKERS="${WORKERS:-2}"
OUTPUT_DIR="${OUTPUT_DIR:-./stress-results}"
FORCE_PARALLEL="${FORCE_PARALLEL:-0}"

mkdir -p "$OUTPUT_DIR"
: > "$OUTPUT_DIR/_summary.tsv"
: > "$OUTPUT_DIR/_failures.txt"

# Extract package names: strip version specs, skip editables and paths
PACKAGES=$(pip freeze \
    | grep -v '^-e ' \
    | grep -v '^#' \
    | grep -v '/' \
    | sed -E 's/[=<>!~].*//' \
    | sort -u)

total=$(echo "$PACKAGES" | wc -l | tr -d ' ')
echo "Scanning $total packages with --workers $WORKERS"
[ "$FORCE_PARALLEL" = "1" ] && echo "Force-parallel enabled"
echo ""

force_flag=""
[ "$FORCE_PARALLEL" = "1" ] && force_flag="--force-parallel"

i=0
clean=0
findings=0
errors=0
total_time=0

while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue
    i=$((i+1))

    out="$OUTPUT_DIR/${pkg}.json"
    err="$OUTPUT_DIR/${pkg}.err"

    start=$(date +%s.%N)
    pydepgate --workers "$WORKERS" $force_flag --format json scan "$pkg" \
        > "$out" 2> "$err"
    rc=$?
    end=$(date +%s.%N)
    elapsed=$(awk "BEGIN { print $end - $start }")

    case $rc in
        0)  status="CLEAN"; clean=$((clean+1)) ;;
        1) status="FINDINGS_LOW"; findings=$((findings+1)) ;;
        2) status="FINDINGS_BLOCKING"; findings=$((findings+1)) ;;
        3)  status="TOOL_ERROR"; errors=$((errors+1))
            echo "$pkg" >> "$OUTPUT_DIR/_failures.txt" ;;
        *)  status="UNKNOWN($rc)"; errors=$((errors+1))
            echo "$pkg (rc=$rc)" >> "$OUTPUT_DIR/_failures.txt" ;;
    esac

    printf "[%3d/%3d] %-40s %-20s %6.2fs\n" \
        "$i" "$total" "$pkg" "$status" "$elapsed"
    total_time=$(awk "BEGIN { print $total_time + $elapsed }")
    printf "%s\t%s\t%s\t%.2f\n" \
        "$pkg" "$status" "$rc" "$elapsed" \
        >> "$OUTPUT_DIR/_summary.tsv"
done <<< "$PACKAGES"

echo ""
echo "=================================================="
echo "Total scanned: $i"
echo "Clean:         $clean"
echo "With findings: $findings"
echo "Tool errors:   $errors"
echo "Total time:    ${total_time}s"
echo "=================================================="
echo "Results in:    $OUTPUT_DIR"
echo "Summary TSV:   $OUTPUT_DIR/_summary.tsv"
echo "Failures:      $OUTPUT_DIR/_failures.txt"