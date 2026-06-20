#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG="$SCRIPT_DIR/promptfooconfig.json"
MERGED="$SCRIPT_DIR/results_merged.json"

# Count total tests
TOTAL=$(python3 -c "import json; print(len(json.load(open('$CONFIG'))['tests']))")
echo "=== Batched eval: $TOTAL test cases ==="

# Split into batches of ~9
BATCH_SIZE=9
BATCH=0

# Initialize merged results
echo '[]' > "$MERGED"

for ((START=0; START<TOTAL; START+=BATCH_SIZE)); do
    BATCH=$((BATCH + 1))
    END=$((START + BATCH_SIZE))
    if [ $END -gt $TOTAL ]; then END=$TOTAL; fi

    echo ""
    echo "--- Batch $BATCH: tests $((START+1))–$END of $TOTAL ---"

    # Create a batch config with only this slice of tests
    BATCH_CONFIG="$SCRIPT_DIR/batch_${BATCH}.json"
    python3 -c "
import json
config = json.load(open('$CONFIG'))
config['tests'] = config['tests'][$START:$END]
config['description'] = f\"Batch $BATCH: tests $((START+1))-$END\"
json.dump(config, open('$BATCH_CONFIG', 'w'), indent=2)
print(f'  {len(config[\"tests\"])} test cases in batch')
"

    BATCH_RESULTS="$SCRIPT_DIR/results_batch_${BATCH}.json"

    npx promptfoo@latest eval \
        --config "$BATCH_CONFIG" \
        --max-concurrency 2 \
        --no-cache \
        --output "$BATCH_RESULTS" 2>&1 || {
            echo "  WARNING: Batch $BATCH failed, continuing..."
            continue
        }

    # Merge batch results into combined file
    python3 -c "
import json
merged = json.load(open('$MERGED'))
try:
    batch = json.load(open('$BATCH_RESULTS'))
    if isinstance(batch, dict) and 'results' in batch:
        merged.extend(batch['results'])
    elif isinstance(batch, list):
        merged.extend(batch)
    else:
        merged.append(batch)
except Exception as e:
    print(f'  Could not parse batch results: {e}')
json.dump(merged, open('$MERGED', 'w'), indent=2)
print(f'  Merged. Total results so far: {len(merged)}')
"

    echo "  Batch $BATCH complete."
done

echo ""
echo "=== All batches complete ==="
echo "Merged results: $MERGED"
echo "View individual batches: $SCRIPT_DIR/results_batch_*.json"
