#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_PYTHON="$PROJECT_ROOT/.venv/bin/python"

# Default provider
PROVIDER="${1:-ollama}"

echo "=== pydepgate injection resistance eval ==="
echo "Provider: $PROVIDER"
echo ""

# Step 1: Regenerate config from test suites
echo "Generating promptfoo config..."
"$VENV_PYTHON" "$SCRIPT_DIR/generate_config.py" --provider "$PROVIDER"
echo ""

# Step 2: Run promptfoo
echo "Running eval (27 test cases)..."
echo ""
npx promptfoo@latest eval \
    --config "$SCRIPT_DIR/promptfooconfig.json" \
    --max-concurrency 2 \
    --no-cache \
    --output "$SCRIPT_DIR/results.json"

echo ""
echo "=== Results ==="
npx promptfoo@latest eval --config "$SCRIPT_DIR/promptfooconfig.json" \
    --output "$SCRIPT_DIR/results.json" 2>/dev/null || true

# Step 3: Summary
echo ""
echo "Full results: $SCRIPT_DIR/results.json"
echo "View in browser: npx promptfoo@latest view"
