#!/bin/bash
# Run all LAPS tests

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL_PASS=0
TOTAL_FAIL=0

run_test_suite() {
    local name="$1"
    local script="$2"

    echo ""
    echo "########################################"
    echo "# $name"
    echo "########################################"
    echo ""

    if bash "$script"; then
        echo ""
        echo "Suite PASSED"
    else
        echo ""
        echo "Suite FAILED"
        ((TOTAL_FAIL++)) || true
    fi
}

echo "========================================"
echo "LAPS Test Suite"
echo "========================================"
echo "Started: $(date)"
echo ""

# Wait for 1Password Connect to be ready
echo "Waiting for 1Password Connect..."
for i in {1..30}; do
    if curl -s "${FLEET_SECRET_OP_CONNECT_HOST}/health" > /dev/null 2>&1; then
        echo "1Password Connect is ready"
        break
    fi
    echo "  Waiting... ($i/30)"
    sleep 2
done

# Run test suites
run_test_suite "API Tests" "$SCRIPT_DIR/test-api.sh"
run_test_suite "Password Generation Tests" "$SCRIPT_DIR/test-password-gen.sh"
run_test_suite "End-to-End Tests" "$SCRIPT_DIR/test-e2e.sh"

# Script logic tests - check both container path and local path
if [[ -f "/scripts/laps-macos.sh" ]] || [[ -f "$SCRIPT_DIR/../scripts/laps-macos.sh" ]]; then
    run_test_suite "Script Logic Tests" "$SCRIPT_DIR/test-script-logic.sh"
fi

echo ""
echo "========================================"
echo "All Test Suites Complete"
echo "========================================"
echo "Finished: $(date)"

if [[ $TOTAL_FAIL -eq 0 ]]; then
    echo "Status: ALL PASSED"
    exit 0
else
    echo "Status: $TOTAL_FAIL suite(s) FAILED"
    exit 1
fi
