#!/bin/bash
# LAPS Script Logic Tests (Dry Run Mode)

set -euo pipefail

PASS=0
FAIL=0

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAPS_SCRIPT="${SCRIPT_DIR}/../scripts/laps-macos.sh"

log_test() { echo "[TEST] $1"; }
log_pass() { echo "  ✓ PASS: $1"; ((PASS++)) || true; }
log_fail() { echo "  ✗ FAIL: $1"; ((FAIL++)) || true; }

# Ensure dry run mode
export LAPS_DRY_RUN=1
export LAPS_DEBUG=1

# Test: Script validates missing config
test_missing_config() {
    log_test "Missing Configuration Detection"

    # Temporarily unset required var
    local saved_token="$OP_CONNECT_TOKEN"
    unset OP_CONNECT_TOKEN

    output=$("$LAPS_SCRIPT" 2>&1 || true)
    exit_code=$?

    export OP_CONNECT_TOKEN="$saved_token"

    if [[ "$output" == *"Missing required environment variables"* ]] || [[ $exit_code -eq 2 ]]; then
        log_pass "Missing config detected correctly"
    else
        log_fail "Should have detected missing OP_CONNECT_TOKEN"
    fi
}

# Test: Script runs in dry run mode without errors
test_dry_run_mode() {
    log_test "Dry Run Mode Execution"

    # Mock hostname for testing
    export HOSTNAME="TEST-HOST-001"

    output=$("$LAPS_SCRIPT" 2>&1 || true)

    if [[ "$output" == *"DRY RUN MODE"* ]]; then
        log_pass "Dry run mode acknowledged"
    else
        log_fail "Dry run mode not detected in output"
    fi

    if [[ "$output" == *"[DRY RUN] Would create"* ]] || [[ "$output" == *"[DRY RUN] Would update"* ]]; then
        log_pass "Dry run shows intended actions"
    else
        log_fail "Dry run should show intended actions"
    fi
}

# Test: Script detects existing vs new setup
test_mode_detection() {
    log_test "Setup vs Rotation Mode Detection"

    output=$("$LAPS_SCRIPT" 2>&1 || true)

    if [[ "$output" == *"Running in SETUP mode"* ]] || [[ "$output" == *"Running in ROTATION mode"* ]]; then
        log_pass "Mode correctly detected"
    else
        log_fail "Mode detection not found in output"
    fi
}

echo "=========================================="
echo "LAPS Script Logic Tests"
echo "=========================================="
echo ""

test_missing_config
test_dry_run_mode
test_mode_detection

echo ""
echo "=========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "=========================================="

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
