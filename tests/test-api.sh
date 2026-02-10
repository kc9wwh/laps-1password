#!/bin/bash
# API Connectivity and Basic Operations Tests

set -euo pipefail

PASS=0
FAIL=0

log_test() {
    echo "[TEST] $1"
}

log_pass() {
    echo "  ✓ PASS: $1"
    ((PASS++)) || true
}

log_fail() {
    echo "  ✗ FAIL: $1"
    ((FAIL++)) || true
}

# Test 1: Health Check
test_health_check() {
    log_test "Health Check"
    response=$(curl -s -o /dev/null -w "%{http_code}" "${FLEET_SECRET_OP_CONNECT_HOST}/health")
    if [[ "$response" == "200" ]]; then
        log_pass "Health endpoint returns 200"
    else
        log_fail "Health endpoint returned $response"
    fi
}

# Test 2: Authentication
test_authentication() {
    log_test "Authentication"
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer ${FLEET_SECRET_OP_CONNECT_TOKEN}" \
        "${FLEET_SECRET_OP_CONNECT_HOST}/v1/vaults")
    if [[ "$response" == "200" ]]; then
        log_pass "Authentication successful"
    else
        log_fail "Authentication failed with status $response"
    fi
}

# Test 3: Vault Access
test_vault_access() {
    log_test "Vault Access"
    response=$(curl -s \
        -H "Authorization: Bearer ${FLEET_SECRET_OP_CONNECT_TOKEN}" \
        "${FLEET_SECRET_OP_CONNECT_HOST}/v1/vaults/${FLEET_SECRET_OP_VAULT_ID}")

    vault_name=$(echo "$response" | jq -r '.name // empty')
    if [[ -n "$vault_name" ]]; then
        log_pass "Vault accessible: $vault_name"
    else
        log_fail "Cannot access vault"
    fi
}

# Test 4: Invalid Token
test_invalid_token() {
    log_test "Invalid Token Rejection"
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer invalid-token" \
        "${FLEET_SECRET_OP_CONNECT_HOST}/v1/vaults")
    if [[ "$response" == "401" ]]; then
        log_pass "Invalid token correctly rejected"
    else
        log_fail "Expected 401, got $response"
    fi
}

# Run all tests
echo "=========================================="
echo "1Password Connect API Tests"
echo "=========================================="
echo ""

test_health_check
test_authentication
test_vault_access
test_invalid_token

echo ""
echo "=========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "=========================================="

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
