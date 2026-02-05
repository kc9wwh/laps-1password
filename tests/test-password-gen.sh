#!/bin/bash
# Password Generation Tests

set -euo pipefail

PASS=0
FAIL=0
TEST_ADMIN_USER="${LAPS_ADMIN_USERNAME:-laps-admin}"
TEST_ITEM_ID=""
TEST_ITEM_RESPONSE=""

log_test() { echo "[TEST] $1"; }
log_pass() { echo "  ✓ PASS: $1"; ((PASS++)) || true; }
log_fail() { echo "  ✗ FAIL: $1"; ((FAIL++)) || true; }

cleanup() {
    if [[ -n "$TEST_ITEM_ID" ]]; then
        echo "Cleaning up test item: $TEST_ITEM_ID"
        curl -s -o /dev/null -X DELETE \
            -H "Authorization: Bearer ${OP_CONNECT_TOKEN}" \
            "${OP_CONNECT_HOST}/v1/vaults/${OP_VAULT_ID}/items/${TEST_ITEM_ID}" || true
    fi
}
trap cleanup EXIT

# Test: Create item with generated password
test_password_generation() {
    log_test "Password Generation on Create"

    local payload=$(cat <<EOF
{
    "vault": {"id": "${OP_VAULT_ID}"},
    "title": "TEST-LAPS-$(date +%s)",
    "category": "LOGIN",
    "fields": [
        {
            "id": "username",
            "type": "STRING",
            "purpose": "USERNAME",
            "label": "username",
            "value": "${TEST_ADMIN_USER}"
        },
        {
            "id": "password",
            "type": "CONCEALED",
            "purpose": "PASSWORD",
            "label": "password",
            "generate": true,
            "recipe": {
                "length": 28,
                "characterSets": ["LETTERS", "DIGITS", "SYMBOLS"]
            }
        }
    ]
}
EOF
)

    TEST_ITEM_RESPONSE=$(curl -s -X POST \
        -H "Authorization: Bearer ${OP_CONNECT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "${OP_CONNECT_HOST}/v1/vaults/${OP_VAULT_ID}/items")

    TEST_ITEM_ID=$(echo "$TEST_ITEM_RESPONSE" | jq -r '.id // empty')
    password=$(echo "$TEST_ITEM_RESPONSE" | jq -r '.fields[] | select(.purpose == "PASSWORD") | .value // empty')

    if [[ -z "$TEST_ITEM_ID" ]]; then
        log_fail "Failed to create item"
        return
    fi

    if [[ -z "$password" ]]; then
        log_fail "No password in response"
        return
    fi

    # Validate password length
    if [[ ${#password} -ge 28 ]]; then
        log_pass "Password generated with correct length (${#password} chars)"
    else
        log_fail "Password too short: ${#password} chars"
    fi

    # Validate password contains required character sets
    if [[ "$password" =~ [A-Z] ]]; then
        log_pass "Password contains uppercase"
    else
        log_fail "Password missing uppercase"
    fi

    if [[ "$password" =~ [a-z] ]]; then
        log_pass "Password contains lowercase"
    else
        log_fail "Password missing lowercase"
    fi

    if [[ "$password" =~ [0-9] ]]; then
        log_pass "Password contains digits"
    else
        log_fail "Password missing digits"
    fi

    # Wait for 1Password Connect to sync the new item
    echo "  Waiting for sync..."
    sleep 2
}

# Test: Update item regenerates password
test_password_rotation() {
    log_test "Password Rotation on Update"

    if [[ -z "$TEST_ITEM_ID" ]]; then
        log_fail "No test item to update"
        return
    fi

    if [[ -z "$TEST_ITEM_RESPONSE" ]]; then
        log_fail "No saved item response to use for update"
        return
    fi

    # Use the saved response from creation (GET doesn't return field values)
    old_password=$(echo "$TEST_ITEM_RESPONSE" | jq -r '.fields[] | select(.purpose == "PASSWORD") | .value')

    if [[ -z "$old_password" ]]; then
        log_fail "Could not get current password from saved response"
        return
    fi

    # Update with generate flag
    updated=$(echo "$TEST_ITEM_RESPONSE" | jq '
        .fields = [.fields[] |
            if .purpose == "PASSWORD" then
                .generate = true |
                .recipe = {"length": 28, "characterSets": ["LETTERS", "DIGITS", "SYMBOLS"]}
            else . end
        ]
    ')

    response=$(curl -s -X PUT \
        -H "Authorization: Bearer ${OP_CONNECT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$updated" \
        "${OP_CONNECT_HOST}/v1/vaults/${OP_VAULT_ID}/items/${TEST_ITEM_ID}")

    new_password=$(echo "$response" | jq -r '.fields[] | select(.purpose == "PASSWORD") | .value')

    if [[ "$new_password" != "$old_password" ]]; then
        log_pass "Password rotated successfully"
    else
        log_fail "Password was not rotated"
    fi
}

echo "=========================================="
echo "Password Generation Tests"
echo "=========================================="
echo ""

test_password_generation
test_password_rotation

echo ""
echo "=========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "=========================================="

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
