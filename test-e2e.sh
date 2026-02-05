#!/bin/bash
# End-to-End LAPS Workflow Tests

set -euo pipefail

PASS=0
FAIL=0
TEST_HOSTNAME="E2E-TEST-$(date +%s)"
TEST_ADMIN_USER="${LAPS_ADMIN_USERNAME:-local-admin}"
CREATED_ITEM_ID=""
CREATED_ITEM_RESPONSE=""

log_test() { echo "[TEST] $1"; }
log_pass() { echo "  ✓ PASS: $1"; ((PASS++)) || true; }
log_fail() { echo "  ✗ FAIL: $1"; ((FAIL++)) || true; }

cleanup() {
    echo ""
    echo "Cleaning up test data..."
    if [[ -n "$CREATED_ITEM_ID" ]]; then
        curl -s -o /dev/null -X DELETE \
            -H "Authorization: Bearer ${OP_CONNECT_TOKEN}" \
            "${OP_CONNECT_HOST}/v1/vaults/${OP_VAULT_ID}/items/${CREATED_ITEM_ID}" || true
        echo "Deleted test item: $CREATED_ITEM_ID"
    fi
}
trap cleanup EXIT

# Helper: Search for item by title
search_item() {
    local title="$1"
    local encoded_title=$(printf '%s' "$title" | jq -sRr @uri)
    curl -s \
        -H "Authorization: Bearer ${OP_CONNECT_TOKEN}" \
        "${OP_CONNECT_HOST}/v1/vaults/${OP_VAULT_ID}/items?filter=title%20eq%20%22${encoded_title}%22"
}

# Test: Full setup workflow (simulated)
test_setup_workflow() {
    log_test "Setup Workflow - Create Item with Generated Password"

    # Simulate what the script does: create item with password generation
    local payload=$(cat <<EOF
{
    "vault": {"id": "${OP_VAULT_ID}"},
    "title": "${TEST_HOSTNAME}",
    "category": "LOGIN",
    "tags": ["LAPS", "local-admin", "test"],
    "fields": [
        {"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": "${TEST_ADMIN_USER}"},
        {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "generate": true, "recipe": {"length": 28, "characterSets": ["LETTERS", "DIGITS", "SYMBOLS"]}}
    ],
    "sections": [{
        "id": "host_info",
        "label": "Host Information",
        "fields": [
            {"id": "hostname", "type": "STRING", "label": "Hostname", "value": "${TEST_HOSTNAME}"},
            {"id": "serial_number", "type": "STRING", "label": "Serial Number", "value": "TEST-SERIAL-001"},
            {"id": "last_rotation", "type": "STRING", "label": "Last Rotation", "value": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
        ]
    }]
}
EOF
)

    CREATED_ITEM_RESPONSE=$(curl -s -X POST \
        -H "Authorization: Bearer ${OP_CONNECT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "${OP_CONNECT_HOST}/v1/vaults/${OP_VAULT_ID}/items")

    CREATED_ITEM_ID=$(echo "$CREATED_ITEM_RESPONSE" | jq -r '.id // empty')
    local password=$(echo "$CREATED_ITEM_RESPONSE" | jq -r '.fields[] | select(.purpose == "PASSWORD") | .value // empty')

    if [[ -n "$CREATED_ITEM_ID" ]]; then
        log_pass "Item created with ID: ${CREATED_ITEM_ID:0:8}..."
    else
        log_fail "Failed to create item"
        echo "Response: $response"
        return 1
    fi

    if [[ -n "$password" && ${#password} -ge 28 ]]; then
        log_pass "Password generated (${#password} chars)"
    else
        log_fail "Password not generated correctly"
    fi

    # Wait for 1Password Connect to sync the new item
    sleep 2
}

# Test: Search finds created item
test_search_item() {
    log_test "Search for Created Item"

    response=$(search_item "$TEST_HOSTNAME")
    found_id=$(echo "$response" | jq -r '.[0].id // empty')

    if [[ "$found_id" == "$CREATED_ITEM_ID" ]]; then
        log_pass "Item found by title search"
    else
        log_fail "Item not found or ID mismatch"
    fi
}

# Test: Rotation workflow
test_rotation_workflow() {
    log_test "Rotation Workflow - Update Item with New Password"

    if [[ -z "$CREATED_ITEM_ID" ]]; then
        log_fail "No item to rotate"
        return
    fi

    if [[ -z "$CREATED_ITEM_RESPONSE" ]]; then
        log_fail "No saved item response for rotation"
        return
    fi

    # Use saved response from creation (GET doesn't return field values)
    old_password=$(echo "$CREATED_ITEM_RESPONSE" | jq -r '.fields[] | select(.purpose == "PASSWORD") | .value')

    # Update with new password generation - only update fields, skip sections
    # (1Password Connect API doesn't return section fields in the same structure)
    local new_timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    updated=$(echo "$CREATED_ITEM_RESPONSE" | jq --arg ts "$new_timestamp" '
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
        "${OP_CONNECT_HOST}/v1/vaults/${OP_VAULT_ID}/items/${CREATED_ITEM_ID}")

    # Check for error response
    if echo "$response" | jq -e '.status' > /dev/null 2>&1; then
        log_fail "PUT failed: $(echo "$response" | jq -r '.message')"
        return
    fi

    new_password=$(echo "$response" | jq -r '.fields[] | select(.purpose == "PASSWORD") | .value // empty')

    if [[ -n "$new_password" && "$new_password" != "$old_password" ]]; then
        log_pass "Password rotated to new value"
    else
        log_fail "Password unchanged after rotation"
    fi
}

# Test: Verify item structure
test_item_structure() {
    log_test "Verify Item Structure"

    if [[ -z "$CREATED_ITEM_ID" ]]; then
        log_fail "No item to verify"
        return
    fi

    item=$(curl -s \
        -H "Authorization: Bearer ${OP_CONNECT_TOKEN}" \
        "${OP_CONNECT_HOST}/v1/vaults/${OP_VAULT_ID}/items/${CREATED_ITEM_ID}")

    # Check category
    category=$(echo "$item" | jq -r '.category')
    if [[ "$category" == "LOGIN" ]]; then
        log_pass "Category is LOGIN"
    else
        log_fail "Category is $category, expected LOGIN"
    fi

    # Check tags
    has_laps_tag=$(echo "$item" | jq '.tags | contains(["LAPS"])')
    if [[ "$has_laps_tag" == "true" ]]; then
        log_pass "Has LAPS tag"
    else
        log_fail "Missing LAPS tag"
    fi

    # Check host_info section
    has_host_info=$(echo "$item" | jq '.sections[] | select(.id == "host_info") | .id')
    if [[ -n "$has_host_info" ]]; then
        log_pass "Has host_info section"
    else
        log_fail "Missing host_info section"
    fi
}

echo "=========================================="
echo "End-to-End LAPS Workflow Tests"
echo "=========================================="
echo "Test hostname: $TEST_HOSTNAME"
echo ""

test_setup_workflow
test_search_item
test_rotation_workflow
test_item_structure

echo ""
echo "=========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "=========================================="

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
