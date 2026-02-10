#!/bin/bash
# LAPS Password Management for macOS
# Version: 1.0.2
#
# Creates and manages a hidden local admin account with password stored in 1Password.
# Passwords are generated server-side by 1Password Connect API.
#
# Required environment variables:
#   OP_CONNECT_HOST  - 1Password Connect server URL
#   OP_CONNECT_TOKEN - API access token
#   OP_VAULT_ID      - Target vault UUID
#
# Optional environment variables:
#   LAPS_ADMIN_USERNAME - Local admin account name (default: laps-admin)
#   LAPS_DEBUG          - Enable debug logging (default: 0)
#   LAPS_DRY_RUN        - Test mode, no changes made (default: 0)

set -euo pipefail

#=============================================================================
# CONFIGURATION
#=============================================================================
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="laps-macos"

# Defaults (can be overridden by environment variables)
readonly DEFAULT_ADMIN_USER="laps-admin"
readonly DEFAULT_ADMIN_REALNAME="LAPS Admin"
readonly PASSWORD_LENGTH=28

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_GENERAL_ERROR=1
readonly EXIT_CONFIG_ERROR=2
readonly EXIT_NETWORK_ERROR=3
readonly EXIT_LOCAL_ERROR=4
readonly EXIT_PERMISSION_ERROR=5

# Retry configuration
readonly MAX_RETRIES=4
readonly RETRY_DELAYS=(0 2 4 8)

#=============================================================================
# RUNTIME VARIABLES
#=============================================================================
ADMIN_USER="${LAPS_ADMIN_USERNAME:-$DEFAULT_ADMIN_USER}"
DEBUG="${LAPS_DEBUG:-0}"
DRY_RUN="${LAPS_DRY_RUN:-0}"

#=============================================================================
# LOGGING FUNCTIONS
#=============================================================================
log() {
    local level="$1"
    local component="$2"
    local message="$3"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] [$component] $message" >&2
}

log_info() {
    log "INFO" "$1" "$2"
}

log_warn() {
    log "WARN" "$1" "$2"
}

log_error() {
    log "ERROR" "$1" "$2" >&2
}

log_debug() {
    if [[ "$DEBUG" == "1" ]]; then
        log "DEBUG" "$1" "$2"
    fi
}

#=============================================================================
# UTILITY FUNCTIONS
#=============================================================================
mask_string() {
    local str="$1"
    local visible="${2:-8}"
    if [[ ${#str} -le $visible ]]; then
        echo "***"
    else
        echo "${str:0:$visible}***"
    fi
}

validate_config() {
    log_info "CONFIG" "Validating configuration"

    local missing=()

    if [[ -z "${OP_CONNECT_HOST:-}" ]]; then
        missing+=("OP_CONNECT_HOST")
    fi

    if [[ -z "${OP_CONNECT_TOKEN:-}" ]]; then
        missing+=("OP_CONNECT_TOKEN")
    fi

    if [[ -z "${OP_VAULT_ID:-}" ]]; then
        missing+=("OP_VAULT_ID")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "CONFIG" "Missing required environment variables: ${missing[*]}"
        exit $EXIT_CONFIG_ERROR
    fi

    log_debug "CONFIG" "OP_CONNECT_HOST: $(mask_string "$OP_CONNECT_HOST" 20)"
    log_debug "CONFIG" "OP_VAULT_ID: $(mask_string "$OP_VAULT_ID")"
    log_info "CONFIG" "Admin username: $ADMIN_USER"
    log_info "CONFIG" "Configuration validated successfully"
}

get_hostname() {
    scutil --get ComputerName 2>/dev/null || hostname -s
}

get_serial_number() {
    system_profiler SPHardwareDataType | awk '/Serial Number/{print $NF}'
}

get_os_version() {
    sw_vers -productVersion
}

get_host_info() {
    HOSTNAME=$(get_hostname)
    SERIAL_NUMBER=$(get_serial_number)
    OS_VERSION="macOS $(get_os_version)"

    log_info "HOST" "Hostname: $HOSTNAME"
    log_info "HOST" "Serial: $SERIAL_NUMBER"
    log_info "HOST" "OS: $OS_VERSION"
}

clear_sensitive_vars() {
    unset PASSWORD
    unset GENERATED_PASSWORD
    log_debug "SECURITY" "Cleared sensitive variables from memory"
}

# Trap to ensure cleanup on exit
cleanup() {
    clear_sensitive_vars
}
trap cleanup EXIT

#=============================================================================
# 1PASSWORD CONNECT API FUNCTIONS
#=============================================================================
op_api_request() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"
    local attempt=0
    local response
    local http_code

    while [[ $attempt -lt $MAX_RETRIES ]]; do
        local delay=${RETRY_DELAYS[$attempt]}

        if [[ $attempt -gt 0 ]]; then
            log_info "1PASSWORD" "Retry attempt $attempt after ${delay}s delay"
            sleep "$delay"
        fi

        log_debug "1PASSWORD" "API request: $method $endpoint (attempt $((attempt + 1)))"

        local curl_args=(
            -s
            -w "\n%{http_code}"
            -X "$method"
            -H "Authorization: Bearer $OP_CONNECT_TOKEN"
            -H "Content-Type: application/json"
        )

        if [[ -n "$data" ]]; then
            curl_args+=(-d "$data")
        fi

        local full_response
        full_response=$(curl "${curl_args[@]}" "${OP_CONNECT_HOST}${endpoint}" 2>&1) || true

        # Extract HTTP code from last line
        http_code=$(echo "$full_response" | tail -n1)
        response=$(echo "$full_response" | sed '$d')

        log_debug "1PASSWORD" "HTTP response code: $http_code"

        case "$http_code" in
            200|201)
                echo "$response"
                return 0
                ;;
            400)
                log_error "1PASSWORD" "Bad request (400): Invalid input"
                log_debug "1PASSWORD" "Response: $response"
                return 1
                ;;
            401)
                log_error "1PASSWORD" "Unauthorized (401): Invalid token"
                return 1
                ;;
            403)
                log_error "1PASSWORD" "Forbidden (403): Insufficient permissions"
                return 1
                ;;
            404)
                log_debug "1PASSWORD" "Not found (404)"
                echo ""
                return 0
                ;;
            429)
                log_warn "1PASSWORD" "Rate limited (429), will retry"
                ;;
            5*)
                log_warn "1PASSWORD" "Server error ($http_code), will retry"
                ;;
            *)
                log_warn "1PASSWORD" "Unexpected response ($http_code), will retry"
                ;;
        esac

        ((attempt++))
    done

    log_error "1PASSWORD" "All retry attempts exhausted"
    return 1
}

op_search_item() {
    local title="$1"
    log_info "1PASSWORD" "Searching for existing entry: $title"

    # URL encode the title for the filter
    local encoded_title
    encoded_title=$(printf '%s' "$title" | jq -sRr @uri)

    local response
    response=$(op_api_request "GET" "/v1/vaults/${OP_VAULT_ID}/items?filter=title%20eq%20%22${encoded_title}%22") || return 1

    if [[ -z "$response" || "$response" == "[]" ]]; then
        log_info "1PASSWORD" "No existing entry found"
        echo ""
        return 0
    fi

    # Extract first item's ID
    local item_id
    item_id=$(echo "$response" | jq -r '.[0].id // empty')

    if [[ -n "$item_id" ]]; then
        log_info "1PASSWORD" "Found existing entry with ID: $(mask_string "$item_id")"
        echo "$item_id"
    else
        echo ""
    fi
}

build_item_payload() {
    local title="$1"
    local is_update="${2:-false}"
    local timestamp
    timestamp=$(date -u "+%Y-%m-%dT%H:%M:%SZ")

    local payload
    payload=$(jq -n \
        --arg vault_id "$OP_VAULT_ID" \
        --arg title "$title" \
        --arg username "$ADMIN_USER" \
        --arg hostname "$HOSTNAME" \
        --arg serial "$SERIAL_NUMBER" \
        --arg os "$OS_VERSION" \
        --arg timestamp "$timestamp" \
        --argjson pw_length "$PASSWORD_LENGTH" \
        '{
            vault: { id: $vault_id },
            title: $title,
            category: "LOGIN",
            tags: ["LAPS", "local-admin", "macOS"],
            sections: [
                {
                    id: "host_info",
                    label: "Host Information"
                }
            ],
            fields: [
                {
                    id: "username",
                    type: "STRING",
                    purpose: "USERNAME",
                    label: "username",
                    value: $username
                },
                {
                    id: "password",
                    type: "CONCEALED",
                    purpose: "PASSWORD",
                    label: "password",
                    generate: true,
                    recipe: {
                        length: $pw_length,
                        characterSets: ["LETTERS", "DIGITS", "SYMBOLS"]
                    }
                },
                {
                    id: "hostname",
                    type: "STRING",
                    label: "Hostname",
                    value: $hostname,
                    section: { id: "host_info" }
                },
                {
                    id: "serial_number",
                    type: "STRING",
                    label: "Serial Number",
                    value: $serial,
                    section: { id: "host_info" }
                },
                {
                    id: "os_version",
                    type: "STRING",
                    label: "OS Version",
                    value: $os,
                    section: { id: "host_info" }
                },
                {
                    id: "last_rotation",
                    type: "STRING",
                    label: "Last Rotation",
                    value: $timestamp,
                    section: { id: "host_info" }
                }
            ]
        }')

    echo "$payload"
}

op_create_item() {
    log_info "1PASSWORD" "Creating new entry with generated password"

    local payload
    payload=$(build_item_payload "$HOSTNAME")

    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "1PASSWORD" "[DRY RUN] Would create item"
        log_debug "1PASSWORD" "Payload: $payload"
        echo '{"fields":[{"id":"password","purpose":"PASSWORD","value":"DRY_RUN_PASSWORD_123!"}]}'
        return 0
    fi

    local response
    response=$(op_api_request "POST" "/v1/vaults/${OP_VAULT_ID}/items" "$payload") || {
        log_error "1PASSWORD" "Failed to create item"
        return 1
    }

    log_info "1PASSWORD" "Successfully created entry"
    echo "$response"
}

op_update_item() {
    local item_id="$1"
    log_info "1PASSWORD" "Updating entry with new generated password"

    # First, get the existing item to preserve structure
    local existing
    existing=$(op_api_request "GET" "/v1/vaults/${OP_VAULT_ID}/items/${item_id}") || {
        log_error "1PASSWORD" "Failed to retrieve existing item"
        return 1
    }

    local timestamp
    timestamp=$(date -u "+%Y-%m-%dT%H:%M:%SZ")

    # Update the item with new password generation
    local payload
    payload=$(echo "$existing" | jq \
        --argjson pw_length "$PASSWORD_LENGTH" \
        --arg timestamp "$timestamp" \
        --arg os "$OS_VERSION" \
        '
        # Update password field to trigger generation
        .fields = [.fields[] |
            if .purpose == "PASSWORD" then
                .generate = true |
                .recipe = {
                    length: $pw_length,
                    characterSets: ["LETTERS", "DIGITS", "SYMBOLS"]
                }
            elif .id == "last_rotation" then .value = $timestamp
            elif .id == "os_version" then .value = $os
            else . end
        ]
        ')

    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "1PASSWORD" "[DRY RUN] Would update item"
        echo '{"fields":[{"id":"password","purpose":"PASSWORD","value":"DRY_RUN_PASSWORD_456!"}]}'
        return 0
    fi

    local response
    response=$(op_api_request "PUT" "/v1/vaults/${OP_VAULT_ID}/items/${item_id}" "$payload") || {
        log_error "1PASSWORD" "Failed to update item"
        return 1
    }

    log_info "1PASSWORD" "Successfully updated entry"
    echo "$response"
}

extract_password_from_response() {
    local response="$1"
    local password
    password=$(echo "$response" | jq -r '.fields[] | select(.purpose == "PASSWORD") | .value')

    if [[ -z "$password" || "$password" == "null" ]]; then
        log_error "1PASSWORD" "Failed to extract password from response"
        return 1
    fi

    log_info "1PASSWORD" "Successfully extracted generated password"
    echo "$password"
}

#=============================================================================
# LOCAL ACCOUNT MANAGEMENT
#=============================================================================
account_exists() {
    if dscl . -read "/Users/$ADMIN_USER" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

is_admin() {
    if dseditgroup -o checkmember -m "$ADMIN_USER" admin &>/dev/null; then
        return 0
    else
        return 1
    fi
}

create_admin_account() {
    local password="$1"
    log_info "LOCAL" "Creating local admin account: $ADMIN_USER"

    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "LOCAL" "[DRY RUN] Would create account"
        return 0
    fi

    # Use sysadminctl to create the account with admin privileges
    if ! sysadminctl -addUser "$ADMIN_USER" \
        -password "$password" \
        -admin \
        -fullName "$DEFAULT_ADMIN_REALNAME" 2>&1; then
        log_error "LOCAL" "Failed to create account with sysadminctl"
        return 1
    fi

    log_info "LOCAL" "Account created successfully"
}

hide_account() {
    log_info "LOCAL" "Hiding account from login window"

    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "LOCAL" "[DRY RUN] Would hide account"
        return 0
    fi

    # Add to HiddenUsersList
    if ! defaults write /Library/Preferences/com.apple.loginwindow HiddenUsersList -array-add "$ADMIN_USER" 2>&1; then
        log_warn "LOCAL" "Failed to add to HiddenUsersList, trying alternative method"
    fi

    # Also set IsHidden attribute on the user
    if ! dscl . -create "/Users/$ADMIN_USER" IsHidden 1 2>&1; then
        log_warn "LOCAL" "Failed to set IsHidden attribute"
    fi

    log_info "LOCAL" "Account hidden from login window"
}

update_account_password() {
    local password="$1"
    log_info "LOCAL" "Updating password for account: $ADMIN_USER"

    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "LOCAL" "[DRY RUN] Would update password"
        return 0
    fi

    # Use dscl to change the password
    if ! dscl . -passwd "/Users/$ADMIN_USER" "$password" 2>&1; then
        log_error "LOCAL" "Failed to update password"
        return 1
    fi

    log_info "LOCAL" "Password updated successfully"
}

ensure_admin_group() {
    log_info "LOCAL" "Ensuring account is in admin group"

    if is_admin; then
        log_info "LOCAL" "Account already in admin group"
        return 0
    fi

    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "LOCAL" "[DRY RUN] Would add to admin group"
        return 0
    fi

    if ! dseditgroup -o edit -a "$ADMIN_USER" -t user admin 2>&1; then
        log_error "LOCAL" "Failed to add account to admin group"
        return 1
    fi

    log_info "LOCAL" "Added account to admin group"
}

#=============================================================================
# MAIN WORKFLOW
#=============================================================================
setup_mode() {
    log_info "LAPS" "Running in SETUP mode"

    # Step 1: Create item in 1Password (generates password)
    local response
    response=$(op_create_item) || {
        log_error "LAPS" "Failed to create 1Password entry, aborting setup"
        exit $EXIT_NETWORK_ERROR
    }

    # Step 2: Extract the generated password
    local password
    password=$(extract_password_from_response "$response") || {
        log_error "LAPS" "Failed to extract password, aborting setup"
        exit $EXIT_NETWORK_ERROR
    }

    # Step 3: Create local account
    create_admin_account "$password" || {
        log_error "LAPS" "Failed to create local account"
        exit $EXIT_LOCAL_ERROR
    }

    # Step 4: Hide account
    hide_account || {
        log_warn "LAPS" "Failed to hide account, continuing anyway"
    }

    # Step 5: Ensure admin group membership
    ensure_admin_group || {
        log_error "LAPS" "Failed to ensure admin group membership"
        exit $EXIT_LOCAL_ERROR
    }

    log_info "LAPS" "Setup completed successfully"
}

rotation_mode() {
    log_info "LAPS" "Running in ROTATION mode"

    # Step 1: Search for existing 1Password entry
    local item_id
    item_id=$(op_search_item "$HOSTNAME") || {
        log_error "LAPS" "Failed to search 1Password, aborting rotation"
        exit $EXIT_NETWORK_ERROR
    }

    local response

    if [[ -z "$item_id" ]]; then
        # No existing entry, create new one
        log_info "LAPS" "No existing 1Password entry found, creating new one"
        response=$(op_create_item) || {
            log_error "LAPS" "Failed to create 1Password entry"
            exit $EXIT_NETWORK_ERROR
        }
    else
        # Update existing entry
        response=$(op_update_item "$item_id") || {
            log_error "LAPS" "Failed to update 1Password entry"
            exit $EXIT_NETWORK_ERROR
        }
    fi

    # Step 2: Extract the generated password
    local password
    password=$(extract_password_from_response "$response") || {
        log_error "LAPS" "Failed to extract password"
        exit $EXIT_NETWORK_ERROR
    }

    # Step 3: Update local account password
    update_account_password "$password" || {
        log_error "LAPS" "Failed to update local account password"
        exit $EXIT_LOCAL_ERROR
    }

    # Step 4: Ensure admin group (in case it was removed)
    ensure_admin_group || {
        log_warn "LAPS" "Failed to ensure admin group membership"
    }

    log_info "LAPS" "Rotation completed successfully"
}

main() {
    log_info "LAPS" "Starting LAPS password management v${SCRIPT_VERSION}"

    if [[ "$DRY_RUN" == "1" ]]; then
        log_warn "LAPS" "DRY RUN MODE - No changes will be made"
    fi

    # Check for root privileges (skip in dry run mode for testing)
    if [[ $EUID -ne 0 ]] && [[ "$DRY_RUN" != "1" ]]; then
        log_error "LAPS" "This script must be run as root"
        exit $EXIT_PERMISSION_ERROR
    fi

    if [[ $EUID -ne 0 ]] && [[ "$DRY_RUN" == "1" ]]; then
        log_warn "LAPS" "Not running as root, but continuing in dry run mode"
    fi

    # Validate configuration
    validate_config

    # Gather host information
    get_host_info

    # Determine mode based on account existence
    if account_exists; then
        log_info "LAPS" "Admin account exists, switching to rotation mode"
        rotation_mode
    else
        log_info "LAPS" "Admin account does not exist, running setup"
        setup_mode
    fi

    log_info "LAPS" "LAPS operation completed successfully"
    exit $EXIT_SUCCESS
}

# Entry point
main "$@"
