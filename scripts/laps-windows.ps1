#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    LAPS Password Management for Windows
.DESCRIPTION
    Creates and manages a hidden local admin account with password stored in 1Password.
    Passwords are generated server-side by 1Password Connect API.
.VERSION
    1.1.0
.NOTES
    Required variables (set as Fleet secrets or environment variables):
        FLEET_SECRET_OP_CONNECT_HOST  - 1Password Connect server URL
        FLEET_SECRET_OP_CONNECT_TOKEN - API access token
        FLEET_SECRET_OP_VAULT_ID      - Target vault UUID

    Optional variables:
        FLEET_SECRET_LAPS_ADMIN_USERNAME - Local admin account name (default: laps-admin)
        FLEET_SECRET_LAPS_DEBUG          - Enable debug logging (default: 0)
        FLEET_SECRET_LAPS_DRY_RUN        - Test mode, no changes made (default: 0)

    When deployed via Fleet, FLEET_SECRET_ placeholders are replaced server-side
    before the script reaches the host. For local testing, set environment variables
    (e.g. $env:FLEET_SECRET_OP_CONNECT_HOST) before running the script.
#>

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#=============================================================================
# CONFIGURATION
#=============================================================================
$Script:Version = "1.1.0"
$Script:ScriptName = "laps-windows"

# Defaults (can be overridden by FLEET_SECRET_ variables)
$Script:DefaultAdminUser = "laps-admin"
$Script:DefaultAdminDescription = "LAPS Managed Admin Account"
$Script:PasswordLength = 28

# Exit codes
$Script:EXIT_SUCCESS = 0
$Script:EXIT_GENERAL_ERROR = 1
$Script:EXIT_CONFIG_ERROR = 2
$Script:EXIT_NETWORK_ERROR = 3
$Script:EXIT_LOCAL_ERROR = 4
$Script:EXIT_PERMISSION_ERROR = 5

# Retry configuration
$Script:MaxRetries = 4
$Script:RetryDelays = @(0, 2, 4, 8)

#=============================================================================
# FLEET SECRET VARIABLES
# When deployed via Fleet, FLEET_SECRET_ placeholders below are replaced
# with actual values via server-side text substitution before the script
# reaches the host. For local testing, set environment variables instead
# (e.g. $env:FLEET_SECRET_OP_CONNECT_HOST = "http://localhost:8080").
#
# NOTE: Fleet substitution replaces ALL occurrences of FLEET_SECRET_ variables
# in the script text regardless of quoting context — including comments.
# Use $env:FLEET_SECRET_ (which Fleet ignores) as the fallback source.
#=============================================================================
# Primary: Fleet server-side substitution (double-quoted so Fleet can replace)
# Fallback: environment variables for local testing (Fleet ignores $env: prefix)
$Script:FleetSecretOPConnectHost = "$FLEET_SECRET_OP_CONNECT_HOST"
$Script:FleetSecretOPConnectToken = "$FLEET_SECRET_OP_CONNECT_TOKEN"
$Script:FleetSecretOPVaultId = "$FLEET_SECRET_OP_VAULT_ID"
$Script:FleetSecretLapsAdminUsername = "$FLEET_SECRET_LAPS_ADMIN_USERNAME"
$Script:FleetSecretLapsDebug = "$FLEET_SECRET_LAPS_DEBUG"
$Script:FleetSecretLapsDryRun = "$FLEET_SECRET_LAPS_DRY_RUN"

# Fall back to environment variables if Fleet substitution did not occur
# (i.e. the variable is still empty after PowerShell evaluated the unset placeholder as "")
if (-not $Script:FleetSecretOPConnectHost) { $Script:FleetSecretOPConnectHost = $env:FLEET_SECRET_OP_CONNECT_HOST }
if (-not $Script:FleetSecretOPConnectToken) { $Script:FleetSecretOPConnectToken = $env:FLEET_SECRET_OP_CONNECT_TOKEN }
if (-not $Script:FleetSecretOPVaultId) { $Script:FleetSecretOPVaultId = $env:FLEET_SECRET_OP_VAULT_ID }
if (-not $Script:FleetSecretLapsAdminUsername) { $Script:FleetSecretLapsAdminUsername = $env:FLEET_SECRET_LAPS_ADMIN_USERNAME }
if (-not $Script:FleetSecretLapsDebug) { $Script:FleetSecretLapsDebug = $env:FLEET_SECRET_LAPS_DEBUG }
if (-not $Script:FleetSecretLapsDryRun) { $Script:FleetSecretLapsDryRun = $env:FLEET_SECRET_LAPS_DRY_RUN }

#=============================================================================
# RUNTIME VARIABLES
#=============================================================================
$Script:AdminUser = if ($Script:FleetSecretLapsAdminUsername) { $Script:FleetSecretLapsAdminUsername } else { $Script:DefaultAdminUser }
$Script:Debug = if ($Script:FleetSecretLapsDebug -eq "1") { $true } else { $false }
$Script:DryRun = if ($Script:FleetSecretLapsDryRun -eq "1") { $true } else { $false }

# Host information (populated later)
$Script:Hostname = $null
$Script:SerialNumber = $null
$Script:OSVersion = $null

#=============================================================================
# LOGGING FUNCTIONS
#=============================================================================
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Level,
        [Parameter(Mandatory = $true)]
        [string]$Component,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $output = "[$timestamp] [$Level] [$Component] $Message"

    # Write all logs to stderr to avoid mixing with JSON responses
    [Console]::Error.WriteLine($output)
}

function Write-LogInfo {
    param([string]$Component, [string]$Message)
    Write-Log -Level "INFO" -Component $Component -Message $Message
}

function Write-LogWarn {
    param([string]$Component, [string]$Message)
    Write-Log -Level "WARN" -Component $Component -Message $Message
}

function Write-LogError {
    param([string]$Component, [string]$Message)
    Write-Log -Level "ERROR" -Component $Component -Message $Message
}

function Write-LogDebug {
    param([string]$Component, [string]$Message)
    if ($Script:Debug) {
        Write-Log -Level "DEBUG" -Component $Component -Message $Message
    }
}

#=============================================================================
# UTILITY FUNCTIONS
#=============================================================================
function Get-MaskedString {
    param(
        [string]$String,
        [int]$VisibleChars = 8
    )
    if ($String.Length -le $VisibleChars) {
        return "***"
    }
    return $String.Substring(0, $VisibleChars) + "***"
}

function Test-Configuration {
    Write-LogInfo -Component "CONFIG" -Message "Validating configuration"

    $missing = @()

    if (-not $Script:FleetSecretOPConnectHost) {
        $missing += "FLEET_SECRET_OP_CONNECT_HOST"
    }

    if (-not $Script:FleetSecretOPConnectToken) {
        $missing += "FLEET_SECRET_OP_CONNECT_TOKEN"
    }

    if (-not $Script:FleetSecretOPVaultId) {
        $missing += "FLEET_SECRET_OP_VAULT_ID"
    }

    if ($missing.Count -gt 0) {
        Write-LogError -Component "CONFIG" -Message "Missing required environment variables: $($missing -join ', ')"
        exit $Script:EXIT_CONFIG_ERROR
    }

    Write-LogDebug -Component "CONFIG" -Message "FLEET_SECRET_OP_CONNECT_HOST: $(Get-MaskedString -String $Script:FleetSecretOPConnectHost -VisibleChars 20)"
    Write-LogDebug -Component "CONFIG" -Message "FLEET_SECRET_OP_VAULT_ID: $(Get-MaskedString -String $Script:FleetSecretOPVaultId)"
    Write-LogInfo -Component "CONFIG" -Message "Admin username: $Script:AdminUser"
    Write-LogInfo -Component "CONFIG" -Message "Configuration validated successfully"
}

function Get-HostInfo {
    $Script:Hostname = $env:COMPUTERNAME
    $Script:SerialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $Script:OSVersion = "$($osInfo.Caption) $($osInfo.Version)"

    Write-LogInfo -Component "HOST" -Message "Hostname: $Script:Hostname"
    Write-LogInfo -Component "HOST" -Message "Serial: $Script:SerialNumber"
    Write-LogInfo -Component "HOST" -Message "OS: $Script:OSVersion"
}

function Clear-SensitiveVariables {
    # Clear any password variables from memory
    $Script:Password = $null
    $Script:GeneratedPassword = $null
    [System.GC]::Collect()
    Write-LogDebug -Component "SECURITY" -Message "Cleared sensitive variables from memory"
}

#=============================================================================
# 1PASSWORD CONNECT API FUNCTIONS
#=============================================================================
function Invoke-OPApiRequest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,
        [string]$Body = $null
    )

    $attempt = 0
    $response = $null

    while ($attempt -lt $Script:MaxRetries) {
        $delay = $Script:RetryDelays[$attempt]

        if ($attempt -gt 0) {
            Write-LogInfo -Component "1PASSWORD" -Message "Retry attempt $attempt after ${delay}s delay"
            Start-Sleep -Seconds $delay
        }

        Write-LogDebug -Component "1PASSWORD" -Message "API request: $Method $Endpoint (attempt $($attempt + 1))"

        $headers = @{
            "Authorization" = "Bearer $Script:FleetSecretOPConnectToken"
            "Content-Type"  = "application/json"
        }

        $uri = "$($Script:FleetSecretOPConnectHost)$Endpoint"

        try {
            $params = @{
                Uri            = $uri
                Method         = $Method
                Headers        = $headers
                TimeoutSec     = 30
                ErrorAction    = "Stop"
            }

            if ($Body) {
                $params["Body"] = $Body
            }

            $response = Invoke-RestMethod @params
            Write-LogDebug -Component "1PASSWORD" -Message "Request successful"
            return $response
        }
        catch {
            $statusCode = $null
            try {
                if ($null -ne $_.Exception -and $null -ne $_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
            }
            catch {
                # Response property not available (e.g., timeout or connection error)
            }

            if ($null -eq $statusCode) {
                Write-LogWarn -Component "1PASSWORD" -Message "Request failed (no HTTP response): $($_.Exception.Message)"
                $attempt++
                continue
            }

            Write-LogDebug -Component "1PASSWORD" -Message "HTTP response code: $statusCode"

            switch ($statusCode) {
                400 {
                    Write-LogError -Component "1PASSWORD" -Message "Bad request (400): Invalid input"
                    throw
                }
                401 {
                    Write-LogError -Component "1PASSWORD" -Message "Unauthorized (401): Invalid token"
                    throw
                }
                403 {
                    Write-LogError -Component "1PASSWORD" -Message "Forbidden (403): Insufficient permissions"
                    throw
                }
                404 {
                    Write-LogDebug -Component "1PASSWORD" -Message "Not found (404)"
                    return $null
                }
                429 {
                    Write-LogWarn -Component "1PASSWORD" -Message "Rate limited (429), will retry"
                }
                { $_ -ge 500 } {
                    Write-LogWarn -Component "1PASSWORD" -Message "Server error ($statusCode), will retry"
                }
                default {
                    Write-LogWarn -Component "1PASSWORD" -Message "Unexpected response ($statusCode): $($_.Exception.Message)"
                }
            }
        }

        $attempt++
    }

    Write-LogError -Component "1PASSWORD" -Message "All retry attempts exhausted"
    throw "API request failed after $Script:MaxRetries attempts"
}

function Find-OPItem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title
    )

    Write-LogInfo -Component "1PASSWORD" -Message "Searching for existing entry: $Title"

    # URL encode the title for the filter
    $encodedTitle = [System.Uri]::EscapeDataString($Title)
    $endpoint = "/v1/vaults/$Script:FleetSecretOPVaultId/items?filter=title%20eq%20%22$encodedTitle%22"

    try {
        $response = @(Invoke-OPApiRequest -Method "GET" -Endpoint $endpoint)

        if ($response.Count -eq 0 -or ($response.Count -eq 1 -and $null -eq $response[0])) {
            Write-LogInfo -Component "1PASSWORD" -Message "No existing entry found"
            return $null
        }

        $itemId = $response[0].id
        Write-LogInfo -Component "1PASSWORD" -Message "Found existing entry with ID: $(Get-MaskedString -String $itemId)"
        return $itemId
    }
    catch {
        if ($_.Exception.Message -match "404") {
            Write-LogInfo -Component "1PASSWORD" -Message "No existing entry found"
            return $null
        }
        throw
    }
}

function New-OPItemPayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title
    )

    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    $payload = @{
        vault    = @{ id = $Script:FleetSecretOPVaultId }
        title    = $Title
        category = "LOGIN"
        tags     = @("LAPS", "local-admin", "Windows")
        sections = @(
            @{
                id    = "host_info"
                label = "Host Information"
            }
        )
        fields   = @(
            @{
                id      = "username"
                type    = "STRING"
                purpose = "USERNAME"
                label   = "username"
                value   = $Script:AdminUser
            },
            @{
                id       = "password"
                type     = "CONCEALED"
                purpose  = "PASSWORD"
                label    = "password"
                generate = $true
                recipe   = @{
                    length        = $Script:PasswordLength
                    characterSets = @("LETTERS", "DIGITS", "SYMBOLS")
                }
            },
            @{ id = "hostname"; type = "STRING"; label = "Hostname"; value = $Script:Hostname; section = @{ id = "host_info" } }
            @{ id = "serial_number"; type = "STRING"; label = "Serial Number"; value = $Script:SerialNumber; section = @{ id = "host_info" } }
            @{ id = "os_version"; type = "STRING"; label = "OS Version"; value = $Script:OSVersion; section = @{ id = "host_info" } }
            @{ id = "last_rotation"; type = "STRING"; label = "Last Rotation"; value = $timestamp; section = @{ id = "host_info" } }
        )
    }

    return $payload | ConvertTo-Json -Depth 10
}

function New-OPItem {
    Write-LogInfo -Component "1PASSWORD" -Message "Creating new entry with generated password"

    $payload = New-OPItemPayload -Title $Script:Hostname

    if ($Script:DryRun) {
        Write-LogInfo -Component "1PASSWORD" -Message "[DRY RUN] Would create item"
        Write-LogDebug -Component "1PASSWORD" -Message "Payload: $payload"
        # Return mock response for dry run
        return @{
            fields = @(
                @{ id = "password"; purpose = "PASSWORD"; value = "DRY_RUN_PASSWORD_123!" }
            )
        }
    }

    try {
        $response = Invoke-OPApiRequest -Method "POST" -Endpoint "/v1/vaults/$Script:FleetSecretOPVaultId/items" -Body $payload
        Write-LogInfo -Component "1PASSWORD" -Message "Successfully created entry"
        return $response
    }
    catch {
        Write-LogError -Component "1PASSWORD" -Message "Failed to create item: $($_.Exception.Message)"
        throw
    }
}

function Update-OPItem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ItemId
    )

    Write-LogInfo -Component "1PASSWORD" -Message "Updating entry with new generated password"

    # First, get the existing item to preserve structure
    try {
        $existing = Invoke-OPApiRequest -Method "GET" -Endpoint "/v1/vaults/$Script:FleetSecretOPVaultId/items/$ItemId"
    }
    catch {
        Write-LogError -Component "1PASSWORD" -Message "Failed to retrieve existing item"
        throw
    }

    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Update fields: password generation, last rotation timestamp, and OS version
    foreach ($field in $existing.fields) {
        $fieldPurpose = if ($field.PSObject.Properties['purpose']) { $field.purpose } else { $null }
        if ($fieldPurpose -eq "PASSWORD") {
            $field | Add-Member -NotePropertyName "generate" -NotePropertyValue $true -Force
            $field | Add-Member -NotePropertyName "recipe" -NotePropertyValue @{
                length        = $Script:PasswordLength
                characterSets = @("LETTERS", "DIGITS", "SYMBOLS")
            } -Force
        }
        elseif ($field.id -eq "last_rotation") {
            $field.value = $timestamp
        }
        elseif ($field.id -eq "os_version") {
            $field.value = $Script:OSVersion
        }
    }

    $payload = $existing | ConvertTo-Json -Depth 10

    if ($Script:DryRun) {
        Write-LogInfo -Component "1PASSWORD" -Message "[DRY RUN] Would update item"
        return @{
            fields = @(
                @{ id = "password"; purpose = "PASSWORD"; value = "DRY_RUN_PASSWORD_456!" }
            )
        }
    }

    try {
        $response = Invoke-OPApiRequest -Method "PUT" -Endpoint "/v1/vaults/$Script:FleetSecretOPVaultId/items/$ItemId" -Body $payload
        Write-LogInfo -Component "1PASSWORD" -Message "Successfully updated entry"
        return $response
    }
    catch {
        Write-LogError -Component "1PASSWORD" -Message "Failed to update item: $($_.Exception.Message)"
        throw
    }
}

function Get-PasswordFromResponse {
    param(
        [Parameter(Mandatory = $true)]
        $Response
    )

    $password = $null

    foreach ($field in $Response.fields) {
        $fieldPurpose = if ($field.PSObject.Properties['purpose']) { $field.purpose } else { $null }
        if ($fieldPurpose -eq "PASSWORD") {
            $password = $field.value
            break
        }
    }

    if (-not $password) {
        Write-LogError -Component "1PASSWORD" -Message "Failed to extract password from response"
        throw "Password not found in response"
    }

    Write-LogInfo -Component "1PASSWORD" -Message "Successfully extracted generated password"
    return $password
}

#=============================================================================
# LOCAL ACCOUNT MANAGEMENT
#=============================================================================
function Test-AccountExists {
    try {
        $user = Get-LocalUser -Name $Script:AdminUser -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Test-IsAdmin {
    try {
        $members = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        foreach ($member in $members) {
            if ($member.Name -like "*\$Script:AdminUser" -or $member.Name -eq $Script:AdminUser) {
                return $true
            }
        }
        return $false
    }
    catch {
        return $false
    }
}

function New-AdminAccount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    Write-LogInfo -Component "LOCAL" -Message "Creating local admin account: $Script:AdminUser"

    if ($Script:DryRun) {
        Write-LogInfo -Component "LOCAL" -Message "[DRY RUN] Would create account"
        return
    }

    try {
        $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force

        New-LocalUser -Name $Script:AdminUser `
            -Password $securePassword `
            -Description $Script:DefaultAdminDescription `
            -AccountNeverExpires `
            -PasswordNeverExpires `
            -ErrorAction Stop

        Write-LogInfo -Component "LOCAL" -Message "Account created successfully"
    }
    catch {
        Write-LogError -Component "LOCAL" -Message "Failed to create account: $($_.Exception.Message)"
        throw
    }
    finally {
        # Clear secure password from memory
        $securePassword = $null
    }
}

function Hide-Account {
    Write-LogInfo -Component "LOCAL" -Message "Hiding account from login screen"

    if ($Script:DryRun) {
        Write-LogInfo -Component "LOCAL" -Message "[DRY RUN] Would hide account"
        return
    }

    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"

        # Create the registry path if it doesn't exist
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Write-LogDebug -Component "LOCAL" -Message "Created registry path: $regPath"
        }

        # Set the user to hidden (value 0)
        Set-ItemProperty -Path $regPath -Name $Script:AdminUser -Value 0 -Type DWord -Force

        Write-LogInfo -Component "LOCAL" -Message "Account hidden from login screen"
    }
    catch {
        Write-LogWarn -Component "LOCAL" -Message "Failed to hide account: $($_.Exception.Message)"
    }
}

function Update-AccountPassword {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    Write-LogInfo -Component "LOCAL" -Message "Updating password for account: $Script:AdminUser"

    if ($Script:DryRun) {
        Write-LogInfo -Component "LOCAL" -Message "[DRY RUN] Would update password"
        return
    }

    try {
        $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force

        $user = Get-LocalUser -Name $Script:AdminUser -ErrorAction Stop
        $user | Set-LocalUser -Password $securePassword -ErrorAction Stop

        Write-LogInfo -Component "LOCAL" -Message "Password updated successfully"
    }
    catch {
        Write-LogError -Component "LOCAL" -Message "Failed to update password: $($_.Exception.Message)"
        throw
    }
    finally {
        $securePassword = $null
    }
}

function Add-ToAdminGroup {
    Write-LogInfo -Component "LOCAL" -Message "Ensuring account is in Administrators group"

    if (Test-IsAdmin) {
        Write-LogInfo -Component "LOCAL" -Message "Account already in Administrators group"
        return
    }

    if ($Script:DryRun) {
        Write-LogInfo -Component "LOCAL" -Message "[DRY RUN] Would add to Administrators group"
        return
    }

    try {
        Add-LocalGroupMember -Group "Administrators" -Member $Script:AdminUser -ErrorAction Stop
        Write-LogInfo -Component "LOCAL" -Message "Added account to Administrators group"
    }
    catch {
        Write-LogError -Component "LOCAL" -Message "Failed to add account to Administrators group: $($_.Exception.Message)"
        throw
    }
}

#=============================================================================
# MAIN WORKFLOW
#=============================================================================
function Invoke-SetupMode {
    Write-LogInfo -Component "LAPS" -Message "Running in SETUP mode"

    # Step 1: Create item in 1Password (generates password)
    try {
        $response = New-OPItem
    }
    catch {
        Write-LogError -Component "LAPS" -Message "Failed to create 1Password entry, aborting setup"
        exit $Script:EXIT_NETWORK_ERROR
    }

    # Step 2: Extract the generated password
    try {
        $password = Get-PasswordFromResponse -Response $response
    }
    catch {
        Write-LogError -Component "LAPS" -Message "Failed to extract password, aborting setup"
        exit $Script:EXIT_NETWORK_ERROR
    }

    # Step 3: Create local account
    try {
        New-AdminAccount -Password $password
    }
    catch {
        Write-LogError -Component "LAPS" -Message "Failed to create local account"
        exit $Script:EXIT_LOCAL_ERROR
    }

    # Step 4: Hide account
    Hide-Account

    # Step 5: Ensure admin group membership
    try {
        Add-ToAdminGroup
    }
    catch {
        Write-LogError -Component "LAPS" -Message "Failed to ensure Administrators group membership"
        exit $Script:EXIT_LOCAL_ERROR
    }

    Write-LogInfo -Component "LAPS" -Message "Setup completed successfully"
}

function Invoke-RotationMode {
    Write-LogInfo -Component "LAPS" -Message "Running in ROTATION mode"

    # Step 1: Search for existing 1Password entry
    try {
        $itemId = Find-OPItem -Title $Script:Hostname
    }
    catch {
        Write-LogError -Component "LAPS" -Message "Failed to search 1Password, aborting rotation"
        exit $Script:EXIT_NETWORK_ERROR
    }

    $response = $null

    if (-not $itemId) {
        # No existing entry, create new one
        Write-LogInfo -Component "LAPS" -Message "No existing 1Password entry found, creating new one"
        try {
            $response = New-OPItem
        }
        catch {
            Write-LogError -Component "LAPS" -Message "Failed to create 1Password entry"
            exit $Script:EXIT_NETWORK_ERROR
        }
    }
    else {
        # Update existing entry
        try {
            $response = Update-OPItem -ItemId $itemId
        }
        catch {
            Write-LogError -Component "LAPS" -Message "Failed to update 1Password entry: $($_.Exception.Message)"
            exit $Script:EXIT_NETWORK_ERROR
        }
    }

    # Step 2: Extract the generated password
    try {
        $password = Get-PasswordFromResponse -Response $response
    }
    catch {
        Write-LogError -Component "LAPS" -Message "Failed to extract password"
        exit $Script:EXIT_NETWORK_ERROR
    }

    # Step 3: Update local account password
    try {
        Update-AccountPassword -Password $password
    }
    catch {
        Write-LogError -Component "LAPS" -Message "Failed to update local account password"
        exit $Script:EXIT_LOCAL_ERROR
    }

    # Step 4: Ensure admin group (in case it was removed)
    try {
        Add-ToAdminGroup
    }
    catch {
        Write-LogWarn -Component "LAPS" -Message "Failed to ensure Administrators group membership"
    }

    Write-LogInfo -Component "LAPS" -Message "Rotation completed successfully"
}

function Main {
    Write-LogInfo -Component "LAPS" -Message "Starting LAPS password management v$Script:Version"

    if ($Script:DryRun) {
        Write-LogWarn -Component "LAPS" -Message "DRY RUN MODE - No changes will be made"
    }

    # Check for administrator privileges (skip in dry run mode for testing)
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin -and -not $Script:DryRun) {
        Write-LogError -Component "LAPS" -Message "This script must be run as Administrator"
        exit $Script:EXIT_PERMISSION_ERROR
    }

    if (-not $isAdmin -and $Script:DryRun) {
        Write-LogWarn -Component "LAPS" -Message "Not running as Administrator, but continuing in dry run mode"
    }

    # Validate configuration
    Test-Configuration

    # Gather host information
    Get-HostInfo

    # Determine mode based on account existence
    if (Test-AccountExists) {
        Write-LogInfo -Component "LAPS" -Message "Admin account exists, switching to rotation mode"
        Invoke-RotationMode
    }
    else {
        Write-LogInfo -Component "LAPS" -Message "Admin account does not exist, running setup"
        Invoke-SetupMode
    }

    # Cleanup
    Clear-SensitiveVariables

    Write-LogInfo -Component "LAPS" -Message "LAPS operation completed successfully"
    exit $Script:EXIT_SUCCESS
}

# Entry point
try {
    Main
}
catch {
    Write-LogError -Component "LAPS" -Message "An unexpected error occurred: $($_.Exception.Message)"
    Write-LogError -Component "LAPS" -Message "Stack trace: $($_.ScriptStackTrace)"
    Clear-SensitiveVariables
    exit $Script:EXIT_GENERAL_ERROR
}
