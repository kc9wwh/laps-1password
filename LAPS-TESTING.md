# LAPS Testing Plan

This document outlines the testing strategy and infrastructure setup for validating the LAPS password management solution.

## 1. Test Infrastructure Setup

### 1.1 Directory Structure

```
laps-testing/
├── docker-compose.yml
├── .env
├── 1password-credentials.json    # Generated from 1Password
├── scripts/
│   ├── laps-macos.sh            # Symlink or copy
│   └── laps-windows.ps1         # Symlink or copy
└── tests/
    ├── test-api.sh              # API connectivity tests
    ├── test-create-item.sh      # Item creation tests
    ├── test-update-item.sh      # Item update tests
    ├── test-password-gen.sh     # Password generation tests
    └── run-all-tests.sh         # Test runner
```

### 1.2 Docker Compose Configuration

Create `docker-compose.yml`:

```yaml
version: "3.4"

services:
  op-connect-api:
    image: 1password/connect-api:latest
    ports:
      - "8081:8080"
    volumes:
      - "./1password-credentials.json:/home/opuser/.op/1password-credentials.json"
      - "data:/home/opuser/.op/data"
  op-connect-sync:
    image: 1password/connect-sync:latest
    ports:
      - "8082:8080"
    volumes:
      - "./1password-credentials.json:/home/opuser/.op/1password-credentials.json"
      - "data:/home/opuser/.op/data"

volumes:
  data:
```

### 1.3 Environment Configuration

Create `.env` file:

```bash
# 1Password Connect host
export OP_CONNECT_HOST="http://localhost:8081"

# 1Password Connect Token (generate from 1Password)
export OP_CONNECT_TOKEN=xxxxxx

# Vault ID for LAPS testing
export OP_VAULT_ID=xxxxx

# Optional: Custom admin username for testing
export LAPS_ADMIN_USERNAME=laps-admin
```

## 2. Starting the Test Environment

```bash
# Navigate to test directory
cd laps-test

# Start all containers
docker-compose up -d

# Verify services are healthy
docker-compose ps

# Check Connect API health
curl http://localhost:8081/health

# View logs
docker-compose logs -f op-connect-api
```

## 3. Test Categories

### 3.1 Unit Tests (API Level)

Test the 1Password Connect API integration in isolation.

Use `tests/test-api.sh`

### 3.2 Integration Tests (Password Generation)

Use `tests/test-password-gen.sh`

### 3.3 Script Logic Tests (Dry Run)

Use `tests/test-script-logic.sh`

### 3.4 End-to-End Tests

Use `tests/test-e2e.sh`

### 3.5 Test Runner

Use `tests/run-all-tests.sh`

## 4. Running Tests

### 4.1 Start Infrastructure

```bash
cd laps-test
docker-compose up -d
```

### 4.2 Run All Tests

```bash
# Execute tests in the bash container
./tests/run-all-tests.sh
```

### 4.3 Run Individual Test Suites

```bash
# API tests
./tests/test-api.sh

# Password generation tests
./tests/test-password-gen.sh

# End-to-end tests
./tests/test-e2e.sh

# Script logic tests (dry run)
./tests/test-script-logic.sh
```

### 4.4 PowerShell Tests

```bash
# Run PowerShell script tests
docker exec -it laps-test-pwsh pwsh -File /tests/test-pwsh.ps1
```

## 5. Manual Testing Checklist

### 5.1 macOS Testing (Requires Real macOS)

```bash
# Set up environment
export OP_CONNECT_HOST="http://localhost:8081"
export OP_CONNECT_TOKEN="your-token"
export OP_VAULT_ID="your-vault-id"
export LAPS_DEBUG=1

# Test 1: Dry run first
LAPS_DRY_RUN=1 sudo ./laps-macos.sh

# Test 2: Create account (first run)
sudo ./laps-macos.sh

# Verify:
# [ ] Account created
dscl . -read /Users/laps-admin

# [ ] In admin group
dseditgroup -o checkmember -m laps-admin admin

# [ ] Hidden from login
defaults read /Library/Preferences/com.apple.loginwindow HiddenUsersList

# [ ] 1Password entry created
# Check 1Password vault

# Test 3: Rotation (second run)
sudo ./laps-macos.sh

# Verify:
# [ ] Password changed in 1Password
# [ ] Last rotation timestamp updated
# [ ] Local password matches 1Password
```

### 5.2 Windows Testing (Requires Real Windows)

```powershell
# Set up environment
$env:OP_CONNECT_HOST = "http://localhost:8080"
$env:OP_CONNECT_TOKEN = "your-token"
$env:OP_VAULT_ID = "your-vault-id"
$env:LAPS_DEBUG = "1"

# Test 1: Dry run first
$env:LAPS_DRY_RUN = "1"
.\laps-windows.ps1

# Test 2: Create account (first run)
$env:LAPS_DRY_RUN = "0"
.\laps-windows.ps1

# Verify:
# [ ] Account created
Get-LocalUser -Name "laps-admin"

# [ ] In Administrators group
Get-LocalGroupMember -Group "Administrators" | Where-Object Name -like "*laps-admin*"

# [ ] Hidden from login
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name "laps-admin"

# [ ] 1Password entry created
# Check 1Password vault

# Test 3: Rotation (second run)
.\laps-windows.ps1

# Verify:
# [ ] Password changed
# [ ] Last rotation timestamp updated
```

## 6. CI/CD Integration

### 6.1 GitHub Actions Workflow

```yaml
# .github/workflows/laps-tests.yml
name: LAPS Tests

on:
  push:
    paths:
      - 'scripts/macOS/laps-macos.sh'
      - 'scripts/windows/laps-windows.ps1'
      - 'laps-test/**'
  pull_request:
    paths:
      - 'scripts/macOS/laps-macos.sh'
      - 'scripts/windows/laps-windows.ps1'

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up test environment
        run: |
          cd laps-testing
          echo "OP_CONNECT_TOKEN=${{ secrets.OP_CONNECT_TOKEN }}" >> .env
          echo "OP_VAULT_ID=${{ secrets.OP_VAULT_ID }}" >> .env
      
      - name: Copy 1Password credentials
        run: |
          echo '${{ secrets.OP_CREDENTIALS_JSON }}' > laps-testing/1password-credentials.json
      
      - name: Start services
        run: |
          cd laps-testing
          docker-compose up -d
          sleep 30  # Wait for services
      
      - name: Run tests
        run: |
          cd laps-testing
          docker exec laps-test-bash bash /tests/run-all-tests.sh
      
      - name: Cleanup
        if: always()
        run: |
          cd laps-testing
          docker-compose down -v
```

## 7. Troubleshooting Tests

### Common Issues

**Permission errors:**
```bash
# Make scripts executable
chmod +x tests/*.sh
chmod +x scripts/*.sh
```
