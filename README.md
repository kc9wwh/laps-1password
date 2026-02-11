# LAPS with 1Password

A Local Administrator Password Solution (LAPS) for macOS and Windows that stores passwords in [1Password](https://1password.com/) via the [Connect API](https://developer.1password.com/docs/connect/). Designed for deployment with [Fleet](https://fleetdm.com/).

## How it works

Fleet policies check whether the local admin password was rotated within the last 7 days. When a host fails the policy, Fleet automatically runs the platform-specific script, which:

1. Creates a hidden local admin account (if it doesn't exist) or rotates the existing password
2. Generates a 28-character password server-side via the 1Password Connect API
3. Stores the credentials in your 1Password vault, tagged with the host's platform

Passwords never leave the 1Password Connect server in plaintext until retrieved by the script, and are applied directly to the local account.

## Prerequisites

- [Fleet Premium](https://fleetdm.com/pricing) (required for policy automations)
- [1Password Connect server](https://developer.1password.com/docs/connect/get-started/) deployed and accessible from your managed hosts
- A 1Password vault and API token scoped to that vault
- `jq` installed on macOS hosts _*Will be installed automatically by the script_

## Directory structure

```
├── scripts/
│   ├── laps-macos.sh              # macOS script (bash)
│   └── laps-windows.ps1           # Windows script (PowerShell)
├── yaml/
│   ├── macos-laps-admin.policies.yml      # macOS policy definition
│   ├── windows-laps-admin.policies.yml    # Windows policy definition
│   └── workstations.yml                   # Example team configuration
├── tests/                         # Test suite for local validation
├── docker-compose.yaml            # Local 1Password Connect for testing
└── LAPS-TESTING.md                # Testing and advanced usage guide
```

## Setup

### 1. Deploy 1Password Connect

Set up a [1Password Connect server](https://developer.1password.com/docs/connect/get-started/) accessible from your Fleet-managed hosts. Note the server URL, API token, and vault ID.

### 2. Add Fleet secrets

In Fleet, add the following [secrets](https://fleetdm.com/docs/configuration/yaml-files#org_settings) so they are available for server-side substitution in your scripts:

| Secret name | Description |
| --- | --- |
| `FLEET_SECRET_OP_CONNECT_HOST` | 1Password Connect server URL |
| `FLEET_SECRET_OP_CONNECT_TOKEN` | API access token |
| `FLEET_SECRET_OP_VAULT_ID` | Target vault UUID |
| `FLEET_SECRET_LAPS_ADMIN_USERNAME` | Local admin username (optional, defaults to `laps-admin`) |
| `FLEET_SECRET_LAPS_DEBUG` | Enable debug logging (optional, defaults to `0`) |
| `FLEET_SECRET_LAPS_DRY_RUN` | Test mode, no changes made (optional, defaults to `0`) |

### 3. Add scripts and policies via GitOps

Add the scripts and policies to your [Fleet GitOps repo](https://github.com/fleetdm/fleet-gitops). The `yaml/workstations.yml` file shows an example team configuration:

```yaml
name: Workstations
policies:
  - path: ../lib/macos/policies/macos-laps-admin.policies.yml
  - path: ../lib/windows/policies/windows-laps-admin.policies.yml
controls:
  scripts:
    - path: ../lib/macos/scripts/laps-macos.sh
    - path: ../lib/windows/scripts/laps-windows.ps1
```

Copy the scripts into your GitOps repo's `lib/` folder and the policy YAML files alongside them. Adjust the `path` references to match your repo's layout. When you push, Fleet will pick up the policies and scripts automatically.

Each policy uses a `run_script` automation that triggers the corresponding LAPS script on any host that fails the check.

### 4. Verify

After deployment, confirm the setup:

- Check 1Password for new vault entries tagged with `LAPS` containing the managed host's credentials
- In Fleet, verify the policies show as passing for hosts that have been rotated

## Testing

See [LAPS-TESTING.md](LAPS-TESTING.md) for instructions on running the test suite locally with Docker Compose, manual testing checklists for macOS and Windows, and CI/CD integration examples.

## License

[MIT](LICENSE)
