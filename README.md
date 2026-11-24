# BloodHound Enterprise collector updater

This project updates existing SharpHound Enterprise and AzureHound Enterprise
services from the versions offered by your BloodHound Enterprise tenant.

The updater:

- authenticates with a BloodHound user API token using the documented HMAC
  request-signing protocol;
- reads `/api/v2/kennel/enterprise-manifest` and selects the newest stable
  Windows release;
- downloads both the package and tenant-provided SHA-256 checksum;
- requires a valid Authenticode signature from `Specter Ops, Inc.` before
  stopping a service;
- runs the SharpHound installer unattended;
- replaces AzureHound atomically and restores the old executable if validation
  or service startup fails;
- records state under
  `C:\ProgramData\BloodHoundCollectorUpdater\state.json` for binaries that do
  not expose a Windows file version.
- restricts its staging directory to `SYSTEM`, local Administrators, and the
  executing agent identity before launching downloaded code.

It intentionally updates existing services only. It does not create services,
change collector credentials, or modify collector configuration.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- Pester 5 or later to run the tests (the updater itself does not require
  Pester)
- an elevated account on each collector server
- outbound HTTPS access to the BloodHound Enterprise tenant
- a BloodHound **user API token ID and key** authorized to download collectors

Do not use a collector-client token for downloads. Create a dedicated,
least-privileged BloodHound user/service account API token and store its key as
a secret.

## Run locally

Set credentials in the process environment so the token key is not included in
the command line:

```powershell
$env:BHE_URL = 'https://TENANT.bloodhoundenterprise.io'
$env:BHE_TOKEN_ID = '<user-api-token-id>'
$env:BHE_TOKEN_KEY = '<user-api-token-key>'

# Safe inventory check: no elevation or service changes.
.\Update-BloodHoundCollectors.ps1 -CheckOnly

# Update both installed collectors from an elevated session.
.\Update-BloodHoundCollectors.ps1

# Update only AzureHound at a non-default location.
.\Update-BloodHoundCollectors.ps1 `
    -Collectors AzureHound `
    -AzureHoundPath 'D:\BloodHound\azurehound.exe'
```

If paths are omitted, the updater first reads each Windows service command
line. It then falls back to:

- SharpHound: `C:\Program Files (x86)\SHService\SHDelegator.exe`
- AzureHound: `C:\Program Files\AzureHound Enterprise\azurehound.exe`

Default service names are `SHDelegator` and `AzureHound`; both can be
overridden with command parameters.

## Azure DevOps

1. Commit these files to an Azure Repos or Git repository.
2. Edit `azure-pipelines.yml`:
   - set `poolName` to the self-hosted Windows agent pool;
   - replace the sample target with one entry per server;
   - give every target a YAML-safe unique `id`;
   - set the exact AzureHound path where it differs from the default;
   - set the comma-separated `collectors` value to the collectors installed on
     that server.
3. Create pipeline variables:

| Variable | Secret | Value |
|---|---:|---|
| `BHE_URL` | No | `https://TENANT.bloodhoundenterprise.io` |
| `BHE_TOKEN_ID` | No | BloodHound user API token ID |
| `BHE_TOKEN_KEY` | **Yes** | BloodHound user API token key |

4. Create a pipeline from `azure-pipelines.yml`.
5. Run once with the `checkOnly` parameter set to `true`, review each published
   JSON result, then run a single-server update before enabling the weekly
   schedule for all targets.

Each job uses an `Agent.Name` demand, so the update executes locally on the
specified collector server through its self-hosted Azure DevOps agent. The
agent service account must be a local administrator on that server.

If one collector fails, the updater still processes the other collector. The
job then fails and publishes a result containing each collector's outcome.

## Failure and rollback behavior

Downloads and signature checks happen before service interruption.

- **AzureHound:** the old executable is renamed to a timestamped `.bak-*`
  sibling. If replacement, signature verification, version validation, or
  service startup fails, it is restored automatically. The two newest
  successful backups are retained by default.
- **SharpHound:** the updater restarts the service after a failed installer
  invocation, but the vendor installer owns file rollback. Installer logs are
  retained in
  `C:\ProgramData\BloodHoundCollectorUpdater\logs`. Existing collector
  configuration is not touched.

An update succeeds only after the target executable is validated and the
corresponding Windows service reaches `Running`.

## Validation

Run the test suite without contacting a tenant or changing services:

```powershell
Invoke-Pester .\tests
```

The included `SHSetup-v2.13.0.exe` is used only to validate version extraction
and the expected Specter Ops Authenticode publisher. The updater always
downloads the tenant-selected current Enterprise package.

## Vendor references

- [Working with the BloodHound API](https://bloodhound.specterops.io/integrations/bloodhound-api/working-with-api)
- [Enterprise collector manifest](https://bloodhound.specterops.io/reference/collectors/get-kennel-enterprise-manifest)
- [Download collector asset](https://bloodhound.specterops.io/reference/collectors/download-asset)
- [SharpHound Enterprise installation and upgrade](https://bloodhound.specterops.io/install-data-collector/install-sharphound/installation-upgrade)
- [AzureHound Enterprise installation and upgrade](https://bloodhound.specterops.io/install-data-collector/install-azurehound/installation-options)
