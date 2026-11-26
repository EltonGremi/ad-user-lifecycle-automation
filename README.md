# AD User Lifecycle Automation

A modular PowerShell utility for standardized **Active Directory user onboarding and offboarding** driven by CSV inputs, built with least-privilege operational safety, dry-run support (`-WhatIf`), and structured audit logging.

## Why This Project Exists

Manual account provisioning and deprovisioning in Active Directory often lead to inconsistent group memberships, lingering access permissions, and missing audit trails. This script standardizes identity lifecycle workflows to support operational consistency and access governance requirements.

## Key Features

- **Deterministic Onboarding:** Creates AD accounts with required attributes, enforces password change at next logon, generates strong temporary passwords using `RandomNumberGenerator`, and assigns department/role security groups.
- **Controlled Offboarding:** Disables user accounts, removes extra group memberships, and moves objects to a dedicated offboarding/archive Organizational Unit (OU).
- **Safe Dry-Run Support:** Built on PowerShell `SupportsShouldProcess`, allowing full simulation via `-WhatIf` before making directory changes.
- **Audit Logging:** Writes timestamped operational and dry-run entries to a structured log file.
- **Sanitized Sample Data:** Includes non-production sample CSV files under `samples/`.

## Prerequisites

- Windows Server or management workstation with **PowerShell 5.1+** or **PowerShell 7+**
- **Active Directory PowerShell module** (RSAT)
- Appropriate Active Directory permissions on target and archive OUs

## Usage

### 1. Simulate Onboarding (`-WhatIf`)

```powershell
.\Invoke-ADLifecycle.ps1 -Mode Onboard -CsvPath .\samples\onboarding.sample.csv -WhatIf
```
### 2. Execute Onboarding

```powershell
.\Invoke-ADLifecycle.ps1 -Mode Onboard -CsvPath .\samples\onboarding.sample.csv -LogPath .\logs\lifecycle.log
```
### 3. Simulate & Execute Offboarding

```powershell
.\Invoke-ADLifecycle.ps1 -Mode Offboard -CsvPath .\samples\offboarding.sample.csv -WhatIf
.\Invoke-ADLifecycle.ps1 -Mode Offboard -CsvPath .\samples\offboarding.sample.csv -LogPath .\logs\lifecycle.log
```
