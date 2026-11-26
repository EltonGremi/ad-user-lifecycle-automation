<#
.SYNOPSIS
    Automates Active Directory user onboarding and offboarding from CSV inputs.

.DESCRIPTION
    Reads a sanitized CSV file and performs controlled user provisioning (onboarding)
    or account decommissioning (offboarding), including group assignments, OU placement,
    password expiration policy, and structured audit logging.

.PARAMETER Mode
    Operation mode: 'Onboard' or 'Offboard'.

.PARAMETER CsvPath
    Path to the input CSV file.

.PARAMETER LogPath
    Path to the audit log file. Defaults to .\logs\ad-lifecycle.log.

.EXAMPLE
    .\Invoke-ADLifecycle.ps1 -Mode Onboard -CsvPath .\samples\onboarding.sample.csv -WhatIf

.EXAMPLE
    .\Invoke-ADLifecycle.ps1 -Mode Offboard -CsvPath .\samples\offboarding.sample.csv
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet('Onboard', 'Offboard')]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = ".\logs\ad-lifecycle.log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-AuditLog {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DRYRUN')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $logDir = Split-Path -Path $LogPath -Parent
    if ($logDir -and -not (Test-Path -Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
    $entry = "[$timestamp] [$Level] [$Mode] $Message"
    Add-Content -Path $LogPath -Value $entry -Encoding UTF8

    switch ($Level) {
        'ERROR'  { Write-Warning $entry }
        'WARN'   { Write-Warning $entry }
        'DRYRUN' { Write-Verbose $entry -Verbose }
        default  { Write-Information $entry -InformationAction Continue }
    }
}

function New-StrongTemporaryPassword {
    param ([int]$Length = 18)

    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower = 'abcdefghijkmnpqrstuvwxyz'
    $digits = '23456789'
    $symbols = '!@#$%^&*-_=+'
    $allChars = $upper + $lower + $digits + $symbols

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $bytes = New-Object byte[] $Length
        $rng.GetBytes($bytes)

        $chars = New-Object char[] $Length
        $chars[0] = $upper[$bytes[0] % $upper.Length]
        $chars[1] = $lower[$bytes[1] % $lower.Length]
        $chars[2] = $digits[$bytes[2] % $digits.Length]
        $chars[3] = $symbols[$bytes[3] % $symbols.Length]

        for ($i = 4; $i -lt $Length; $i++) {
            $chars[$i] = $allChars[$bytes[$i] % $allChars.Length]
        }

        # Shuffle characters securely
        for ($i = $chars.Length - 1; $i -gt 0; $i--) {
            $swapByte = New-Object byte[] 1
            $rng.GetBytes($swapByte)
            $j = $swapByte[0] % ($i + 1)
            $temp = $chars[$i]
            $chars[$i] = $chars[$j]
            $chars[$j] = $temp
        }

        return (-join $chars)
    }
    finally {
        $rng.Dispose()
    }
}

function Invoke-UserOnboarding {
    param ([Parameter(Mandatory = $true)]$Row)

    $samAccountName = $Row.SamAccountName.Trim().ToLower()
    $displayName = "$($Row.GivenName.Trim()) $($Row.Surname.Trim())"
    $upn = "$samAccountName@$($Row.UpnSuffix.Trim())"
    $targetOU = $Row.TargetOU.Trim()

    if (-not $samAccountName -or -not $targetOU -or -not $Row.UpnSuffix) {
        Write-AuditLog -Level 'ERROR' -Message "Missing required fields for row: $($Row | ConvertTo-Json -Compress)"
        return
    }

    $existingUser = Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" -ErrorAction SilentlyContinue
    if ($existingUser) {
        Write-AuditLog -Level 'WARN' -Message "User '$samAccountName' already exists. Skipping creation."
        return
    }

    $plainPassword = New-StrongTemporaryPassword -Length 18
    $securePassword = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force

    $actionDesc = "Create AD user '$samAccountName' ($displayName) in OU '$targetOU'"
    if ($PSCmdlet.ShouldProcess($samAccountName, $actionDesc)) {
        New-ADUser `
            -SamAccountName $samAccountName `
            -UserPrincipalName $upn `
            -Name $displayName `
            -GivenName $Row.GivenName.Trim() `
            -Surname $Row.Surname.Trim() `
            -Department $Row.Department.Trim() `
            -Title $Row.Title.Trim() `
            -Path $targetOU `
            -AccountPassword $securePassword `
            -ChangePasswordAtLogon $true `
            -Enabled $true

        Write-AuditLog -Level 'INFO' -Message "Created user '$samAccountName' ($upn) in '$targetOU'."

        if ($Row.Groups) {
            $groups = $Row.Groups.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            foreach ($group in $groups) {
                Add-ADGroupMember -Identity $group -Members $samAccountName
                Write-AuditLog -Level 'INFO' -Message "Added '$samAccountName' to group '$group'."
            }
        }
    }
    else {
        Write-AuditLog -Level 'DRYRUN' -Message "Would create user '$samAccountName' ($upn) in '$targetOU' with groups '$($Row.Groups)'."
    }
}

function Invoke-UserOffboarding {
    param ([Parameter(Mandatory = $true)]$Row)

    $samAccountName = $Row.SamAccountName.Trim().ToLower()
    $archiveOU = $Row.ArchiveOU.Trim()

    if (-not $samAccountName -or -not $archiveOU) {
        Write-AuditLog -Level 'ERROR' -Message "Missing SamAccountName or ArchiveOU for row: $($Row | ConvertTo-Json -Compress)"
        return
    }

    $user = Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" -Properties MemberOf -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-AuditLog -Level 'WARN' -Message "User '$samAccountName' not found in Active Directory."
        return
    }

    $actionDesc = "Disable account, remove non-default groups, and move '$samAccountName' to '$archiveOU'"
    if ($PSCmdlet.ShouldProcess($samAccountName, $actionDesc)) {
        Disable-ADAccount -Identity $user.DistinguishedName
        Write-AuditLog -Level 'INFO' -Message "Disabled account '$samAccountName'."

        # Remove group memberships except Domain Users (primary group)
        foreach ($groupDN in $user.MemberOf) {
            Remove-ADGroupMember -Identity $groupDN -Members $user.DistinguishedName -Confirm:$false
            Write-AuditLog -Level 'INFO' -Message "Removed '$samAccountName' from group '$groupDN'."
        }

        Move-ADObject -Identity $user.DistinguishedName -TargetPath $archiveOU
        Write-AuditLog -Level 'INFO' -Message "Moved '$samAccountName' to archive OU '$archiveOU'."
    }
    else {
        Write-AuditLog -Level 'DRYRUN' -Message "Would disable '$samAccountName', clear $($user.MemberOf.Count) group(s), and move to '$archiveOU'."
    }
}

try {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "Active Directory PowerShell module (RSAT) is not installed on this machine."
    }
    Import-Module -Name ActiveDirectory -ErrorAction Stop

    $rows = Import-Csv -Path $CsvPath -Delimiter ',' -Encoding UTF8
    if (-not $rows -or $rows.Count -eq 0) {
        Write-AuditLog -Level 'WARN' -Message "CSV file '$CsvPath' contains no records."
        exit 0
    }

    foreach ($row in $rows) {
        switch ($Mode) {
            'Onboard'  { Invoke-UserOnboarding -Row $row }
            'Offboard' { Invoke-UserOffboarding -Row $row }
        }
    }
}
catch {
    Write-AuditLog -Level 'ERROR' -Message "Execution failed: $($_.Exception.Message)"
    exit 1
}
