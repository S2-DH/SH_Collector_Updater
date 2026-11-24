[CmdletBinding()]
param(
    [uri] $BloodHoundUrl = $env:BHE_URL,

    [string] $TokenId = $env:BHE_TOKEN_ID,

    [string] $TokenKey = $env:BHE_TOKEN_KEY,

    [ValidateSet('SharpHound', 'AzureHound')]
    [string[]] $Collectors = @('SharpHound', 'AzureHound'),

    [string] $SharpHoundPath,

    [string] $AzureHoundPath,

    [string] $SharpHoundServiceName = 'SHDelegator',

    [string] $AzureHoundServiceName = 'AzureHound',

    [string] $WorkingDirectory = (Join-Path $env:ProgramData 'BloodHoundCollectorUpdater'),

    [ValidateRange(5, 600)]
    [int] $ServiceTimeoutSec = 90,

    [ValidateRange(1, 20)]
    [int] $BackupRetentionCount = 2,

    [string] $ResultPath,

    [switch] $CheckOnly,

    [switch] $Force
)

$ErrorActionPreference = 'Stop'

if ($null -eq $BloodHoundUrl) {
    throw 'BloodHoundUrl is required. Pass -BloodHoundUrl or set BHE_URL.'
}
if ([string]::IsNullOrWhiteSpace($TokenId)) {
    throw 'TokenId is required. Pass -TokenId or set BHE_TOKEN_ID.'
}
if ([string]::IsNullOrWhiteSpace($TokenKey)) {
    throw 'TokenKey is required. Pass -TokenKey or set BHE_TOKEN_KEY.'
}

Import-Module (Join-Path $PSScriptRoot 'BloodHoundCollectorUpdater.psm1') -Force

$parameters = @{
    BloodHoundUrl         = $BloodHoundUrl
    TokenId               = $TokenId
    TokenKey              = $TokenKey
    Collectors            = $Collectors
    SharpHoundServiceName = $SharpHoundServiceName
    AzureHoundServiceName = $AzureHoundServiceName
    WorkingDirectory      = $WorkingDirectory
    ServiceTimeoutSec     = $ServiceTimeoutSec
    BackupRetentionCount  = $BackupRetentionCount
    CheckOnly             = $CheckOnly
    Force                 = $Force
}
if (-not [string]::IsNullOrWhiteSpace($SharpHoundPath)) {
    $parameters.SharpHoundPath = $SharpHoundPath
}
if (-not [string]::IsNullOrWhiteSpace($AzureHoundPath)) {
    $parameters.AzureHoundPath = $AzureHoundPath
}

$results = @(Invoke-BloodHoundCollectorUpdate @parameters)

if (-not [string]::IsNullOrWhiteSpace($ResultPath)) {
    $resultDirectory = Split-Path -Parent $ResultPath
    if (-not [string]::IsNullOrWhiteSpace($resultDirectory)) {
        $null = New-Item -ItemType Directory -Path $resultDirectory -Force
    }
    $results | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $ResultPath -Encoding UTF8
}

$results

$failed = @($results | Where-Object { $_.Action -eq 'Failed' })
if ($failed.Count -gt 0) {
    $summary = ($failed | ForEach-Object {
        "$($_.Collector): $($_.Error)"
    }) -join '; '
    throw "One or more collector updates failed. $summary"
}
