Set-StrictMode -Version Latest

$script:InvariantCulture = [System.Globalization.CultureInfo]::InvariantCulture

function Get-BhPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $Object,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function ConvertTo-BhVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    if ($Value -notmatch '(?i)v?(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)') {
        throw "Could not parse a semantic version from '$Value'."
    }

    return [version]::new(
        [int] $Matches.major,
        [int] $Matches.minor,
        [int] $Matches.patch
    )
}

function Get-BhSignatureHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Method,

        [Parameter(Mandatory)]
        [ValidatePattern('^/')]
        [string] $RequestUri,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $TokenId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $TokenKey,

        [byte[]] $Body = [byte[]]::new(0),

        [string] $RequestDate = [DateTimeOffset]::UtcNow.ToString(
            "yyyy-MM-ddTHH:mm:ss.fff'Z'",
            $script:InvariantCulture
        )
    )

    if ($RequestDate.Length -lt 13) {
        throw 'RequestDate must be an RFC3339 timestamp containing at least the hour.'
    }

    $tokenBytes = [Text.Encoding]::UTF8.GetBytes($TokenKey)
    $operationBytes = [Text.Encoding]::UTF8.GetBytes(
        ('{0}{1}' -f $Method.ToUpperInvariant(), $RequestUri)
    )
    $dateBytes = [Text.Encoding]::UTF8.GetBytes($RequestDate.Substring(0, 13))

    $operationHmac = [Security.Cryptography.HMACSHA256]::new($tokenBytes)
    try {
        $operationKey = $operationHmac.ComputeHash($operationBytes)
    }
    finally {
        $operationHmac.Dispose()
    }

    $dateHmac = [Security.Cryptography.HMACSHA256]::new($operationKey)
    try {
        $dateKey = $dateHmac.ComputeHash($dateBytes)
    }
    finally {
        $dateHmac.Dispose()
    }

    $bodyHmac = [Security.Cryptography.HMACSHA256]::new($dateKey)
    try {
        $signature = $bodyHmac.ComputeHash($Body)
    }
    finally {
        $bodyHmac.Dispose()
    }

    return @{
        Authorization = "bhesignature $TokenId"
        RequestDate   = $RequestDate
        Signature     = [Convert]::ToBase64String($signature)
    }
}

function Resolve-BhApiUri {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri] $BaseUri,

        [Parameter(Mandatory)]
        [string] $Uri
    )

    $normalizedBase = [uri]::new($BaseUri.AbsoluteUri.TrimEnd('/') + '/')
    $resolved = [uri]::new($normalizedBase, $Uri)

    if ($resolved.Scheme -ne 'https') {
        throw "BloodHound API URI must use HTTPS: $resolved"
    }

    if (
        $resolved.Host -ne $normalizedBase.Host -or
        $resolved.Port -ne $normalizedBase.Port -or
        $resolved.Scheme -ne $normalizedBase.Scheme
    ) {
        throw "Refusing to send BloodHound credentials to a different origin: $resolved"
    }

    return $resolved
}

function Invoke-BhApiRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri] $BaseUri,

        [Parameter(Mandatory)]
        [string] $Uri,

        [Parameter(Mandatory)]
        [string] $TokenId,

        [Parameter(Mandatory)]
        [string] $TokenKey,

        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string] $Method = 'GET',

        [byte[]] $Body = [byte[]]::new(0),

        [string] $OutFile,

        [ValidateRange(1, 3600)]
        [int] $TimeoutSec = 120
    )

    $target = Resolve-BhApiUri -BaseUri $BaseUri -Uri $Uri
    $headers = Get-BhSignatureHeaders `
        -Method $Method `
        -RequestUri $target.PathAndQuery `
        -TokenId $TokenId `
        -TokenKey $TokenKey `
        -Body $Body

    $request = @{
        Uri                = $target.AbsoluteUri
        Method             = $Method
        Headers            = $headers
        TimeoutSec         = $TimeoutSec
        MaximumRedirection = 0
        UseBasicParsing    = $true
        ErrorAction        = 'Stop'
    }

    if ($Body.Length -gt 0) {
        $request.Body = $Body
        $request.ContentType = 'application/json'
    }

    try {
        if ($OutFile) {
            $request.OutFile = $OutFile
            $oldProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            try {
                $null = Invoke-WebRequest @request
            }
            finally {
                $ProgressPreference = $oldProgressPreference
            }
            return
        }

        return Invoke-RestMethod @request
    }
    catch {
        throw "BloodHound API request failed for $($target.AbsolutePath): $($_.Exception.Message)"
    }
}

function Select-BhCollectorRelease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]] $Releases
    )

    $stable = foreach ($release in $Releases) {
        $prerelease = ''
        $versionMeta = Get-BhPropertyValue -Object $release -Name 'version_meta'
        $prereleaseValue = Get-BhPropertyValue -Object $versionMeta -Name 'prerelease'
        $versionText = [string] (Get-BhPropertyValue -Object $release -Name 'version')
        if ($null -ne $prereleaseValue) {
            $prerelease = [string] $prereleaseValue
        }
        elseif ($versionText -match '-') {
            $prerelease = $versionText.Split('-', 2)[1]
        }

        if ([string]::IsNullOrWhiteSpace($prerelease)) {
            [pscustomobject]@{
                ParsedVersion = ConvertTo-BhVersion -Value $versionText
                Release       = $release
            }
        }
    }

    $selected = $stable | Sort-Object ParsedVersion -Descending | Select-Object -First 1
    if ($null -eq $selected) {
        throw 'The Enterprise manifest does not contain a stable collector release.'
    }

    return $selected.Release
}

function Get-BhPlatformArchitecture {
    [CmdletBinding()]
    param()

    switch -Regex ([string] $env:PROCESSOR_ARCHITEW6432 + [string] $env:PROCESSOR_ARCHITECTURE) {
        'ARM64' { return 'arm64' }
        'AMD64' { return 'amd64' }
        default { return 'x86' }
    }
}

function Select-BhCollectorAsset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Release,

        [Parameter(Mandatory)]
        [ValidateSet('SharpHound', 'AzureHound')]
        [string] $Collector,

        [ValidateSet('amd64', 'arm64', 'x86')]
        [string] $Architecture = (Get-BhPlatformArchitecture)
    )

    $releaseVersion = [string] (Get-BhPropertyValue -Object $Release -Name 'version')
    $releaseAssets = Get-BhPropertyValue -Object $Release -Name 'release_assets'
    $windowsAssets = @($releaseAssets | Where-Object {
        $os = [string] (Get-BhPropertyValue -Object $_ -Name 'os')
        $name = [string] (Get-BhPropertyValue -Object $_ -Name 'name')
        $os -ieq 'windows' -or (
            [string]::IsNullOrWhiteSpace($os) -and $name -match '(?i)(?:^|_)windows(?:_|\.|$)'
        )
    })

    if ($windowsAssets.Count -eq 0) {
        throw "No Windows asset is available for $Collector $releaseVersion."
    }

    $candidates = @($windowsAssets | Where-Object {
        $arch = [string] (Get-BhPropertyValue -Object $_ -Name 'arch')
        $name = [string] (Get-BhPropertyValue -Object $_ -Name 'name')
        $arch -ieq $Architecture -or (
            [string]::IsNullOrWhiteSpace($arch) -and
            $name -match "(?i)(?:^|_)$([regex]::Escape($Architecture))(?:_|\.|$)"
        )
    })

    if ($candidates.Count -eq 0 -and $Collector -eq 'SharpHound') {
        $candidates = @($windowsAssets | Where-Object {
            $arch = [string] (Get-BhPropertyValue -Object $_ -Name 'arch')
            $name = [string] (Get-BhPropertyValue -Object $_ -Name 'name')
            $arch -ieq 'x86' -or (
                [string]::IsNullOrWhiteSpace($arch) -and
                $name -match '(?i)(?:^|_)x86(?:_|\.|$)'
            )
        })
    }

    if ($candidates.Count -ne 1) {
        throw "Expected one Windows/$Architecture asset for $Collector $releaseVersion, found $($candidates.Count)."
    }

    $asset = $candidates[0]
    foreach ($property in 'name', 'download_url', 'checksum_download_url') {
        if ([string]::IsNullOrWhiteSpace(
            [string] (Get-BhPropertyValue -Object $asset -Name $property)
        )) {
            throw "Manifest asset for $Collector is missing '$property'."
        }
    }

    return $asset
}

function Get-BhSha256FromText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    if ($Text -notmatch '(?im)(?<![0-9a-f])(?<hash>[0-9a-f]{64})(?![0-9a-f])') {
        throw 'The checksum response does not contain a valid SHA-256 value.'
    }

    return $Matches.hash.ToLowerInvariant()
}

function Assert-BhAuthenticodeSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string] $Path,

        [ValidateNotNullOrEmpty()]
        [string] $AllowedPublisher = 'Specter Ops, Inc.'
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
        throw "Authenticode signature validation failed for '$Path': $($signature.StatusMessage)"
    }

    $subject = [string] $signature.SignerCertificate.Subject
    if ($subject -notmatch [regex]::Escape($AllowedPublisher)) {
        throw "Unexpected Authenticode publisher for '$Path': $subject"
    }

    return $signature
}

function Receive-BhCollectorPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri] $BaseUri,

        [Parameter(Mandatory)]
        [string] $TokenId,

        [Parameter(Mandatory)]
        [string] $TokenKey,

        [Parameter(Mandatory)]
        [object] $Asset,

        [Parameter(Mandatory)]
        [ValidateSet('SharpHound', 'AzureHound')]
        [string] $Collector,

        [Parameter(Mandatory)]
        [string] $StagingDirectory,

        [string] $AllowedPublisher = 'Specter Ops, Inc.'
    )

    $null = New-Item -ItemType Directory -Path $StagingDirectory -Force
    $archivePath = Join-Path $StagingDirectory ([IO.Path]::GetFileName([string] $Asset.name))
    $checksumPath = "$archivePath.sha256"

    Invoke-BhApiRequest `
        -BaseUri $BaseUri `
        -Uri ([string] $Asset.checksum_download_url) `
        -TokenId $TokenId `
        -TokenKey $TokenKey `
        -OutFile $checksumPath

    Invoke-BhApiRequest `
        -BaseUri $BaseUri `
        -Uri ([string] $Asset.download_url) `
        -TokenId $TokenId `
        -TokenKey $TokenKey `
        -OutFile $archivePath

    $expectedHash = Get-BhSha256FromText -Text (Get-Content -LiteralPath $checksumPath -Raw)
    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "SHA-256 mismatch for '$($Asset.name)'. Expected $expectedHash, got $actualHash."
    }

    $extractPath = Join-Path $StagingDirectory 'extracted'
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath -Force

    $fileName = if ($Collector -eq 'SharpHound') {
        'SHSetup-v*.exe'
    }
    else {
        'azurehound.exe'
    }

    $executables = @(Get-ChildItem -LiteralPath $extractPath -Filter $fileName -File -Recurse)
    if ($executables.Count -ne 1) {
        throw "Expected one '$fileName' in '$($Asset.name)', found $($executables.Count)."
    }

    $null = Assert-BhAuthenticodeSignature `
        -Path $executables[0].FullName `
        -AllowedPublisher $AllowedPublisher

    return [pscustomobject]@{
        ArchivePath   = $archivePath
        ExecutablePath = $executables[0].FullName
        ArchiveSha256 = $actualHash
        BinarySha256  = (Get-FileHash -LiteralPath $executables[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Get-BhServiceExecutablePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ServiceName
    )

    $escapedName = $ServiceName.Replace("'", "''")
    $service = Get-CimInstance `
        -ClassName Win32_Service `
        -Filter "Name='$escapedName'" `
        -ErrorAction SilentlyContinue

    if ($null -eq $service -or [string]::IsNullOrWhiteSpace([string] $service.PathName)) {
        return $null
    }

    $commandLine = [Environment]::ExpandEnvironmentVariables([string] $service.PathName).Trim()
    if ($commandLine -match '^"(?<path>[^"]+\.exe)"') {
        return $Matches.path
    }
    if ($commandLine -match '^(?<path>.+?\.exe)(?:\s|$)') {
        return $Matches.path
    }

    throw "Could not parse the executable path for service '$ServiceName': $commandLine"
}

function Get-BhFileVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    $versionInfo = (Get-Item -LiteralPath $Path).VersionInfo
    foreach ($candidate in $versionInfo.ProductVersion, $versionInfo.FileVersion) {
        if (-not [string]::IsNullOrWhiteSpace([string] $candidate)) {
            try {
                return ConvertTo-BhVersion -Value ([string] $candidate)
            }
            catch {
                continue
            }
        }
    }

    return $null
}

function Wait-BhServiceStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ServiceName,

        [Parameter(Mandatory)]
        [ValidateSet('Running', 'Stopped')]
        [string] $Status,

        [ValidateRange(1, 600)]
        [int] $TimeoutSec = 60
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    do {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        if ([string] $service.Status -eq $Status) {
            return
        }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "Service '$ServiceName' did not reach state '$Status' within $TimeoutSec seconds."
}

function Stop-BhCollectorService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ServiceName,

        [int] $TimeoutSec = 60
    )

    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        Wait-BhServiceStatus -ServiceName $ServiceName -Status Stopped -TimeoutSec $TimeoutSec
    }
}

function Start-BhCollectorService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ServiceName,

        [int] $TimeoutSec = 60
    )

    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        Start-Service -Name $ServiceName -ErrorAction Stop
    }
    Wait-BhServiceStatus -ServiceName $ServiceName -Status Running -TimeoutSec $TimeoutSec
}

function Test-BhAdministrator {
    [CmdletBinding()]
    param()

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        return $false
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-BhWorkingDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $null = New-Item -ItemType Directory -Path $Path -Force
    $directory = Get-Item -LiteralPath $Path -Force
    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Working directory '$Path' must not be a symbolic link or junction."
    }

    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $access = [Security.AccessControl.AccessControlType]::Allow
    $rights = [Security.AccessControl.FileSystemRights]::FullControl

    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($sidValue in 'S-1-5-18', 'S-1-5-32-544', $currentSid) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidValue)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            $rights,
            $inheritance,
            $propagation,
            $access
        )
        $null = $acl.AddAccessRule($rule)
    }

    Set-Acl -LiteralPath $directory.FullName -AclObject $acl
}

function Get-BhUpdaterState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{}
    }

    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw "Updater state file '$Path' is invalid: $($_.Exception.Message)"
    }
}

function Set-BhUpdaterState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [ValidateSet('SharpHound', 'AzureHound')]
        [string] $Collector,

        [Parameter(Mandatory)]
        [version] $Version,

        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $state = Get-BhUpdaterState -Path $Path
    $record = [pscustomobject]@{
        version       = $Version.ToString(3)
        executable    = $ExecutablePath
        sha256        = (Get-FileHash -LiteralPath $ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant()
        updated_at_utc = [DateTime]::UtcNow.ToString('o', $script:InvariantCulture)
    }
    $state | Add-Member -NotePropertyName $Collector -NotePropertyValue $record -Force

    $directory = Split-Path -Parent $Path
    $null = New-Item -ItemType Directory -Path $directory -Force
    $temporaryPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
    Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

function Get-BhInstalledVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('SharpHound', 'AzureHound')]
        [string] $Collector,

        [Parameter(Mandatory)]
        [string] $ExecutablePath,

        [Parameter(Mandatory)]
        [string] $StatePath
    )

    $state = Get-BhUpdaterState -Path $StatePath
    $stateProperty = $state.PSObject.Properties[$Collector]
    if ($null -ne $stateProperty -and (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
        $record = $stateProperty.Value
        $recordPath = [IO.Path]::GetFullPath([string] $record.executable)
        $currentPath = [IO.Path]::GetFullPath($ExecutablePath)
        $samePath = $recordPath.Equals(
            $currentPath,
            [StringComparison]::OrdinalIgnoreCase
        )
        if ($samePath) {
            $currentHash = (Get-FileHash -LiteralPath $ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($currentHash -eq [string] $record.sha256) {
                return ConvertTo-BhVersion -Value ([string] $record.version)
            }
        }
    }

    return Get-BhFileVersion -Path $ExecutablePath
}

function Get-BhUpdateDisposition {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [version] $InstalledVersion,

        [Parameter(Mandatory)]
        [version] $AvailableVersion,

        [switch] $Force
    )

    if ($Force) {
        return 'UpdateAvailable'
    }
    if ($null -eq $InstalledVersion) {
        return 'UpdateAvailable'
    }
    if ($InstalledVersion -gt $AvailableVersion) {
        return 'NewerInstalled'
    }
    if ($InstalledVersion -eq $AvailableVersion) {
        return 'UpToDate'
    }
    return 'UpdateAvailable'
}

function Invoke-BhSharpHoundUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Release,

        [Parameter(Mandatory)]
        [object] $Asset,

        [Parameter(Mandatory)]
        [uri] $BaseUri,

        [Parameter(Mandatory)]
        [string] $TokenId,

        [Parameter(Mandatory)]
        [string] $TokenKey,

        [Parameter(Mandatory)]
        [string] $ExecutablePath,

        [Parameter(Mandatory)]
        [string] $ServiceName,

        [Parameter(Mandatory)]
        [string] $WorkingDirectory,

        [Parameter(Mandatory)]
        [string] $StatePath,

        [string] $AllowedPublisher,

        [int] $ServiceTimeoutSec = 90,

        [switch] $CheckOnly,

        [switch] $Force
    )

    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        throw "SharpHound service '$ServiceName' is not installed. This updater only upgrades existing collectors."
    }
    if (-not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
        throw "SharpHound executable was not found at '$ExecutablePath'."
    }

    $availableVersion = ConvertTo-BhVersion -Value (
        [string] (Get-BhPropertyValue -Object $Release -Name 'version')
    )
    $installedVersion = Get-BhInstalledVersion `
        -Collector SharpHound `
        -ExecutablePath $ExecutablePath `
        -StatePath $StatePath
    $disposition = Get-BhUpdateDisposition `
        -InstalledVersion $installedVersion `
        -AvailableVersion $availableVersion `
        -Force:$Force

    if ($disposition -ne 'UpdateAvailable' -or $CheckOnly) {
        return [pscustomobject]@{
            Collector        = 'SharpHound'
            InstalledVersion = if ($installedVersion) { $installedVersion.ToString(3) } else { 'Unknown' }
            AvailableVersion = $availableVersion.ToString(3)
            Action           = if ($CheckOnly -and $disposition -eq 'UpdateAvailable') { 'UpdateAvailable' } else { $disposition }
            ExecutablePath   = $ExecutablePath
        }
    }

    $stage = Join-Path $WorkingDirectory "SharpHound-$($availableVersion.ToString(3))-$([guid]::NewGuid().ToString('N'))"
    try {
        $package = Receive-BhCollectorPackage `
            -BaseUri $BaseUri `
            -TokenId $TokenId `
            -TokenKey $TokenKey `
            -Asset $Asset `
            -Collector SharpHound `
            -StagingDirectory $stage `
            -AllowedPublisher $AllowedPublisher

        $logDirectory = Join-Path $WorkingDirectory 'logs'
        $null = New-Item -ItemType Directory -Path $logDirectory -Force
        $installerLog = Join-Path $logDirectory "SharpHound-$($availableVersion.ToString(3))-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')).log"

        Stop-BhCollectorService -ServiceName $ServiceName -TimeoutSec $ServiceTimeoutSec
        try {
            $arguments = @(
                '/VERYSILENT',
                '/SUPPRESSMSGBOXES',
                '/FORCECLOSEAPPLICATIONS',
                "/LOG=`"$installerLog`""
            )
            $process = Start-Process `
                -FilePath $package.ExecutablePath `
                -ArgumentList $arguments `
                -Wait `
                -PassThru `
                -ErrorAction Stop
            if ($process.ExitCode -ne 0) {
                throw "SharpHound installer exited with code $($process.ExitCode). See '$installerLog'."
            }

            Start-BhCollectorService -ServiceName $ServiceName -TimeoutSec $ServiceTimeoutSec
            $updatedPath = Get-BhServiceExecutablePath -ServiceName $ServiceName
            if (-not [string]::IsNullOrWhiteSpace($updatedPath)) {
                $ExecutablePath = $updatedPath
            }
            $updatedVersion = Get-BhFileVersion -Path $ExecutablePath
            if (-not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
                throw "SharpHound installer completed, but '$ExecutablePath' is missing."
            }
            if ($null -eq $updatedVersion -or $updatedVersion -ne $availableVersion) {
                Write-Warning "SharpHound installer succeeded and the service is running, but '$ExecutablePath' does not report version $availableVersion. The tenant package version will be recorded."
            }

            Set-BhUpdaterState `
                -Path $StatePath `
                -Collector SharpHound `
                -Version $availableVersion `
                -ExecutablePath $ExecutablePath
        }
        catch {
            try {
                Start-BhCollectorService -ServiceName $ServiceName -TimeoutSec $ServiceTimeoutSec
            }
            catch {
                Write-Warning "SharpHound service recovery failed: $($_.Exception.Message)"
            }
            throw
        }

        return [pscustomobject]@{
            Collector        = 'SharpHound'
            InstalledVersion = if ($installedVersion) { $installedVersion.ToString(3) } else { 'Unknown' }
            AvailableVersion = $availableVersion.ToString(3)
            Action           = 'Updated'
            ExecutablePath   = $ExecutablePath
        }
    }
    finally {
        if (Test-Path -LiteralPath $stage) {
            Remove-Item -LiteralPath $stage -Recurse -Force
        }
    }
}

function Invoke-BhAzureHoundUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Release,

        [Parameter(Mandatory)]
        [object] $Asset,

        [Parameter(Mandatory)]
        [uri] $BaseUri,

        [Parameter(Mandatory)]
        [string] $TokenId,

        [Parameter(Mandatory)]
        [string] $TokenKey,

        [Parameter(Mandatory)]
        [string] $ExecutablePath,

        [Parameter(Mandatory)]
        [string] $ServiceName,

        [Parameter(Mandatory)]
        [string] $WorkingDirectory,

        [Parameter(Mandatory)]
        [string] $StatePath,

        [string] $AllowedPublisher,

        [int] $ServiceTimeoutSec = 90,

        [ValidateRange(1, 20)]
        [int] $BackupRetentionCount = 2,

        [switch] $CheckOnly,

        [switch] $Force
    )

    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        throw "AzureHound service '$ServiceName' is not installed. This updater only upgrades existing collectors."
    }
    if (-not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
        throw "AzureHound executable was not found at '$ExecutablePath'."
    }

    $availableVersion = ConvertTo-BhVersion -Value (
        [string] (Get-BhPropertyValue -Object $Release -Name 'version')
    )
    $installedVersion = Get-BhInstalledVersion `
        -Collector AzureHound `
        -ExecutablePath $ExecutablePath `
        -StatePath $StatePath
    $disposition = Get-BhUpdateDisposition `
        -InstalledVersion $installedVersion `
        -AvailableVersion $availableVersion `
        -Force:$Force

    if ($disposition -ne 'UpdateAvailable' -or $CheckOnly) {
        return [pscustomobject]@{
            Collector        = 'AzureHound'
            InstalledVersion = if ($installedVersion) { $installedVersion.ToString(3) } else { 'Unknown' }
            AvailableVersion = $availableVersion.ToString(3)
            Action           = if ($CheckOnly -and $disposition -eq 'UpdateAvailable') { 'UpdateAvailable' } else { $disposition }
            ExecutablePath   = $ExecutablePath
        }
    }

    $stage = Join-Path $WorkingDirectory "AzureHound-$($availableVersion.ToString(3))-$([guid]::NewGuid().ToString('N'))"
    $destinationDirectory = Split-Path -Parent $ExecutablePath
    $pendingPath = Join-Path $destinationDirectory "azurehound.$([guid]::NewGuid().ToString('N')).new.exe"
    $backupPath = "$ExecutablePath.bak-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))"
    $serviceStopped = $false
    $replacementStarted = $false
    $committed = $false

    try {
        $package = Receive-BhCollectorPackage `
            -BaseUri $BaseUri `
            -TokenId $TokenId `
            -TokenKey $TokenKey `
            -Asset $Asset `
            -Collector AzureHound `
            -StagingDirectory $stage `
            -AllowedPublisher $AllowedPublisher

        Copy-Item -LiteralPath $package.ExecutablePath -Destination $pendingPath -Force
        if ((Get-FileHash -LiteralPath $pendingPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $package.BinarySha256) {
            throw "AzureHound staging verification failed for '$pendingPath'."
        }

        Stop-BhCollectorService -ServiceName $ServiceName -TimeoutSec $ServiceTimeoutSec
        $serviceStopped = $true
        Move-Item -LiteralPath $ExecutablePath -Destination $backupPath
        $replacementStarted = $true
        Move-Item -LiteralPath $pendingPath -Destination $ExecutablePath

        $destinationHash = (Get-FileHash -LiteralPath $ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($destinationHash -ne $package.BinarySha256) {
            throw "AzureHound replacement verification failed for '$ExecutablePath'."
        }
        $null = Assert-BhAuthenticodeSignature `
            -Path $ExecutablePath `
            -AllowedPublisher $AllowedPublisher

        $updatedVersion = Get-BhFileVersion -Path $ExecutablePath
        if ($null -ne $updatedVersion -and $updatedVersion -ne $availableVersion) {
            throw "AzureHound replacement reports version $updatedVersion instead of $availableVersion."
        }

        Start-BhCollectorService -ServiceName $ServiceName -TimeoutSec $ServiceTimeoutSec
        $serviceStopped = $false
        $committed = $true

        try {
            Set-BhUpdaterState `
                -Path $StatePath `
                -Collector AzureHound `
                -Version $availableVersion `
                -ExecutablePath $ExecutablePath
        }
        catch {
            Write-Warning "AzureHound was updated, but updater state could not be saved: $($_.Exception.Message)"
        }

        try {
            $backups = @(Get-ChildItem `
                -LiteralPath $destinationDirectory `
                -Filter "$([IO.Path]::GetFileName($ExecutablePath)).bak-*" `
                -File | Sort-Object LastWriteTimeUtc -Descending)
            $backups | Select-Object -Skip $BackupRetentionCount | Remove-Item -Force -ErrorAction Stop
        }
        catch {
            Write-Warning "AzureHound was updated, but old backups could not be pruned: $($_.Exception.Message)"
        }

        return [pscustomobject]@{
            Collector        = 'AzureHound'
            InstalledVersion = if ($installedVersion) { $installedVersion.ToString(3) } else { 'Unknown' }
            AvailableVersion = $availableVersion.ToString(3)
            Action           = 'Updated'
            ExecutablePath   = $ExecutablePath
            BackupPath       = $backupPath
        }
    }
    catch {
        $updateError = $_
        if ($replacementStarted -and -not $committed) {
            try {
                Stop-BhCollectorService -ServiceName $ServiceName -TimeoutSec $ServiceTimeoutSec
                if (Test-Path -LiteralPath $ExecutablePath) {
                    Remove-Item -LiteralPath $ExecutablePath -Force
                }
                Move-Item -LiteralPath $backupPath -Destination $ExecutablePath -Force
                Start-BhCollectorService -ServiceName $ServiceName -TimeoutSec $ServiceTimeoutSec
                $serviceStopped = $false
            }
            catch {
                throw "AzureHound update failed and rollback also failed: $($updateError.Exception.Message) Rollback error: $($_.Exception.Message)"
            }
        }
        elseif ($serviceStopped) {
            try {
                Start-BhCollectorService -ServiceName $ServiceName -TimeoutSec $ServiceTimeoutSec
                $serviceStopped = $false
            }
            catch {
                throw "AzureHound update failed before replacement and service recovery also failed: $($updateError.Exception.Message) Recovery error: $($_.Exception.Message)"
            }
        }
        throw $updateError
    }
    finally {
        if (Test-Path -LiteralPath $pendingPath) {
            Remove-Item -LiteralPath $pendingPath -Force
        }
        if (Test-Path -LiteralPath $stage) {
            Remove-Item -LiteralPath $stage -Recurse -Force
        }
    }
}

function Invoke-BloodHoundCollectorUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri] $BloodHoundUrl,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $TokenId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $TokenKey,

        [ValidateSet('SharpHound', 'AzureHound')]
        [string[]] $Collectors = @('SharpHound', 'AzureHound'),

        [string] $SharpHoundPath,

        [string] $AzureHoundPath,

        [string] $SharpHoundServiceName = 'SHDelegator',

        [string] $AzureHoundServiceName = 'AzureHound',

        [string] $WorkingDirectory = (Join-Path $env:ProgramData 'BloodHoundCollectorUpdater'),

        [string] $AllowedPublisher = 'Specter Ops, Inc.',

        [ValidateRange(5, 600)]
        [int] $ServiceTimeoutSec = 90,

        [ValidateRange(1, 20)]
        [int] $BackupRetentionCount = 2,

        [switch] $CheckOnly,

        [switch] $Force
    )

    if (-not $CheckOnly -and -not (Test-BhAdministrator)) {
        throw 'Collector updates require an elevated PowerShell session.'
    }

    if ($BloodHoundUrl.Scheme -ne 'https') {
        throw 'BloodHoundUrl must use HTTPS.'
    }

    if (
        [Net.ServicePointManager]::SecurityProtocol -band
        [Net.SecurityProtocolType]::Tls12
    ) {
        # TLS 1.2 is already enabled.
    }
    else {
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    $apiVersion = Invoke-BhApiRequest `
        -BaseUri $BloodHoundUrl `
        -Uri '/api/version' `
        -TokenId $TokenId `
        -TokenKey $TokenKey
    $versionData = Get-BhPropertyValue -Object $apiVersion -Name 'data'
    $apiData = Get-BhPropertyValue -Object $versionData -Name 'API'
    $currentApiVersion = [string] (Get-BhPropertyValue -Object $apiData -Name 'current_version')
    if ($currentApiVersion -ne 'v2') {
        throw "Unsupported BloodHound API version '$currentApiVersion'; expected 'v2'."
    }

    $manifestResponse = Invoke-BhApiRequest `
        -BaseUri $BloodHoundUrl `
        -Uri '/api/v2/kennel/enterprise-manifest' `
        -TokenId $TokenId `
        -TokenKey $TokenKey
    $manifestData = Get-BhPropertyValue -Object $manifestResponse -Name 'data'
    if ($null -eq $manifestData) {
        throw 'BloodHound Enterprise manifest response does not contain data.'
    }

    $statePath = Join-Path $WorkingDirectory 'state.json'
    if (-not $CheckOnly) {
        Initialize-BhWorkingDirectory -Path $WorkingDirectory
    }
    $results = @()

    foreach ($collector in $Collectors) {
        $collectorPath = $null
        $availableVersionText = 'Unknown'
        try {
            if ($collector -eq 'SharpHound') {
                $releaseData = Get-BhPropertyValue `
                    -Object $manifestData `
                    -Name 'sharphound_enterprise'
                $releases = @($releaseData | Where-Object { $null -ne $_ })
                if ($releases.Count -eq 0) {
                    throw 'The Enterprise manifest does not contain SharpHound releases.'
                }
                $release = Select-BhCollectorRelease -Releases $releases
                $availableVersionText = [string] (
                    Get-BhPropertyValue -Object $release -Name 'version'
                )
                $asset = Select-BhCollectorAsset -Release $release -Collector SharpHound

                $collectorPath = $SharpHoundPath
                if ([string]::IsNullOrWhiteSpace($collectorPath)) {
                    $collectorPath = Get-BhServiceExecutablePath -ServiceName $SharpHoundServiceName
                }
                if ([string]::IsNullOrWhiteSpace($collectorPath)) {
                    $collectorPath = Join-Path ${env:ProgramFiles(x86)} 'SHService\SHDelegator.exe'
                }

                $results += Invoke-BhSharpHoundUpdate `
                    -Release $release `
                    -Asset $asset `
                    -BaseUri $BloodHoundUrl `
                    -TokenId $TokenId `
                    -TokenKey $TokenKey `
                    -ExecutablePath $collectorPath `
                    -ServiceName $SharpHoundServiceName `
                    -WorkingDirectory $WorkingDirectory `
                    -StatePath $statePath `
                    -AllowedPublisher $AllowedPublisher `
                    -ServiceTimeoutSec $ServiceTimeoutSec `
                    -CheckOnly:$CheckOnly `
                    -Force:$Force
            }
            else {
                $releaseData = Get-BhPropertyValue `
                    -Object $manifestData `
                    -Name 'azurehound_enterprise'
                $releases = @($releaseData | Where-Object { $null -ne $_ })
                if ($releases.Count -eq 0) {
                    throw 'The Enterprise manifest does not contain AzureHound releases.'
                }
                $release = Select-BhCollectorRelease -Releases $releases
                $availableVersionText = [string] (
                    Get-BhPropertyValue -Object $release -Name 'version'
                )
                $asset = Select-BhCollectorAsset -Release $release -Collector AzureHound

                $collectorPath = $AzureHoundPath
                if ([string]::IsNullOrWhiteSpace($collectorPath)) {
                    $collectorPath = Get-BhServiceExecutablePath -ServiceName $AzureHoundServiceName
                }
                if ([string]::IsNullOrWhiteSpace($collectorPath)) {
                    $collectorPath = Join-Path $env:ProgramFiles 'AzureHound Enterprise\azurehound.exe'
                }

                $results += Invoke-BhAzureHoundUpdate `
                    -Release $release `
                    -Asset $asset `
                    -BaseUri $BloodHoundUrl `
                    -TokenId $TokenId `
                    -TokenKey $TokenKey `
                    -ExecutablePath $collectorPath `
                    -ServiceName $AzureHoundServiceName `
                    -WorkingDirectory $WorkingDirectory `
                    -StatePath $statePath `
                    -AllowedPublisher $AllowedPublisher `
                    -ServiceTimeoutSec $ServiceTimeoutSec `
                    -BackupRetentionCount $BackupRetentionCount `
                    -CheckOnly:$CheckOnly `
                    -Force:$Force
            }
        }
        catch {
            $results += [pscustomobject]@{
                Collector        = $collector
                InstalledVersion = 'Unknown'
                AvailableVersion = $availableVersionText
                Action           = 'Failed'
                ExecutablePath   = $collectorPath
                Error            = $_.Exception.Message
            }
        }
    }

    return $results
}

Export-ModuleMember -Function @(
    'ConvertTo-BhVersion',
    'Get-BhSignatureHeaders',
    'Resolve-BhApiUri',
    'Select-BhCollectorRelease',
    'Select-BhCollectorAsset',
    'Get-BhSha256FromText',
    'Assert-BhAuthenticodeSignature',
    'Get-BhServiceExecutablePath',
    'Get-BhFileVersion',
    'Get-BhUpdateDisposition',
    'Invoke-BloodHoundCollectorUpdate'
)
