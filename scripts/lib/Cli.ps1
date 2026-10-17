Set-StrictMode -Version Latest

# Shared by the scripts in scripts/. Not run on its own: each script dot-sources it.

# The one place that runs gh and git. Tests mock this function, so they never need
# a network, a GitHub token or a real repository.
# -InputText is sent on stdin (gh api --input -). Returns the exit code and the combined stdout and stderr.
function Invoke-Cli {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [ValidateSet('gh', 'git')] [string] $Name,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [string] $InputText
    )
    $run = if ($PSBoundParameters.ContainsKey('InputText')) {
        { $InputText | & $Name @Arguments 2>&1 }
    } else {
        { & $Name @Arguments 2>&1 }
    }
    $lines = @(& $run | ForEach-Object { "$_" })
    [pscustomobject] @{
        ExitCode = $LASTEXITCODE
        Output   = ($lines -join [Environment]::NewLine)
    }
}

# True when a program is on PATH.
function Test-ToolInstalled {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Name)
    [bool] (Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue)
}

# Reads governance/policy.json, the single source of truth for what "governed" means.
function Get-GovernancePolicy {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string] $Path = (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'governance', 'policy.json'))
    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        throw "Policy file not found: $Path"
    }
    Get-Content -Path $Path -Raw | ConvertFrom-Json
}

# owner/name, checked before it goes into any gh argument or API path.
function Assert-RepositoryName {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Repository)
    if ($Repository -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$') {
        throw "Repository must look like owner/name, got '$Repository'."
    }
}

# The HTTP status gh api prints on failure ("gh: Not Found (HTTP 404)"), or nothing when there is none.
function Get-HttpStatus {
    [CmdletBinding()]
    [OutputType([int])]
    param([AllowEmptyString()] [AllowNull()] [string] $Output)
    if ($Output -match '\(HTTP (\d{3})\)') {
        [int] $Matches[1]
    }
}
