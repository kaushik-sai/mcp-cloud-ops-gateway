<#
.SYNOPSIS
    Runs the same checks as CI, before you push.

.DESCRIPTION
    Checks, in order:
      gofmt         every .go file is formatted
      vet           go vet ./...
      golangci-lint golangci-lint run ./... with .golangci.yml
      test          go test -race -count=1 ./... (the e2e tests need a cluster and a build tag; not run)
      govulncheck   known vulnerabilities in the code the gateway can reach
      actionlint    GitHub Actions workflow syntax
      gitleaks      secrets. In a git repository it runs `gitleaks git`, which scans every commit
                    that a push would publish, including a secret added and deleted again.
                    Outside one it runs `gitleaks dir .` on the files.
    A tool that is not installed is reported as Skip with how to install it. A check you
    pass in -Skip is reported as Skip too. Prints a summary table. Exits 1 if any check failed.

.PARAMETER Skip
    Checks to leave out: gofmt, vet, golangci-lint, test, govulncheck, actionlint, gitleaks.

.EXAMPLE
    pwsh ./scripts/Invoke-LocalChecks.ps1 -Skip gitleaks, govulncheck
#>
[CmdletBinding()]
param(
    [ValidateSet('gofmt', 'vet', 'golangci-lint', 'test', 'govulncheck', 'actionlint', 'gitleaks')]
    [string[]] $Skip = @()
)

Set-StrictMode -Version Latest

# The checks, in order: what each one needs and how to get it.
function Get-LocalCheck {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()
    $goInstall = 'https://go.dev/doc/install'
    [pscustomobject] @{ Name = 'gofmt'; Tool = 'gofmt'; Install = $goInstall }
    [pscustomobject] @{ Name = 'vet'; Tool = 'go'; Install = $goInstall }
    [pscustomobject] @{ Name = 'golangci-lint'; Tool = 'golangci-lint'; Install = 'brew install golangci-lint or go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest; https://golangci-lint.run/welcome/install/' }
    [pscustomobject] @{ Name = 'test'; Tool = 'go'; Install = $goInstall }
    [pscustomobject] @{ Name = 'govulncheck'; Tool = 'govulncheck'; Install = 'go install golang.org/x/vuln/cmd/govulncheck@v1.7.0' }
    [pscustomobject] @{ Name = 'actionlint'; Tool = 'actionlint'; Install = 'brew install actionlint or winget install rhysd.actionlint; https://github.com/rhysd/actionlint' }
    [pscustomobject] @{ Name = 'gitleaks'; Tool = 'gitleaks'; Install = 'brew install gitleaks or winget install gitleaks.gitleaks; https://github.com/gitleaks/gitleaks' }
}

function Test-ToolInstalled {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Name)
    [bool] (Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue)
}

# The one place that runs the tools. Tests mock this function.
# Returns the exit code and the combined stdout and stderr.
function Invoke-LocalTool {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [ValidateSet('gofmt', 'vet', 'golangci-lint', 'test', 'govulncheck', 'actionlint', 'gitleaks')] [string] $Name)
    $inGit = Test-Path -Path (Join-Path -Path (Get-Location) -ChildPath '.git')
    $command = switch ($Name) {
        'gofmt' { @{ File = 'gofmt'; Arguments = @('-l', '.') } }
        'vet' { @{ File = 'go'; Arguments = @('vet', './...') } }
        'golangci-lint' { @{ File = 'golangci-lint'; Arguments = @('run', './...') } }
        'test' { @{ File = 'go'; Arguments = @('test', '-race', '-count=1', './...') } }
        'govulncheck' { @{ File = 'govulncheck'; Arguments = @('./...') } }
        'actionlint' { @{ File = 'actionlint'; Arguments = @() } }
        'gitleaks' {
            @{ File = 'gitleaks'; Arguments = @($(if ($inGit) { 'git' } else { 'dir' }), '.', '--config', '.gitleaks.toml', '--redact', '--no-banner') }
        }
    }
    $file = $command.File
    $arguments = $command.Arguments
    $lines = @(& $file @arguments 2>&1 | ForEach-Object { "$_" })
    $exitCode = $LASTEXITCODE
    # gofmt -l exits 0 even when it lists unformatted files; any output is a failure.
    if ($Name -eq 'gofmt' -and $exitCode -eq 0 -and $lines.Count -gt 0) {
        $exitCode = 1
        $lines = @('Not formatted (run gofmt -w):') + $lines
    }
    [pscustomobject] @{ ExitCode = $exitCode; Output = ($lines -join [Environment]::NewLine) }
}

# Runs each check once. Returns one result per check: Check, Status (Pass, Fail, Skip), Detail.
function Invoke-LocalCheck {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string[]] $Skip = @())
    foreach ($check in Get-LocalCheck) {
        $status = 'Pass'
        $detail = ''
        if ($check.Name -in $Skip) {
            $status = 'Skip'
            $detail = 'Skipped by -Skip.'
        } elseif (-not (Test-ToolInstalled -Name $check.Tool)) {
            $status = 'Skip'
            $detail = "$($check.Tool) is not installed. Install: $($check.Install)"
        } else {
            $run = Invoke-LocalTool -Name $check.Name
            if ($run.ExitCode -ne 0) {
                $status = 'Fail'
                $detail = "Exit code $($run.ExitCode).`n$($run.Output)"
            }
        }
        [pscustomobject] @{ Check = $check.Name; Status = $status; Detail = $detail }
    }
}

# Main: only runs when the script is executed, not when tests dot-source it.
if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    $InformationPreference = 'Continue'
    # go install puts govulncheck and golangci-lint here; it is often not on PATH.
    if (Test-ToolInstalled -Name 'go') {
        $goBin = Join-Path -Path (& go env GOPATH) -ChildPath 'bin'
        if (Test-Path -Path $goBin) {
            $env:PATH = $goBin + [IO.Path]::PathSeparator + $env:PATH
        }
    }
    Push-Location -Path (Join-Path -Path $PSScriptRoot -ChildPath '..')
    try {
        $results = @(Invoke-LocalCheck -Skip $Skip)
    } finally {
        Pop-Location
    }
    foreach ($r in @($results | Where-Object Status -eq 'Fail')) {
        Write-Information "--- $($r.Check) ---`n$($r.Detail)"
    }
    $table = $results | Select-Object Check, Status, @{ Name = 'Detail'; Expression = { ($_.Detail -split "`n")[0] } }
    Write-Information ($table | Format-Table -AutoSize -Wrap | Out-String -Width 200)
    $failed = @($results | Where-Object Status -eq 'Fail')
    if ($failed.Count -gt 0) {
        Write-Error "$($failed.Count) of $($results.Count) local check(s) failed." -ErrorAction Continue
        exit 1
    }
    Write-Information "No check failed ($(@($results | Where-Object Status -eq 'Skip').Count) skipped)."
    exit 0
}
