<#
.SYNOPSIS
    Checks a pull request's title and description against governance/policy.json.

.DESCRIPTION
    Checks, in order:
      Title         matches pullRequest.titlePattern (Conventional Commits), on one line
      <section>     every pullRequest.requiredSections heading is there with real content
                    (an HTML comment or blank lines do not count as content)
      AI assistance pullRequest.agentDisclosureSection is there
      Changed files more than pullRequest.maxChangedFiles is a Warn, never a Fail
    Prints one row per check: Check, Status (Pass, Fail, Warn), Detail.
    On GitHub Actions (GITHUB_STEP_SUMMARY set) it also appends a markdown table to the run summary
    and prints a ::error:: line per failure. Exits 1 on any Fail.
    Title and Body are untrusted text: they are only compared and counted, never executed
    or put into a command.

.PARAMETER Title
    The pull request title.

.PARAMETER Body
    The pull request description (markdown).

.PARAMETER ChangedFiles
    Number of changed files. Leave out to skip the file-count check.

.PARAMETER PolicyPath
    Path to the policy file. Defaults to governance/policy.json.

.PARAMETER TitleOnly
    Check only the title (and file count). For automated dependency PRs (Dependabot), whose
    body GitHub writes and cannot follow the template. The skipped body checks show as Warn.

.EXAMPLE
    pwsh ./scripts/Test-PullRequest.ps1 -Title $env:PR_TITLE -Body $env:PR_BODY -ChangedFiles 12
#>
[CmdletBinding()]
param(
    [AllowEmptyString()] [string] $Title = '',
    [AllowEmptyString()] [string] $Body = '',
    [ValidateRange(0, 100000)] [int] $ChangedFiles = -1,
    [string] $PolicyPath,
    [switch] $TitleOnly
)

Set-StrictMode -Version Latest
. (Join-Path -Path $PSScriptRoot -ChildPath 'lib' -AdditionalChildPath 'Cli.ps1')

function Get-CheckResult {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Check,
        [Parameter(Mandatory)] [ValidateSet('Pass', 'Fail', 'Warn')] [string] $Status,
        [Parameter(Mandatory)] [string] $Detail
    )
    [pscustomobject] @{ Check = $Check; Status = $Status; Detail = $Detail }
}

# The title must match the pattern (case-sensitive) and be a single line.
function Test-PullRequestTitle {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyString()] [string] $Title = '',
        [Parameter(Mandatory)] [string] $Pattern
    )
    if ($Title -match '[\r\n]') {
        return Get-CheckResult -Check 'Title' -Status Fail -Detail 'The title must be a single line.'
    }
    if ($Title -cmatch $Pattern) {
        return Get-CheckResult -Check 'Title' -Status Pass -Detail 'Matches the Conventional Commits pattern.'
    }
    Get-CheckResult -Check 'Title' -Status Fail -Detail "Does not match the Conventional Commits pattern 'type(scope): summary' (summary 1 to 99 characters, lower-case type)."
}

# Body without HTML comments, line endings normalised.
function Get-TextWithoutComment {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()] [string] $Text = '')
    ($Text -replace '(?s)<!--.*?-->', '') -replace "`r`n?", "`n"
}

# Text under a heading, up to the next "## " heading. $null when the heading is not there.
function Get-SectionContent {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()] [string] $Body = '',
        [Parameter(Mandatory)] [string] $Heading
    )
    $found = $false
    $content = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ((Get-TextWithoutComment -Text $Body) -split "`n")) {
        if ($line.StartsWith($Heading, [System.StringComparison]::OrdinalIgnoreCase)) {
            if ($found) { continue }
            $found = $true
            continue
        }
        if ($found -and $line -match '^## ') { break }
        if ($found) { $content.Add($line) }
    }
    if ($found) { $content -join "`n" }
}

function Test-PullRequestSection {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyString()] [string] $Body = '',
        [Parameter(Mandatory)] [string[]] $Heading
    )
    foreach ($h in $Heading) {
        $content = Get-SectionContent -Body $Body -Heading $h
        if ($null -eq $content) {
            Get-CheckResult -Check $h -Status Fail -Detail 'Section is missing.'
        } elseif ([string]::IsNullOrWhiteSpace($content)) {
            Get-CheckResult -Check $h -Status Fail -Detail 'Section is empty (comments and blank lines do not count).'
        } else {
            Get-CheckResult -Check $h -Status Pass -Detail 'Present with content.'
        }
    }
}

function Test-AgentDisclosure {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyString()] [string] $Body = '',
        [Parameter(Mandatory)] [string] $Heading
    )
    if ($null -eq (Get-SectionContent -Body $Body -Heading $Heading)) {
        Get-CheckResult -Check $Heading -Status Fail -Detail 'AI assistance section is missing; state what was and was not AI-assisted.'
    } else {
        Get-CheckResult -Check $Heading -Status Pass -Detail 'Present.'
    }
}

function Test-ChangedFileCount {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [int] $Count,
        [Parameter(Mandatory)] [int] $Max
    )
    if ($Count -gt $Max) {
        Get-CheckResult -Check 'Changed files' -Status Warn -Detail "$Count files changed, more than $Max. Consider splitting the pull request."
    } else {
        Get-CheckResult -Check 'Changed files' -Status Pass -Detail "$Count files changed (limit $Max)."
    }
}

# Runs every check. Returns one result per check.
function Invoke-PullRequestCheck {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyString()] [string] $Title = '',
        [AllowEmptyString()] [string] $Body = '',
        [int] $ChangedFiles = -1,
        [Parameter(Mandatory)] [pscustomobject] $Policy,
        [switch] $TitleOnly
    )
    $pr = $Policy.pullRequest
    Test-PullRequestTitle -Title $Title -Pattern $pr.titlePattern
    if ($TitleOnly) {
        Get-CheckResult -Check 'Body' -Status Warn -Detail 'Body checks skipped (-TitleOnly): automated dependency pull request.'
    } else {
        Test-PullRequestSection -Body $Body -Heading @($pr.requiredSections)
        Test-AgentDisclosure -Body $Body -Heading $pr.agentDisclosureSection
    }
    if ($ChangedFiles -ge 0) {
        Test-ChangedFileCount -Count $ChangedFiles -Max ([int] $pr.maxChangedFiles)
    }
}

# Markdown table for the Actions run summary.
function ConvertTo-SummaryMarkdown {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [object[]] $Result)
    $rows = foreach ($r in $Result) { "| $($r.Check) | $($r.Status) | $($r.Detail) |" }
    (@('### Pull request policy', '', '| Check | Status | Detail |', '|---|---|---|') + $rows) -join [Environment]::NewLine
}

# Main: only runs when the script is executed, not when tests dot-source it.
if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    $InformationPreference = 'Continue'
    try {
        $policyArguments = if ($PolicyPath) { @{ Path = $PolicyPath } } else { @{} }
        $policy = Get-GovernancePolicy @policyArguments
        $results = @(Invoke-PullRequestCheck -Title $Title -Body $Body -ChangedFiles $ChangedFiles -Policy $policy -TitleOnly:$TitleOnly)
    } catch {
        Write-Error $_.Exception.Message -ErrorAction Continue
        exit 1
    }
    Write-Information ($results | Format-Table -AutoSize -Wrap | Out-String -Width 200)
    if ($env:GITHUB_STEP_SUMMARY) {
        Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value (ConvertTo-SummaryMarkdown -Result $results)
    }
    $failed = @($results | Where-Object Status -eq 'Fail')
    if ($env:GITHUB_STEP_SUMMARY) {
        foreach ($f in $failed) {
            Write-Output "::error title=Pull request policy::$($f.Check): $($f.Detail)"
        }
    }
    if ($failed.Count -gt 0) {
        Write-Error "$($failed.Count) of $($results.Count) pull request check(s) failed." -ErrorAction Continue
        exit 1
    }
    Write-Information "All $($results.Count) pull request checks passed."
    exit 0
}
