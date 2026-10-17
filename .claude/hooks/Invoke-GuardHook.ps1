<#
.SYNOPSIS
    Claude Code PreToolUse guard: blocks risky shell commands and secret writes, and asks a
    human before an agent changes the files that hold the rules.

.DESCRIPTION
    Claude Code runs this script before every Bash, PowerShell, Write, Edit and MultiEdit call
    (see .claude/settings.json). It reads the hook input JSON from stdin and answers with the
    documented PreToolUse output on stdout:

      {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}

    deny  the call does not run, and Claude sees the reason.
    ask   the user is asked to confirm the call.
    (no output, exit 0)  no opinion: the normal permission rules decide. The hook never answers
          "allow", so it can never approve something the settings would have asked about.

    Shell commands (Bash and PowerShell tools), deny:
      force pushes (--force, -f, +refspec), pushes to main or master, --mirror and --all;
      history rewrites (filter-branch, filter-repo, reset --hard, moving or deleting main);
      skipping git hooks (--no-verify, commit -n, core.hooksPath);
      disabling or deleting workflows and rulesets (gh workflow disable, gh api DELETE, gh api
      writes to rulesets or branch protection, rm or mv of workflow and governance files);
      reading secret files (.env, *.pem, *.key, secrets/ ...);
      pipe-to-shell installs (curl ... | sh, iwr ... | iex);
      rm -rf of / or home, gh repo delete, gh pr merge.
    Shell commands, ask: git push --force-with-lease to a feature branch; shell writes to
      protected paths; running Set-RepoGovernance.ps1 or New-GovernedRepo.ps1.

    Write and Edit, deny: content that looks like a secret (AWS key id, GitHub token, private
      key, Slack token, a long literal password). The reason names the kind, never the value.
    Write and Edit, ask: .github/workflows/, governance/, .claude/settings*.json,
      .claude/hooks/ and .github/CODEOWNERS. No exceptions: a human confirms every change to
      the rules.

    Failure mode: if the input cannot be read or checked, the script writes a note to stderr
    and exits 1. Claude Code treats exit 1 as a non-blocking error: the call goes on to the
    normal permission rules, and the user sees the note. This is fail-open on purpose. A hook
    that fails closed would stop every tool call in every session the moment it breaks (a
    missing pwsh, a JSON change in a new Claude Code release). The settings deny rules, CI, the
    ruleset and human review still apply, so a broken hook loses one layer, not all of them.
    To fail closed instead, set "onFailure": "block" on the hook in .claude/settings.json.

    This is a guard rail, not a security boundary: a command can be written in ways no text
    check can see. See docs/AGENT_WORKFLOW.md for what each layer does not catch.

.EXAMPLE
    '{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' |
        pwsh -NoProfile -File ./.claude/hooks/Invoke-GuardHook.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest

# One verdict: deny, ask or allow, with the reason Claude and the user see.
function Get-Verdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [ValidateSet('deny', 'ask', 'allow')] [string] $Decision,
        [string] $Reason = ''
    )
    [pscustomobject] @{ Decision = $Decision; Reason = $Reason }
}

# The strongest of several verdicts: deny beats ask beats allow. The first one wins a tie.
function Select-StrongestVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowEmptyCollection()] [AllowNull()] [object[]] $Verdict)
    $rank = @{ allow = 0; ask = 1; deny = 2 }
    $best = Get-Verdict -Decision 'allow'
    foreach ($v in @($Verdict | Where-Object { $_ })) {
        if ($rank[$v.Decision] -gt $rank[$best.Decision]) {
            $best = $v
        }
    }
    $best
}

# Branches that are shared, so pushing to them or rewriting them is never an agent's call.
function Get-ProtectedBranch {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    'main'
    'master'
}

# Splits a command line into simple commands at ; && || | & and newlines, and at ( ) { }
# $( <( >( and backticks, so a command inside a subshell or script block is checked on its own.
# Quotes are kept for Split-CommandToken. Not a full shell parser: it only has to find commands.
function Split-CommandSegment {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowEmptyString()] [string] $Command)
    $segments = [System.Collections.Generic.List[string]]::new()
    $current = [System.Text.StringBuilder]::new()
    $quote = [char] 0
    $flush = {
        $text = $current.ToString().Trim()
        if ($text) { $segments.Add($text) }
        [void] $current.Clear()
    }
    for ($i = 0; $i -lt $Command.Length; $i++) {
        $ch = $Command[$i]
        $next = if ($i + 1 -lt $Command.Length) { $Command[$i + 1] } else { [char] 0 }
        $prev = if ($i -gt 0) { $Command[$i - 1] } else { [char] 0 }
        if ($quote -eq [char] "'") {
            [void] $current.Append($ch)
            if ($ch -eq [char] "'") { $quote = [char] 0 }
            continue
        }
        # Command substitution runs even inside double quotes.
        if (($ch -eq [char] '$' -and $next -eq [char] '(') -or $ch -eq [char] '`') {
            & $flush
            if ($ch -eq [char] '$') { $i++ }
            continue
        }
        if ($quote -eq [char] '"') {
            [void] $current.Append($ch)
            if ($ch -eq [char] '"') { $quote = [char] 0 }
            continue
        }
        if ($ch -eq [char] "'" -or $ch -eq [char] '"') {
            $quote = $ch
            [void] $current.Append($ch)
            continue
        }
        # & is a separator, except in redirects such as 2>&1 and &>.
        $isAmp = $ch -eq [char] '&' -and $prev -ne [char] '>' -and $prev -ne [char] '<' -and $next -ne [char] '>'
        if ($ch -in [char] ';', [char] '|', [char] "`n", [char] "`r", [char] '(', [char] ')', [char] '{', [char] '}' -or $isAmp) {
            & $flush
            continue
        }
        [void] $current.Append($ch)
    }
    & $flush
    $segments.ToArray()
}

# Splits one simple command into words, removing quotes. Redirect targets (> file, >> file,
# 2>file) are listed separately in Redirects and also kept in Words.
function Split-CommandToken {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowEmptyString()] [string] $Segment)
    $raw = [System.Collections.Generic.List[string]]::new()
    $word = [System.Text.StringBuilder]::new()
    $quote = [char] 0
    $started = $false
    foreach ($ch in $Segment.ToCharArray()) {
        if ($quote -ne [char] 0) {
            if ($ch -eq $quote) { $quote = [char] 0 } else { [void] $word.Append($ch) }
            continue
        }
        if ($ch -eq [char] "'" -or $ch -eq [char] '"') {
            $quote = $ch
            $started = $true
            continue
        }
        if ([char]::IsWhiteSpace($ch)) {
            if ($started -or $word.Length -gt 0) { $raw.Add($word.ToString()) }
            [void] $word.Clear()
            $started = $false
            continue
        }
        [void] $word.Append($ch)
    }
    if ($started -or $word.Length -gt 0) { $raw.Add($word.ToString()) }

    # Brackets left over from a subshell or $( ) split, and empty words, are dropped.
    $raw = @($raw | ForEach-Object { $_.Trim('(', ')') } | Where-Object { $_ })
    $words = [System.Collections.Generic.List[string]]::new()
    $redirects = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $raw.Count; $i++) {
        $w = $raw[$i]
        if ($w -match '^(?:\d|\*|&)?>>?\|?$') {
            if ($i + 1 -lt $raw.Count) {
                $redirects.Add($raw[$i + 1])
                $words.Add($raw[$i + 1])
                $i++
            }
            continue
        }
        if ($w -match '^(?:\d|\*|&)?>>?([^&].*)$') {
            $redirects.Add($Matches[1])
            $words.Add($Matches[1])
            continue
        }
        if ($w -match '^<+(.+)$') {
            $words.Add($Matches[1])
            continue
        }
        if ($w -eq '<') { continue }
        $words.Add($w)
    }
    [pscustomobject] @{ Words = $words.ToArray(); Redirects = $redirects.ToArray() }
}

# Index of the program word, after leading VAR=value assignments and wrappers such as sudo,
# env, timeout and nohup. Returns -1 when the command has no program.
function Get-ProgramIndex {
    [CmdletBinding()]
    [OutputType([int])]
    param([AllowEmptyCollection()] [string[]] $Words)
    $wrappers = @('sudo', 'env', 'command', 'builtin', 'nohup', 'time', 'nice', 'exec', 'xargs', 'stdbuf', 'doas')
    $i = 0
    while ($i -lt $Words.Count) {
        $name = Get-ProgramName -Word $Words[$i]
        if ($Words[$i] -match '^[A-Za-z_][A-Za-z0-9_]*=') {
            $i++
        } elseif ($name -eq 'timeout') {
            $i += 2
        } elseif ($name -in $wrappers) {
            $i++
            while ($i -lt $Words.Count -and $Words[$i].StartsWith('-')) { $i++ }
        } else {
            return $i
        }
    }
    -1
}

# A program word as a plain lower-case name: /usr/bin/git, git.exe and GIT all become git.
function Get-ProgramName {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()] [string] $Word)
    $leaf = ($Word -split '[\\/]')[-1].ToLowerInvariant()
    $leaf -replace '\.exe$', ''
}

# A path with forward slashes and no leading ./, relative to the project when it is inside it.
function Get-RepoRelativePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()] [string] $Path,
        [AllowEmptyString()] [string] $ProjectDir
    )
    $p = $Path -replace '\\', '/'
    if ($ProjectDir) {
        $root = ($ProjectDir -replace '\\', '/').TrimEnd('/')
        if ($root -and $p.StartsWith("$root/", [System.StringComparison]::OrdinalIgnoreCase)) {
            $p = $p.Substring($root.Length + 1)
        }
    }
    while ($p.StartsWith('./')) { $p = $p.Substring(2) }
    $p
}

# What a path protects, or $null. Matched at any depth and case-insensitively (Windows).
function Get-ProtectedPathKind {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()] [string] $Path)
    $p = $Path -replace '\\', '/'
    if ($p -match '(?i)(^|/)\.github/workflows(/|$)') { return 'a GitHub Actions workflow' }
    if ($p -match '(?i)(^|/)governance(/|$)') { return 'the governance policy or ruleset' }
    if ($p -match '(?i)(^|/)\.claude/settings(\.local)?\.json$') { return 'the Claude Code settings' }
    if ($p -match '(?i)(^|/)\.claude/hooks(/|$)') { return 'the agent guard hook' }
    if ($p -match '(?i)(^|/)\.github/CODEOWNERS$') { return 'CODEOWNERS' }
    $null
}

# True for files that hold secrets: .env and .env.* (not .env.example/.sample/.template),
# *.pem, *.key, *.pfx, *.p12, SSH private keys, and anything under secrets/ or .secrets/.
function Test-SecretPath {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()] [string] $Path)
    if (-not $Path -or $Path.StartsWith('-') -or $Path -match '://') { return $false }
    $p = $Path -replace '\\', '/'
    $leaf = ($p -split '/')[-1]
    if ($leaf -match '(?i)^\.env(\..+)?$' -and $leaf -notmatch '(?i)^\.env\.(example|sample|template)$') { return $true }
    if ($leaf -match '(?i)\.(pem|key|pfx|p12)$') { return $true }
    if ($leaf -match '^id_(rsa|dsa|ecdsa|ed25519)$') { return $true }
    $p -match '(?i)(^|/)\.?secrets(/|$)'
}

# The parts of a git command: the subcommand, its arguments and any -c key=value settings.
function Get-GitArgument {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowEmptyCollection()] [string[]] $Words)
    $configs = [System.Collections.Generic.List[string]]::new()
    $i = 0
    while ($i -lt $Words.Count) {
        $w = $Words[$i]
        if ($w -in '-C', '-c', '--git-dir', '--work-tree', '--namespace') {
            if ($w -eq '-c' -and $i + 1 -lt $Words.Count) { $configs.Add($Words[$i + 1]) }
            $i += 2
        } elseif ($w.StartsWith('-')) {
            $i++
        } else {
            break
        }
    }
    $sub = if ($i -lt $Words.Count) { $Words[$i].ToLowerInvariant() } else { '' }
    $rest = @(if ($i + 1 -lt $Words.Count) { $Words[($i + 1)..($Words.Count - 1)] })
    [pscustomobject] @{ Subcommand = $sub; Arguments = [string[]] $rest; Configs = [string[]] $configs.ToArray() }
}

# A branch name from a refspec side: refs/heads/main and main are both main.
function Get-BranchName {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()] [string] $Ref)
    $Ref -replace '^refs/heads/', ''
}

# Checks git push: force, pushes to protected branches, --mirror and --all.
function Get-GitPushVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowEmptyCollection()] [string[]] $Arguments)
    $protected = @(Get-ProtectedBranch)
    $valueOptions = @('-o', '--push-option', '--repo', '--receive-pack', '--exec')
    $force = $false
    $lease = $false
    $positional = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        $a = $Arguments[$i]
        if ($a -in $valueOptions) { $i++; continue }
        if ($a -eq '--mirror') { return Get-Verdict -Decision 'deny' -Reason 'git push --mirror overwrites and deletes remote branches. Push one feature branch and open a PR.' }
        if ($a -in '--all', '--branches') { return Get-Verdict -Decision 'deny' -Reason 'git push --all also pushes main. Push one feature branch and open a PR.' }
        if ($a -eq '--force') { $force = $true; continue }
        if ($a -like '--force-with-lease*') { $lease = $true; continue }
        if ($a -cmatch '^-[A-Za-z]+$') {
            if ($a.Contains('f')) { $force = $true }
            continue
        }
        if ($a.StartsWith('-')) { continue }
        $positional.Add($a)
    }
    # The first positional word is the remote; the rest are refspecs.
    for ($r = 1; $r -lt $positional.Count; $r++) {
        $refspec = $positional[$r]
        if ($refspec.StartsWith('+')) {
            $force = $true
            $refspec = $refspec.Substring(1)
        }
        $destination = Get-BranchName -Ref (($refspec -split ':')[-1])
        if ($destination -in $protected) {
            return Get-Verdict -Decision 'deny' -Reason "Pushing to $destination directly is not allowed. Push a feature branch and open a PR; the ruleset requires review and green checks."
        }
    }
    if ($force) {
        return Get-Verdict -Decision 'deny' -Reason 'Force push is not allowed: it rewrites history others may have pulled. Push new commits instead, or ask a human.'
    }
    if ($lease) {
        return Get-Verdict -Decision 'ask' -Reason 'git push --force-with-lease rewrites the remote feature branch. A human must confirm.'
    }
    Get-Verdict -Decision 'allow'
}

# Checks one git command: push, hook bypass and history rewrites.
function Get-GitVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowEmptyCollection()] [string[]] $Words)
    $git = Get-GitArgument -Words $Words
    $protected = @(Get-ProtectedBranch)
    $arguments = @($git.Arguments)

    foreach ($config in $git.Configs) {
        if ($config -match '(?i)^core\.hookspath=') {
            return Get-Verdict -Decision 'deny' -Reason 'Overriding core.hooksPath skips the git hooks. Run the hooks; fix what they report.'
        }
    }
    if ($arguments -contains '--no-verify') {
        return Get-Verdict -Decision 'deny' -Reason '--no-verify skips the git hooks. Run the hooks; fix what they report.'
    }
    switch ($git.Subcommand) {
        'push' { return Get-GitPushVerdict -Arguments $arguments }
        'commit' {
            if (@($arguments | Where-Object { $_ -cmatch '^-[A-Za-z]+$' -and $_.Contains('n') }).Count -gt 0) {
                return Get-Verdict -Decision 'deny' -Reason 'git commit -n skips the git hooks. Run the hooks; fix what they report.'
            }
        }
        { $_ -in 'filter-branch', 'filter-repo' } {
            return Get-Verdict -Decision 'deny' -Reason "git $($git.Subcommand) rewrites the whole history. That is a human decision."
        }
        'reset' {
            if ($arguments -contains '--hard') {
                return Get-Verdict -Decision 'deny' -Reason 'git reset --hard throws away work and can rewrite history. Use git stash or a new commit, or ask a human.'
            }
        }
        'branch' {
            $changes = @($arguments | Where-Object { $_ -in '-d', '-D', '--delete', '-f', '--force', '-m', '-M', '--move' })
            $names = @($arguments | Where-Object { -not $_.StartsWith('-') } | ForEach-Object { Get-BranchName -Ref $_ })
            if ($changes.Count -gt 0 -and @($names | Where-Object { $_ -in $protected }).Count -gt 0) {
                return Get-Verdict -Decision 'deny' -Reason 'Deleting, moving or resetting main or master is not allowed.'
            }
        }
        'update-ref' {
            if (@($arguments | Where-Object { (Get-BranchName -Ref $_) -in $protected -and $_ -like 'refs/heads/*' }).Count -gt 0) {
                return Get-Verdict -Decision 'deny' -Reason 'Rewriting the main or master ref directly is not allowed.'
            }
        }
        'rebase' {
            # git rebase <upstream> <branch> checks out <branch> first, so the last word is rewritten.
            $positional = [System.Collections.Generic.List[string]]::new()
            for ($i = 0; $i -lt $arguments.Count; $i++) {
                if ($arguments[$i] -in '--onto', '-s', '--strategy', '-X', '--strategy-option', '-x', '--exec') { $i++; continue }
                if (-not $arguments[$i].StartsWith('-')) { $positional.Add($arguments[$i]) }
            }
            if ($positional.Count -ge 2 -and (Get-BranchName -Ref $positional[-1]) -in $protected) {
                return Get-Verdict -Decision 'deny' -Reason 'Rebasing main or master rewrites a shared branch. Rebase your feature branch instead.'
            }
        }
        'config' {
            $reads = @($arguments | Where-Object { $_ -in '--get', '--get-all', '--list', '-l', '--get-regexp' })
            if ($reads.Count -eq 0 -and @($arguments | Where-Object { $_ -match '(?i)^core\.hookspath$' }).Count -gt 0) {
                return Get-Verdict -Decision 'deny' -Reason 'Changing core.hooksPath skips the git hooks. Ask a human.'
            }
        }
    }
    Get-Verdict -Decision 'allow'
}

# Checks one gh command: deletes, merges, and changes to workflows and rulesets.
function Get-GhVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowEmptyCollection()] [string[]] $Words)
    $positional = @($Words | Where-Object { -not $_.StartsWith('-') })
    $group = if ($positional.Count -gt 0) { $positional[0].ToLowerInvariant() } else { '' }
    $action = if ($positional.Count -gt 1) { $positional[1].ToLowerInvariant() } else { '' }
    if ($group -eq 'repo' -and $action -eq 'delete') {
        return Get-Verdict -Decision 'deny' -Reason 'gh repo delete is irreversible. Only a human deletes repositories.'
    }
    if ($group -eq 'pr' -and $action -eq 'merge') {
        return Get-Verdict -Decision 'deny' -Reason 'Merging is a human step after review. Leave the PR for the reviewer.'
    }
    if ($group -eq 'workflow' -and $action -eq 'disable') {
        return Get-Verdict -Decision 'deny' -Reason 'Disabling a workflow removes a required check. Ask a human.'
    }
    if ($group -ne 'api') {
        return Get-Verdict -Decision 'allow'
    }
    $valueOptions = @('-H', '--header', '-q', '--jq', '-t', '--template', '--hostname', '--cache', '-p', '--preview')
    $fieldOptions = @('-f', '-F', '--field', '--raw-field', '--input')
    $method = ''
    $hasFields = $false
    $apiPath = ''
    $start = [array]::IndexOf($Words, 'api') + 1
    for ($i = $start; $i -lt $Words.Count; $i++) {
        $w = $Words[$i]
        if ($w -in '-X', '--method') {
            if ($i + 1 -lt $Words.Count) { $method = $Words[$i + 1] }
            $i++
        } elseif ($w -match '^(?:-X|--method=)(.+)$') {
            $method = $Matches[1]
        } elseif ($w -in $fieldOptions) {
            $hasFields = $true
            $i++
        } elseif ($w -match '^(?:--field|--raw-field|--input)=') {
            $hasFields = $true
        } elseif ($w -in $valueOptions) {
            $i++
        } elseif (-not $w.StartsWith('-') -and -not $apiPath) {
            $apiPath = $w
        }
    }
    $method = $method.ToUpperInvariant()
    if (-not $method) { $method = if ($hasFields) { 'POST' } else { 'GET' } }
    if ($method -eq 'DELETE') {
        return Get-Verdict -Decision 'deny' -Reason 'gh api DELETE removes something on GitHub. Only a human runs deletes.'
    }
    if ($method -ne 'GET' -and $apiPath -match '(?i)(rulesets|/protection|actions/workflows/[^/]+/disable)') {
        return Get-Verdict -Decision 'deny' -Reason 'Changing rulesets, branch protection or workflows through the API is a human step. Change governance/ in a PR instead.'
    }
    Get-Verdict -Decision 'allow'
}

# Checks the whole command line for download-and-run: curl ... | sh, bash <(curl ...), iwr ... | iex.
function Get-PipeToShellVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowEmptyString()] [string] $Command)
    $download = '(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)'
    $shell = '(?:sh|bash|zsh|dash|ksh|fish|pwsh|powershell|iex|invoke-expression|python[0-9.]*|node|perl|ruby)'
    $patterns = @(
        "(?is)\b$download\b.*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+)?$shell(?![\w.-])"
        "(?is)\b(?:sh|bash|zsh|dash|ksh)\s+(?:-\S+\s+)*<\(\s*$download\b"
        "(?is)\b(?:sh|bash|zsh|dash|ksh)\s+-c\s+[`"']?\$\(\s*$download\b"
        "(?is)\b(?:iex|invoke-expression)\b.*(?:\b$download\b|downloadstring)"
    )
    foreach ($pattern in $patterns) {
        if ($Command -match $pattern) {
            return Get-Verdict -Decision 'deny' -Reason 'Piping a download into a shell runs unreviewed code. Download the file, check its SHA-256, read it, then run it.'
        }
    }
    Get-Verdict -Decision 'allow'
}

# Checks a Bash or PowerShell command line. Every simple command in it is checked; the
# strongest verdict wins. bash -c, sh -c and pwsh -Command strings are checked too.
function Get-ShellVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyString()] [string] $Command,
        [AllowEmptyString()] [string] $ProjectDir = '',
        [ValidateRange(0, 5)] [int] $Depth = 0
    )
    $verdicts = [System.Collections.Generic.List[object]]::new()
    $verdicts.Add((Get-PipeToShellVerdict -Command $Command))
    # Inside a substitution, a "harmless" program could be fed a secret, so no exemptions then.
    $hasSubstitution = $Command -match '\$\(|`|<\('
    $shells = @('bash', 'sh', 'zsh', 'dash', 'ksh', 'pwsh', 'powershell', 'cmd')
    $deleters = @('rm', 'rmdir', 'unlink', 'remove-item', 'ri', 'del', 'erase', 'rd', 'mv', 'move-item', 'mi', 'move', 'rename-item', 'ren')
    $writers = @('tee', 'set-content', 'sc', 'add-content', 'ac', 'out-file', 'new-item', 'ni', 'cp', 'copy-item', 'copy', 'cpi', 'touch', 'install', 'truncate', 'dd')
    $secretSafe = @('ls', 'dir', 'gci', 'get-childitem', 'test', '[', 'test-path', 'echo', 'write-output', 'printf', 'rm', 'remove-item', 'del')

    foreach ($segment in @(Split-CommandSegment -Command $Command)) {
        $tokens = Split-CommandToken -Segment $segment
        $words = @($tokens.Words)
        $index = Get-ProgramIndex -Words $words
        if ($index -lt 0) { continue }
        $program = Get-ProgramName -Word $words[$index]
        $rest = @(if ($index + 1 -lt $words.Count) { $words[($index + 1)..($words.Count - 1)] })
        $paths = @($rest | ForEach-Object { $_; if ($_ -match '=(.+)$') { $Matches[1] } } | ForEach-Object { Get-RepoRelativePath -Path $_ -ProjectDir $ProjectDir })

        # A command string handed to another shell: check what it runs.
        if ($program -in $shells -and $Depth -lt 3) {
            for ($i = 0; $i -lt $rest.Count; $i++) {
                if ($rest[$i] -in '-c', '-Command', '/c' -and $i + 1 -lt $rest.Count) {
                    $inner = ($rest[($i + 1)..($rest.Count - 1)] -join ' ')
                    $verdicts.Add((Get-ShellVerdict -Command $inner -ProjectDir $ProjectDir -Depth ($Depth + 1)))
                    break
                }
            }
        }

        $git = $null
        if ($program -eq 'git') {
            $git = Get-GitArgument -Words $rest
            $verdicts.Add((Get-GitVerdict -Words $rest))
        }
        if ($program -eq 'gh') {
            $verdicts.Add((Get-GhVerdict -Words $rest))
        }

        # rm -rf / or home.
        $flags = ($rest | Where-Object { $_ -cmatch '^-[A-Za-z]+$' }) -join ''
        $recursive = ($program -eq 'rm' -and ($flags -cmatch '[rR]' -or $rest -contains '--recursive')) -or
        ($program -in 'remove-item', 'ri', 'del', 'rd', 'rmdir' -and @($rest | Where-Object { $_ -match '(?i)^-r(ecurse)?$' }).Count -gt 0)
        if ($recursive) {
            $roots = @('', '~', '$home', '${home}', '$env:home', '$env:userprofile', 'c:', '/home', '/root', '/users')
            foreach ($target in @($rest | Where-Object { -not $_.StartsWith('-') })) {
                if ((($target.ToLowerInvariant() -replace '\\', '/') -replace '/+\*?$', '') -in $roots) {
                    $verdicts.Add((Get-Verdict -Decision 'deny' -Reason 'Recursive delete of the filesystem root or a home directory is never allowed.'))
                }
            }
        }

        # Deleting or moving workflows and governance files disables the checks.
        $isDeleter = $program -in $deleters -or ($git -and $git.Subcommand -in 'rm', 'mv')
        foreach ($path in $paths) {
            $kind = Get-ProtectedPathKind -Path $path
            if ($isDeleter -and $kind -in 'a GitHub Actions workflow', 'the governance policy or ruleset') {
                $verdicts.Add((Get-Verdict -Decision 'deny' -Reason "Deleting or moving $kind ($path) disables a check. Change it in a PR a human reviews."))
            } elseif ($kind -and ($program -in $writers -or ($program -in 'sed', 'perl' -and @($rest | Where-Object { $_ -like '-i*' -or $_ -eq '--in-place' }).Count -gt 0))) {
                $verdicts.Add((Get-Verdict -Decision 'ask' -Reason "This command changes $kind ($path). A human must confirm changes to the rules."))
            } elseif ($kind -and $isDeleter) {
                $verdicts.Add((Get-Verdict -Decision 'ask' -Reason "This command deletes or moves $kind ($path). A human must confirm changes to the rules."))
            }
        }
        foreach ($target in @($tokens.Redirects)) {
            $kind = Get-ProtectedPathKind -Path (Get-RepoRelativePath -Path $target -ProjectDir $ProjectDir)
            if ($kind) {
                $verdicts.Add((Get-Verdict -Decision 'ask' -Reason "This command writes to $kind ($target). A human must confirm changes to the rules."))
            }
        }

        # Reading secret files. Listing, testing or deleting one is fine.
        $secretPaths = @($paths | Where-Object { Test-SecretPath -Path $_ })
        if ($secretPaths.Count -gt 0) {
            $safe = -not $hasSubstitution -and (
                $program -in $secretSafe -or
                ($git -and ($git.Subcommand -in 'check-ignore', 'status', 'ls-files' -or ($git.Subcommand -eq 'rm' -and $git.Arguments -contains '--cached'))))
            if (-not $safe) {
                $verdicts.Add((Get-Verdict -Decision 'deny' -Reason "This command reads a secret file ($($secretPaths[0])). Agents never read secrets; ask the user to provide what is needed."))
            }
        }

        # Scripts that change GitHub-side settings.
        if (@($words | Where-Object { $_ -match '(?i)(^|[\\/])(Set-RepoGovernance|New-GovernedRepo)\.ps1$' }).Count -gt 0) {
            $verdicts.Add((Get-Verdict -Decision 'ask' -Reason 'This script changes settings on GitHub. A human must confirm.'))
        }
    }
    Select-StrongestVerdict -Verdict $verdicts.ToArray()
}

# The kind of secret the text seems to hold, or $null. Never returns the secret itself.
function Find-SecretKind {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()] [AllowNull()] [string] $Text)
    if (-not $Text) { return $null }
    if ($Text -cmatch '-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----') { return 'a private key' }
    if ($Text -cmatch '(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])') { return 'an AWS access key id' }
    if ($Text -cmatch '(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,}') { return 'a GitHub token' }
    if ($Text -cmatch '(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{22,}') { return 'a GitHub token' }
    if ($Text -cmatch '(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,}') { return 'a Slack token' }
    # password = "literal", at least 12 characters, not a ${{ }}, $VAR, <placeholder> or {{ }}.
    $generic = '(?i)\b(?:password|passwd|pwd|secret|client_secret|api_?key|access_?token|auth_?token)\b["'']?\s*[:=]\s*["''](?![$<{%])[^"''\s]{12,}["'']'
    if ($Text -match $generic) { return 'a hard-coded password or secret' }
    $null
}

# Checks a Write or Edit: secrets in the new content, then protected paths.
function Get-FileVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyString()] [string] $FilePath,
        [AllowEmptyString()] [AllowNull()] [string] $Content,
        [AllowEmptyString()] [string] $ProjectDir = ''
    )
    $relative = Get-RepoRelativePath -Path $FilePath -ProjectDir $ProjectDir
    $secret = Find-SecretKind -Text $Content
    if ($secret) {
        return Get-Verdict -Decision 'deny' -Reason "The new content for $relative looks like $secret. Never write secrets to files: read them from an environment variable or the CI secret store. If it is a fake value for a test, build it at runtime or put it under tests/fixtures/."
    }
    $kind = Get-ProtectedPathKind -Path $relative
    if ($kind) {
        return Get-Verdict -Decision 'ask' -Reason "$relative is $kind. Changes to the rules need a human to confirm, every time."
    }
    Get-Verdict -Decision 'allow'
}

# A field of a JSON object, or $null when it is missing (StrictMode-safe).
function Get-JsonField {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Object,
        [Parameter(Mandatory)] [string] $Name
    )
    if ($null -eq $Object -or $Object -isnot [pscustomobject]) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { $property.Value } else { $null }
}

# Parses the hook input. Throws when it is empty, not JSON or has no tool_name.
function ConvertFrom-HookInput {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowEmptyString()] [AllowNull()] [string] $Json)
    if ([string]::IsNullOrWhiteSpace($Json)) { throw 'The hook input on stdin was empty.' }
    try {
        $parsed = $Json | ConvertFrom-Json -ErrorAction Stop
    } catch {
        # Do not echo the parser message: it can quote the input, and the input can hold a secret.
        throw 'The hook input on stdin is not valid JSON.'
    }
    if (-not (Get-JsonField -Object $parsed -Name 'tool_name')) { throw 'The hook input has no tool_name.' }
    $parsed
}

# The project root: CLAUDE_PROJECT_DIR when Claude Code set it, else the cwd from the input.
function Resolve-ProjectDirectory {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()] [AllowNull()] [string] $EnvironmentValue,
        [AllowNull()] [object] $HookInput
    )
    if ($EnvironmentValue) { return $EnvironmentValue }
    $cwd = Get-JsonField -Object $HookInput -Name 'cwd'
    if ($cwd) { return [string] $cwd }
    ''
}

# The verdict for one hook input.
function Get-GuardDecision {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [object] $HookInput,
        [AllowEmptyString()] [string] $ProjectDir = ''
    )
    $tool = [string] (Get-JsonField -Object $HookInput -Name 'tool_name')
    $toolInput = Get-JsonField -Object $HookInput -Name 'tool_input'
    switch ($tool) {
        { $_ -in 'Bash', 'PowerShell' } {
            return Get-ShellVerdict -Command ([string] (Get-JsonField -Object $toolInput -Name 'command')) -ProjectDir $ProjectDir
        }
        'Write' {
            return Get-FileVerdict -FilePath ([string] (Get-JsonField -Object $toolInput -Name 'file_path')) `
                -Content ([string] (Get-JsonField -Object $toolInput -Name 'content')) -ProjectDir $ProjectDir
        }
        'Edit' {
            return Get-FileVerdict -FilePath ([string] (Get-JsonField -Object $toolInput -Name 'file_path')) `
                -Content ([string] (Get-JsonField -Object $toolInput -Name 'new_string')) -ProjectDir $ProjectDir
        }
        'MultiEdit' {
            $edits = @(Get-JsonField -Object $toolInput -Name 'edits')
            $content = ($edits | ForEach-Object { [string] (Get-JsonField -Object $_ -Name 'new_string') }) -join "`n"
            return Get-FileVerdict -FilePath ([string] (Get-JsonField -Object $toolInput -Name 'file_path')) -Content $content -ProjectDir $ProjectDir
        }
    }
    Get-Verdict -Decision 'allow'
}

# The documented PreToolUse JSON for deny and ask, or $null for allow (no output means
# "no opinion": the permission rules decide).
function ConvertTo-HookOutput {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [pscustomobject] $Verdict)
    if ($Verdict.Decision -eq 'allow') { return $null }
    @{
        hookSpecificOutput = [ordered] @{
            hookEventName            = 'PreToolUse'
            permissionDecision       = $Verdict.Decision
            permissionDecisionReason = "Guard hook: $($Verdict.Reason)"
        }
    } | ConvertTo-Json -Compress -Depth 4
}

# Main: only runs when the script is executed, not when tests dot-source it.
if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    try {
        $hookInput = ConvertFrom-HookInput -Json ([Console]::In.ReadToEnd())
        $projectDir = Resolve-ProjectDirectory -EnvironmentValue $env:CLAUDE_PROJECT_DIR -HookInput $hookInput
        $verdict = Get-GuardDecision -HookInput $hookInput -ProjectDir $projectDir
        $output = ConvertTo-HookOutput -Verdict $verdict
    } catch {
        # Fail open (see .DESCRIPTION): exit 1 is a non-blocking error, so the call goes on to
        # the normal permission rules and the user sees this line.
        [Console]::Error.WriteLine("Guard hook could not check this call, so it did not block it: $($_.Exception.Message)")
        exit 1
    }
    if ($output) { [Console]::Out.WriteLine($output) }
    exit 0
}
