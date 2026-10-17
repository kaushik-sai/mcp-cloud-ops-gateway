<!--
PR title: Conventional Commits, for example "feat(policy): add namespace allowlist" or "fix: handle empty approval reason".
Every section below is checked by the pr-policy job. HTML comments do not count as content.
-->

## What changed

<!-- The visible change, in plain words. -->

## Why

<!-- The problem or the ticket. Link it. -->

## How it was verified

<!-- Commands run and their results, with numbers (for example "go test -race ./...: 212 passed, 0 failed"). Say what is not verified. -->

## Risk and rollback

<!-- What could break, who is affected, and how to undo it (revert this PR, roll back the deployment, and so on). Say if the change widens what an agent can do or weakens policy, approval or audit. -->

## AI assistance

<!-- Which parts an AI agent wrote or changed, and what a human checked. "None" is a valid answer. -->

## Checklist

- [ ] `pwsh ./scripts/Invoke-LocalChecks.ps1` passes
- [ ] Docs and example policy updated where behaviour changed
- [ ] No secrets, tokens, kubeconfigs or internal hostnames in code, logs, fixtures or this description
