# CLAUDE.md

Instructions for Claude Code in this repository. Other agents: see [AGENTS.md](AGENTS.md). Humans: see [CONTRIBUTING.md](CONTRIBUTING.md).

## What this repo is

A governed MCP server in Go. Agents call tools (`k8s_get`, `k8s_scale`, `terraform_plan`, ...); every call goes through identify, validate, policy (allow/ask/deny), approval, audit, short-lived credentials, run, redact. Read [DESIGN.md](DESIGN.md) before changing the pipeline.

| Path | What |
|---|---|
| `cmd/mcp-cloud-ops-gateway/` | CLI: serve, validate, approvals, audit verify, hash-token |
| `internal/gateway/` | the pipeline, MCP and admin HTTP handlers (security-critical) |
| `internal/policy/`, `internal/approval/` | policy evaluator and approval broker (security-critical, ask before editing) |
| `internal/tools/` | tool specs, input validation, command building |
| `internal/creds/`, `internal/runner/`, `internal/audit/`, `internal/redact/`, `internal/guard/` | credentials, exec wrapper, audit chain, output hygiene |
| `examples/` | example config and policy (the policy is code-owned) |
| `deploy/kubernetes/` | Kustomize base and overlays |
| `test/e2e/` | end-to-end test, build tag `e2e`, needs a throwaway cluster |
| `docs/` | DECISIONS, EVIDENCE, THREAT_MODEL, CONFIGURATION, INTEGRATION, EXTENDING |

## Commands

```powershell
go build ./... ; go vet ./...
go test -race ./...
pwsh ./scripts/Invoke-LocalChecks.ps1          # everything CI runs
go run ./cmd/mcp-cloud-ops-gateway validate --config examples/gateway.yaml
$env:E2E_KUBE_CONTEXT = 'kind-gw'; go test -tags e2e -v ./test/e2e/
```

## Conventions

- **One wrapper per external system.** CLIs go through `internal/runner` (argv only, no shell, minimal env). HTTP goes through `creds.HTTPDoer`. Tests use fakes; unit tests need no network or cluster.
- **Every tool argument is validated** in `Prepare` against a strict pattern before it reaches a CLI. Targets are aliases from config, never paths or IDs.
- **Mutating tools** set `Mutating: true` and embed `tools.Approval`. Destructive ones set `Destructive: true`.
- **The policy sees every argument**, defaults and zero values included (`gateway.argMap`). Do not reintroduce `omitempty`-based maps.
- **Fail closed.** No audit record, no call. Unknown config fields are errors.
- **Tests first** where practical: table-driven, `_test.go` next to the code. A security behaviour gets a test named for it.
- **Zero findings** from gofmt, go vet and golangci-lint (`.golangci.yml`).
- **Pin everything.** Actions by SHA, tools by SHA-256, images by digest, Go modules in go.sum.
- **Docs move with code.** A design choice gets a numbered row in `docs/DECISIONS.md`; a real run goes in `docs/EVIDENCE.md`; a new config field goes in `docs/CONFIGURATION.md`; a new tool goes in README, INTEGRATION and CONFIGURATION.
- Plain, short sentences in docs. Say what is verified and what is not.

## Pull requests

Branch `<type>/<short-description>`. Conventional Commit titles. The PR body uses `.github/pull_request_template.md`; `## What changed`, `## Why`, `## How it was verified`, `## Risk and rollback` and `## AI assistance` need real content (checked by `pr-policy`). A human merges, never an agent.

## Never

- Read, print or commit secrets, tokens or real token hashes from a live environment.
- Add a tool that reads Kubernetes Secrets, runs a shell, or takes a free-form path or command.
- Weaken a default (default deny, fail-closed audit, approval binding) without a DECISIONS entry and the owner's approval.
- Push to `main`, force-push, skip checks, or disable a test to get green.
- Change `.github/workflows/`, `governance/`, `.claude/`, `CODEOWNERS`, `examples/policy.yaml`, `deploy/`, `internal/policy/` or `internal/approval/` without saying why in the PR. The guard hook asks every time.

## How to work

Use the orchestrate skill ([.claude/skills/orchestrate/SKILL.md](.claude/skills/orchestrate/SKILL.md)) for non-trivial work: refine the request into a brief, explore then plan, delegate in parallel with explicit model and effort, verify the combined result yourself (`Invoke-LocalChecks.ps1` and the e2e test when a cluster is available), report what is verified and what is not.

The guard hook `.claude/hooks/Invoke-GuardHook.ps1` is copied unchanged from [governed-repo-template](https://github.com/kaushik-sai/governed-repo-template), where its Pester tests live.
