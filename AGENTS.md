# AGENTS.md

Rules for any coding agent in this repository. Claude Code reads [CLAUDE.md](CLAUDE.md), which says the same in more detail.

- Build and test: `go build ./...`, `go vet ./...`, `go test -race ./...`. All CI checks: `pwsh ./scripts/Invoke-LocalChecks.ps1`.
- Security-critical code: `internal/gateway`, `internal/policy`, `internal/approval`, `internal/runner`. Change it only with a test that shows the new behaviour, and say why in the PR.
- New tools validate every argument with a strict pattern, run through `internal/runner` (no shell), take aliases instead of paths, and set `Mutating`/`Destructive` correctly. No tool may read Kubernetes Secrets.
- Keep defaults safe: default deny, fail-closed audit, approvals bound to the exact call.
- Docs move with code: `docs/DECISIONS.md` for choices, `docs/EVIDENCE.md` for real runs, `docs/CONFIGURATION.md` for config fields.
- No secrets anywhere. Branch from `main`, Conventional Commit titles, fill every PR template section. Never push to `main`, force-push or merge.
