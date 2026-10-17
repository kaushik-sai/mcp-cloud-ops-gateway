# Contributing

Humans and AI agents follow the same rules. Agents also follow [CLAUDE.md](CLAUDE.md) (Claude Code) or [AGENTS.md](AGENTS.md) (other agents).

## The flow

1. **Start from an issue.** Use the bug or feature form. Work needs testable requirements before it starts.
2. **Branch from `main`.** Name it `<type>/<short-description>`, for example `feat/gcp-group` or `fix/approval-expiry`. Nobody pushes to `main`; the ruleset blocks it.
3. **Write the test first** where it is practical. CLIs go through `internal/runner` and HTTP through `creds.HTTPDoer`, so unit tests use fakes and need no network, cluster or cloud account.
4. **Run the checks locally** before you push:

   ```powershell
   pwsh ./scripts/Invoke-LocalChecks.ps1
   ```

   This runs what CI runs: gofmt, go vet, golangci-lint, `go test -race`, govulncheck, actionlint and gitleaks. A missing tool is reported as skipped with how to install it.
5. **Run the end-to-end test** when you touch the pipeline, a Kubernetes tool or the CLI, against a throwaway cluster (kind, kwok, minikube):

   ```powershell
   $env:E2E_KUBE_CONTEXT = 'kind-gw'
   go test -tags e2e -v ./test/e2e/
   ```

   It creates and deletes the namespace `e2e-payments`. CI does not run it; paste its output into the PR.
6. **Open a PR** using the template. The title is a [Conventional Commit](https://www.conventionalcommits.org/en/v1.0.0/) (`feat:`, `fix:`, `docs:`, `ci:`, `security:` ...). Fill in every section; the `pr-policy` job checks them.
7. **Review.** One code-owner approval, conversations resolved, all required checks green, and a fresh approval after the last push. A human merges; the PR is squash-merged.

## Rules that are not negotiable

- No secrets in code, logs, issues or PRs. Test fixtures build fake credentials from parts so scanners do not flag them.
- Pin every new action to a full commit SHA, every downloaded tool to a version and its SHA-256, every image to a digest.
- Workflows get `permissions: contents: read` and add only what a job needs.
- Never skip, disable or quarantine a test to get green. Fix the cause or ask.
- Do not weaken a safe default (default deny, fail-closed audit, approval binding, no Secrets, no shell) without a DECISIONS entry and the owner's approval.
- A behaviour change updates the docs in the same PR. A decision gets a numbered row in [docs/DECISIONS.md](docs/DECISIONS.md); a new config field goes in [docs/CONFIGURATION.md](docs/CONFIGURATION.md); a real run goes in [docs/EVIDENCE.md](docs/EVIDENCE.md).
- New tools follow the checklist in [docs/EXTENDING.md](docs/EXTENDING.md#d-security-checklist-for-every-new-tool).

## Style

- `gofmt`, zero findings from go vet and golangci-lint ([.golangci.yml](.golangci.yml)).
- Table-driven tests next to the code. A security behaviour gets a test named for what it guarantees.
- Comments explain why, not what. Exported names have doc comments.
- Docs in plain, short sentences. Say what is verified and what is not.
